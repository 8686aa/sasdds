import Foundation

/**
 新赛季 UDP 接管（与安卓 `SeasonProtocol` / pytho/gui/seasonbridge.py 对齐）。

 服务端只为「握手时提交的公钥」派生下行 key，所以代理必须插到手机与服务器中间，
 用自己的 control7 再换一次 key，才能解开服务器下行、再用手机的 mobile_key
 （128 字节 bank 的前 16 字节）重新加密回手机。
 */
public enum SeasonProtocol {

    public static let INITIAL_LEN = 33

    /// 首包判定：33B / [8]==1 / [^1]==8 / 9~31 全 0（与采集器 UdpDecoder.IsInitial 一致）。
    public static func isInitial(_ payload: [UInt8]) -> Bool {
        if payload.count != INITIAL_LEN {
            return false
        }
        if Int(payload[8]) != 1 || Int(payload[INITIAL_LEN - 1]) != 8 {
            return false
        }
        if payload[9..<32].contains(where: { $0 != 0 }) {
            return false
        }
        return true
    }

    /// Castagnoli CRC32C，用于 UDP 私有头 check 字段的增量修正。
    public static func crc32c(_ data: [UInt8]) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for value in data {
            crc ^= UInt32(value)
            for _ in 0..<8 {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 2_197_175_160 : crc >> 1
            }
        }
        return crc ^ 0xFFFF_FFFF
    }

    /// 把 8 字节 UDP 传输头里的 seq 加 delta，并增量修正 check。
    public static func shiftHeader(_ header: [UInt8], _ delta: Int = 1) throws -> [UInt8] {
        guard header.count == 8 else { throw SeasonFailure.illegal("UDP 传输头必须为 8 字节") }
        let check = SeasonCrypto.readU32(header, 0)
        let seq = SeasonCrypto.readU32(header, 4)
        let changed = UInt32(truncatingIfNeeded: Int64(seq) + Int64(delta))
        var value = [UInt8](repeating: 0, count: 4)
        SeasonCrypto.writeU32(&value, 0, changed)
        let newCheck = check ^ crc32c(Array(header[4..<8])) ^ crc32c(value)
        var out = [UInt8](repeating: 0, count: 8)
        SeasonCrypto.writeU32(&out, 0, newCheck)
        SeasonCrypto.writeU32(&out, 4, changed)
        return out
    }

    /// 25 字节下行控制包前 5 字节里塞着一个 float（服务端握手状态）。
    public static func floatFromLead(_ payload: [UInt8]) -> Float {
        guard payload.count >= 5 else { return 0 }
        var value: UInt64 = 0
        for index in stride(from: 4, through: 0, by: -1) {
            value = (value << 8) | UInt64(payload[index])
        }
        return Float(bitPattern: UInt32(truncatingIfNeeded: value >> 3))
    }
}

/// 单个 UDP 流的 type-7 握手状态机。
public final class SeasonSession {

    public static let TIMEOUT = 5.0
    public static let RETRY_INTERVAL = 1.0
    public static let MAX_RETRIES = 3
    public static let COOKIE_RETRY_INTERVAL = 0.25
    public static let HANDSHAKE_TIMEOUT = 5.0

    private let mobileKey: [UInt8]
    private let log: (String) -> Void

    private let privateKey: [UInt8]
    public let clientPublic: [UInt8]
    private let shared: [UInt8]
    private let clientWire: [UInt8]
    private let client: SeasonCrypto.Control7

    /// 会话下行 key；bypass 后置空。
    public var key: [UInt8]?

    public private(set) var state = "hello"

    private let created: Double
    private var mobileFinal: [UInt8]?
    private var request: [UInt8]?
    private var replyHeader: [UInt8]?
    private var serverFinal: [UInt8]?
    private var cookieReply: [UInt8]?
    private var cookieRecoveryPending = false
    private var cookieRetries = 0
    private var lastCookieRetry = -Double.infinity
    private var offerStarted: Double?
    public var initialHeader: [UInt8]?
    private var lastOffer = 0.0
    private var retries = 0
    public var translated = 0

    public init(mobileKey: [UInt8], log: @escaping (String) -> Void = { _ in }) throws {
        guard mobileKey.count == 16 else {
            throw SeasonFailure.illegal("mobile_key 必须为 16 字节")
        }
        let privateBytes = CryptoUtil.randomBytes(32)
        let clientPublicValue = try CryptoUtil.x25519Public(privateKey: privateBytes)
        let sharedValue = try CryptoUtil.x25519(privateKey: privateBytes,
                                                peerPublic: SeasonCrypto.exchangePublic)
        let first = CryptoUtil.md5(clientPublicValue + sharedValue)
        let wire = try SeasonCrypto.control7(
            SeasonCrypto.identifier,
            clientPublicValue + first + CryptoUtil.md5(clientPublicValue + first)
        )
        let parsed = try SeasonCrypto.parseControl7(wire)
        let sessionKeyValue = try SeasonCrypto.sessionKey(sharedValue,
                                                          clientPublicValue,
                                                          SeasonCrypto.exchangePublic)

        self.mobileKey = mobileKey
        self.log = log
        privateKey = privateBytes
        clientPublic = clientPublicValue
        shared = sharedValue
        clientWire = wire
        client = parsed
        key = sessionKeyValue
        created = SeasonSession.now()
    }

    private static func now() -> Double {
        ProcessInfo.processInfo.systemUptime
    }

    // ── 重试 / 超时 ─────────────────────────────────────────────────────

    private func retry(up: Bool, payload: [UInt8]) -> [(up: Bool, payload: [UInt8])] {
        let now = SeasonSession.now()
        if state != "confirm" {
            if ["hello", "cookie", "final"].contains(state) &&
                now - created >= SeasonSession.HANDSHAKE_TIMEOUT {
                state = "bypass"
                key = nil
                log("握手 \(Int(SeasonSession.HANDSHAKE_TIMEOUT))s 内没有按预期推进，放弃改包，恢复纯转发")
            }
            return [(up, payload)]
        }
        if let started = offerStarted, now - started >= SeasonSession.TIMEOUT {
            state = "bypass"
            key = nil
            log("\(Int(SeasonSession.TIMEOUT))s 内没收到服务端 ACK（重试 \(retries) 次），放弃接管")
            var actions: [(up: Bool, payload: [UInt8])] = []
            if let final = serverFinal {
                actions.append((false, final))
            }
            if up {
                actions.append((true, payload))
            }
            return actions
        }
        if retries < SeasonSession.MAX_RETRIES &&
            now - lastOffer >= SeasonSession.RETRY_INTERVAL {
            lastOffer = now
            retries += 1
            log("重发 control7（第 \(retries) 次）")
            return [(true, request ?? payload)]
        }
        return []
    }

    private func retryCookie() -> [(up: Bool, payload: [UInt8])] {
        let now = SeasonSession.now()
        if state != "confirm" || cookieReply == nil {
            return []
        }
        if let started = offerStarted, now - started >= SeasonSession.TIMEOUT {
            return []
        }
        if cookieRetries >= SeasonSession.MAX_RETRIES {
            return []
        }
        if now - lastCookieRetry < SeasonSession.COOKIE_RETRY_INTERVAL {
            return []
        }
        cookieRetries += 1
        lastCookieRetry = now
        cookieRecoveryPending = true
        return [(true, cookieReply!)]
    }

    // ── 上行 ────────────────────────────────────────────────────────────

    public func fromGame(_ payload: [UInt8]) throws -> [(up: Bool, payload: [UInt8])] {
        if state == "bypass" {
            return [(true, payload)]
        }
        if state == "ready" {
            if payload.count < 9 {
                return []
            }
            let shifted = try SeasonProtocol.shiftHeader(Array(payload[0..<8]))
            return [(true, shifted + Array(payload[8...]))]
        }
        if SeasonProtocol.isInitial(payload) {
            if initialHeader == nil {
                initialHeader = Array(payload[0..<8])
            }
            return [(true, payload)]
        }
        if state == "cookie" &&
            payload.count == 33 &&
            (payload[8] & 3) == 1 &&
            (payload[32] & 248) == 8 {
            replyHeader = Array(payload[0..<8])
            cookieReply = payload
            state = "final"
            return [(true, payload)]
        }
        if state == "final" && payload.count >= 8 && replyHeader != nil &&
            Array(payload[0..<8]) == replyHeader! {
            return [(true, payload)]
        }
        if state == "confirm" && cookieReply != nil && payload == cookieReply! {
            let actions = retryCookie()
            if !actions.isEmpty {
                return actions
            }
        }
        return retry(up: true, payload: payload)
    }

    // ── 下行 ────────────────────────────────────────────────────────────

    public func fromServer(_ payload: [UInt8]) throws -> [(up: Bool, payload: [UInt8])] {
        if state == "bypass" {
            return [(false, payload)]
        }
        if state == "ready" {
            guard let current = key else {
                return [(false, payload)]
            }
            let plain = try SeasonCrypto.decryptDownlink(payload, key: current)
            translated += 1
            // 用手机侧的 mobile_key 重新加密，手机才解得开
            let reencrypted = try SeasonCrypto.encryptDownlink(plain, key: mobileKey)
            return [(false, reencrypted)]
        }

        if payload.count == 25 &&
            (payload[0] & 3) == 1 &&
            (payload[24] & 248) == 8 {
            let value = SeasonProtocol.floatFromLead(payload)
            if value > 0 && ["hello", "cookie", "final"].contains(state) {
                if state == "hello" {
                    state = "cookie"
                }
                return [(false, payload)]
            }
            if value == -1.0 {
                if state == "final" {
                    if let header = replyHeader {
                        serverFinal = payload
                        mobileFinal = Array(payload[0..<24]) +
                            [payload[24] & 7] +
                            [UInt8](repeating: 0, count: 19) +
                            [UInt8(8)]
                        let requestBytes = try SeasonProtocol.shiftHeader(header) + clientWire
                        request = requestBytes
                        offerStarted = SeasonSession.now()
                        lastOffer = SeasonSession.now()
                        state = "confirm"
                        log("进入接管：发出 \(clientWire.count + 8)B control7")
                        return [(true, requestBytes)]
                    }
                }
                if state == "confirm" && cookieRecoveryPending {
                    let started = offerStarted ?? 0.0
                    if SeasonSession.now() - started < SeasonSession.TIMEOUT {
                        cookieRecoveryPending = false
                        serverFinal = payload
                        lastOffer = SeasonSession.now()
                        return [(true, request!)]
                    }
                }
            }
        }

        if state == "confirm" {
            if payload.count == 1 && Int(payload[0]) == 15 {
                let actions = retryCookie()
                if !actions.isEmpty {
                    return actions
                }
            }
            if payload.count == 25 &&
                (payload[0] & 3) == 1 &&
                (payload[24] & 248) == 8 &&
                SeasonProtocol.floatFromLead(payload) == -1.0 {
                log("接管期间收到服务端重发确认挑战，补发 control7")
                return retry(up: false, payload: payload)
            }
            let ack: SeasonCrypto.Control7
            do {
                ack = try SeasonCrypto.parseControl7(payload)
            } catch {
                return retry(up: false, payload: payload)
            }
            if SeasonCrypto.matchesTranscript(client: client, ack: ack) {
                state = "ready"
                log("type-7 ACK 验签通过，会话 key 就绪")
                return [(false, mobileFinal ?? payload)]
            }
        }
        return retry(up: false, payload: payload)
    }
}

/// 多流 UDP 接管桥：维护 peers / flows / 统计，并把就绪的会话 key 抛给上层。
public final class SeasonBridge {

    /// 默认日志出口：安卓端由 CaptureRelay 注入，iOS 侧缺省直接进诊断环形缓冲。
    public static func diagnosticsSink(_ text: String) {
        Diagnostics.shared.log(text)
    }

    private static let MAX_FLOWS = 64

    /// 保持插入顺序的字典，等价于 Kotlin 的 LinkedHashMap。
    private struct OrderedMap<Value> {

        private var order: [String] = []
        private var storage: [String: Value] = [:]

        var count: Int { order.count }
        var isEmpty: Bool { order.isEmpty }
        var keys: [String] { order }

        func value(_ key: String) -> Value? {
            storage[key]
        }

        mutating func set(_ key: String, _ value: Value) {
            if storage[key] == nil {
                order.append(key)
            }
            storage[key] = value
        }

        mutating func remove(_ key: String) {
            guard storage.removeValue(forKey: key) != nil else { return }
            if let index = order.firstIndex(of: key) {
                order.remove(at: index)
            }
        }

        mutating func removeAll() {
            order.removeAll()
            storage.removeAll()
        }
    }

    private let log: (String) -> Void
    private let onReady: (_ local: String, _ remote: String, _ key: [UInt8]) -> Void
    private let lock = NSRecursiveLock()

    private var mobileKey: [UInt8]?
    private var peers = OrderedMap<[UInt8]>()
    private var bypassPeers = Set<String>()
    private var flows = OrderedMap<SeasonSession>()
    private var unsolicited = Set<String>()

    public private(set) var offers = 0
    public private(set) var readyFlows = 0
    public private(set) var bypassFlows = 0

    public init(log: @escaping (String) -> Void = SeasonBridge.diagnosticsSink,
                onReady: @escaping (_ local: String, _ remote: String, _ key: [UInt8]) -> Void = { _, _, _ in }) {
        self.log = log
        self.onReady = onReady
    }

    public var enabled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return mobileKey != nil
    }

    public func setMobileKey(material: [UInt8], advertised: [String]? = nil) throws {
        lock.lock()
        defer { lock.unlock() }

        let key: [UInt8]
        switch material.count {
        case 128:
            key = Array(material[0..<16])
        case 16:
            key = Array(material[0..<16])
        default:
            throw SeasonFailure.illegal("mobile_key 必须为 16 字节（或 128 字节 bank）")
        }

        if mobileKey == nil || key != mobileKey! {
            flows.removeAll()
            offers = 0
            readyFlows = 0
            bypassFlows = 0
            unsolicited.removeAll()
            mobileKey = key
            bypassPeers.removeAll()
            for peer in peers.keys {
                peers.set(peer, key)
            }
            log("[season] 手机侧 key 已更新 \(String(CryptoUtil.hex(key).prefix(8)))…（新局，清空旧会话）")
        }

        if let advertised = advertised, !advertised.isEmpty {
            let wantedList = advertised.filter { !$0.isEmpty }
            let wanted = Set(wantedList)
            if wanted != Set(peers.keys) {
                for peer in wantedList {
                    if let existing = peers.value(peer), existing != key {
                        bypassPeers.remove(peer)
                    }
                    peers.set(peer, key)
                }
                let stale = peers.keys.filter { !wanted.contains($0) }
                for peer in stale {
                    peers.remove(peer)
                    bypassPeers.remove(peer)
                }
                unsolicited.removeAll()
                log("[season] 对局通告端点 \(wanted.count) 个")
            }
        }
    }

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        flows.removeAll()
        offers = 0
        readyFlows = 0
        bypassFlows = 0
        unsolicited.removeAll()
    }

    private func keyFor(_ remote: String) -> [UInt8]? {
        // 没有 0x4013 通告时退回「任何 33B 首包」：本工具拿不到参考实现的
        // 候选密钥上下文，只能靠首包模板 + 5s 握手超时兜底。
        if peers.isEmpty {
            return mobileKey
        }
        if let value = peers.value(remote) {
            return value
        }
        // 端口会随对局变，IP 命中也算（与参考实现一致）。
        let ip = SeasonBridge.hostPart(remote)
        for peer in peers.keys {
            if SeasonBridge.hostPart(peer) == ip {
                return peers.value(peer)
            }
        }
        return nil
    }

    /// 这条流是不是新赛季对局流（已建会话，或首包落在已知端点）。
    public func ownsFlow(local: String, remote: String, payload: [UInt8]) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if flows.value("\(local)>\(remote)") != nil {
            return true
        }
        return SeasonProtocol.isInitial(payload) && keyFor(remote) != nil
    }

    /**
     返回要真正发出去的 [(up, payload)]；空列表表示这一包被吞掉。
     up=true 发往服务器，up=false 发往手机。
     */
    public func transform(up: Bool,
                          local: String,
                          remote: String,
                          payload: [UInt8]) throws -> [(up: Bool, payload: [UInt8])] {
        lock.lock()
        defer { lock.unlock() }

        if payload.isEmpty {
            return [(up, payload)]
        }
        let flow = "\(local)>\(remote)"
        var session = flows.value(flow)

        if up && SeasonProtocol.isInitial(payload) {
            let key = keyFor(remote)
            if let key = key, !bypassPeers.contains(remote) {
                if let existing = session, existing.state == "ready",
                   let header = existing.initialHeader,
                   payload.count >= 8,
                   Array(payload[0..<8]) == header {
                    return [] // 同一首包重传，会话已建立，吞掉
                }
                if session == nil || session!.state == "ready" {
                    if flows.count >= SeasonBridge.MAX_FLOWS {
                        flows.remove(flows.keys[0])
                    }
                    let created = try SeasonSession(mobileKey: key, log: { text in
                        self.log("[season] \(text)")
                    })
                    created.initialHeader = Array(payload[0..<8])
                    flows.set(flow, created)
                    session = created
                    log("[season] 建立新赛季会话 \(flow)（首包 \(payload.count)B）")
                }
            } else if key == nil {
                if unsolicited.insert(remote).inserted {
                    log("[season] 尚未取得对局通告端点，暂不接管 \(remote)（纯转发）")
                }
            }
        }

        guard let session = session else {
            return [(up, payload)]
        }

        let before = session.state
        let actions: [(up: Bool, payload: [UInt8])]
        if up {
            actions = try session.fromGame(payload)
        } else {
            actions = try session.fromServer(payload)
        }

        if before != "confirm" && session.state == "confirm" {
            offers += 1
        }
        if before != "ready" && session.state == "ready" {
            readyFlows += 1
            if let key = session.key {
                log("[season] 会话就绪 \(flow)（下行已可解密）")
                onReady(local, remote, key)
            }
        }
        if before != "bypass" && session.state == "bypass" {
            bypassFlows += 1
            bypassPeers.insert(remote)
            log("[season] 会话超时放弃 \(flow)，恢复纯转发")
        }
        return actions
    }

    public func snapshot() -> String {
        lock.lock()
        defer { lock.unlock() }
        return "peers=\(peers.count) flows=\(flows.count) ready=\(readyFlows) bypass=\(bypassFlows)"
    }

    private static func hostPart(_ address: String) -> String {
        guard let index = address.lastIndex(of: ":") else { return address }
        return String(address[address.startIndex..<index])
    }
}
