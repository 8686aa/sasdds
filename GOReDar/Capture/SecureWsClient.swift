import Foundation

/// 与安卓端 SecureWsClient.kt 错误语义等价的异常。
public enum SecureWsFailure: Error, CustomStringConvertible {
    case illegal(String)

    public var description: String {
        switch self {
        case .illegal(let message):
            return message
        }
    }
}

/// WS 1082 secure_ws 客户端的就绪/断开回调（安卓 Listener）。
public protocol SecureWsListener: AnyObject {
    func onReady()
    func onDown(_ reason: String)
}

/**
 WS 1082 secure_ws 客户端。

 线协议（与中转器 SecureChannel.cs 对齐）：
   hello(明文) -> challenge(明文) -> finish(密文) -> ok(密文) -> batch/battle_key(密文)
 加密：HKDF-SHA256 派生 104 字节；AES-256-GCM；
       nonce = iv(4) + seq(8 大端)；AAD = "SRW1" + 版本 + 方向 + seq。

 安卓端的三条守护线程在这里用三条 Thread 复现：连接/读取、发送、心跳。
 */
public final class SecureWsClient {

    private enum Item {
        case datagram(packet: [UInt8], keyId: String)
        case key(json: String)
    }

    /// 双端队列：submit 走尾部，失败重排走头部，避免 Array.removeFirst 的整段搬移。
    private struct Deque<Element> {

        private var storage: [Element] = []
        private var head = 0

        var count: Int { storage.count - head }
        var isEmpty: Bool { count == 0 }

        mutating func append(_ value: Element) {
            storage.append(value)
        }

        mutating func prepend(_ value: Element) {
            if head > 0 {
                head -= 1
                storage[head] = value
            } else {
                storage.insert(value, at: 0)
            }
        }

        mutating func removeFirst() -> Element? {
            guard head < storage.count else { return nil }
            let value = storage[head]
            head += 1
            if head > 64 && head * 2 > storage.count {
                storage.removeFirst(head)
                head = 0
            }
            return value
        }

        mutating func removeAll() {
            storage.removeAll()
            head = 0
        }
    }

    private static let MAX_DATA_QUEUE = 20000
    private static let MAX_KEY_QUEUE = 1000

    private let host: String
    private let port: Int
    private let apiKey: String
    private weak var listener: SecureWsListener?

    private let condition = NSCondition()
    private var data = Deque<Item>()
    private var keys = Deque<Item>()

    private var running = true
    private var ready = false
    private var ws: WsConnection?

    private var c2sKey: [UInt8] = []
    private var s2cKey: [UInt8] = []
    private var proofKey: [UInt8] = []
    private var c2sIv: [UInt8] = []
    private var s2cIv: [UInt8] = []
    private var c2sSeq: Int64 = 0
    private var s2cSeq: Int64 = 0

    private let sentCounter = AtomicCounter()
    private let droppedCounter = AtomicCounter()

    public init(host: String, port: Int, apiKey: String, listener: SecureWsListener?) {
        self.host = host
        self.port = port
        self.apiKey = apiKey
        self.listener = listener
    }

    public var sentBatches: Int64 { sentCounter.value }
    public var dropped: Int64 { droppedCounter.value }

    public var queued: Int {
        condition.lock()
        defer { condition.unlock() }
        return data.count + keys.count
    }

    // ── 生命周期 ─────────────────────────────────────────────────────────

    public func start() {
        let connectThread = Thread { self.connectLoop() }
        connectThread.name = "secure-ws"
        connectThread.start()

        let sendThread = Thread { self.sendLoop() }
        sendThread.name = "secure-ws-send"
        sendThread.start()

        let heartbeatThread = Thread { self.heartbeatLoop() }
        heartbeatThread.name = "secure-ws-ping"
        heartbeatThread.start()
    }

    public func stop() {
        running = false
        ready = false
        condition.lock()
        condition.broadcast()
        condition.unlock()
        ws?.close()
    }

    public func submit(datagram: [UInt8], keyId: String) {
        condition.lock()
        if data.count >= SecureWsClient.MAX_DATA_QUEUE {
            _ = data.removeFirst()
            droppedCounter.increment()
        }
        data.append(.datagram(packet: datagram, keyId: keyId))
        condition.broadcast()
        condition.unlock()
    }

    public func sendKey(_ json: String) {
        condition.lock()
        if keys.count >= SecureWsClient.MAX_KEY_QUEUE {
            _ = keys.removeFirst()
        }
        keys.append(.key(json: json))
        condition.broadcast()
        condition.unlock()
    }

    // ── 连接 / 鉴权 ──────────────────────────────────────────────────────

    private func connectLoop() {
        var delay: Double = 1.0
        while running {
            do {
                try connectAndAuth()
                delay = 1.0
                try readLoop()
            } catch {
                ready = false
                ws?.close()
                ws = nil
                if !running { return }
                listener?.onDown(errorText(error))
                if !pause(delay) { return }
                delay = 5.0
            }
        }
    }

    private func connectAndAuth() throws {
        c2sSeq = 0
        s2cSeq = 0

        let connection = WsConnection(host: host, port: port)
        try connection.connect()
        ws = connection

        let clientNonce = CryptoUtil.randomBytes(32)
        let hello: [String: Any] = [
            "type": "secure_hello",
            "v": 1,
            "api_key": apiKey,
            "nonce": CryptoUtil.hex(clientNonce),
        ]
        try connection.sendText(try jsonText(hello))

        guard let challengeText = try connection.readMessage() else {
            throw SecureWsFailure.illegal("服务端在 challenge 前关闭连接")
        }
        let challenge = try jsonObject(challengeText)
        guard stringField(challenge, "type") == "secure_challenge" else {
            throw SecureWsFailure.illegal("期望 secure_challenge，收到 \(stringField(challenge, "type"))")
        }
        guard intField(challenge, "v", 0) == 1 else {
            throw SecureWsFailure.illegal("secure_ws 版本不匹配")
        }
        guard let nonceText = challenge["nonce"] as? String,
              let proofText = challenge["proof"] as? String else {
            throw SecureWsFailure.illegal("challenge 字段缺失")
        }
        let serverNonce = try CryptoUtil.unhex(nonceText)
        let serverProof = try CryptoUtil.unhex(proofText)
        if serverNonce.count != 32 || serverProof.count != 32 {
            throw SecureWsFailure.illegal("challenge 字段长度不正确")
        }

        let roomId = CryptoUtil.hex(
            CryptoUtil.sha256(Array("StarRadarRoomKeyV1\u{0}".utf8) + Array(apiKey.utf8))
        )
        let transcript = "StarRadarSecureWS1|\(roomId)|\(CryptoUtil.hex(clientNonce))|\(CryptoUtil.hex(serverNonce))"

        let material = CryptoUtil.hkdfSha256(
            ikm: Array(apiKey.utf8),
            salt: clientNonce + serverNonce,
            info: Array("StarRadarSecureWS/v1".utf8),
            length: 104
        )
        c2sKey = Array(material[0..<32])
        s2cKey = Array(material[32..<64])
        c2sIv = Array(material[64..<68])
        s2cIv = Array(material[68..<72])
        proofKey = Array(material[72..<104])

        let expected = CryptoUtil.hmacSha256(key: proofKey,
                                             data: Array(("server|" + transcript).utf8))
        if !CryptoUtil.constantTimeEquals(expected, serverProof) {
            throw SecureWsFailure.illegal("服务端 proof 校验失败（房间 Key 不匹配？）")
        }

        let clientProof = CryptoUtil.hmacSha256(key: proofKey,
                                                data: Array(("client|" + transcript).utf8))
        let finish: [String: Any] = [
            "type": "secure_finish",
            "v": 1,
            "proof": CryptoUtil.hex(clientProof),
        ]
        try connection.sendText(try encrypt(try jsonText(finish)))

        guard let okText = try connection.readMessage() else {
            throw SecureWsFailure.illegal("服务端在 secure_ok 前关闭连接")
        }
        let ok = try jsonObject(try decrypt(okText))
        guard stringField(ok, "type") == "secure_ok" else {
            throw SecureWsFailure.illegal("期望 secure_ok，收到 \(stringField(ok, "type"))")
        }

        ready = true
        listener?.onReady()
        condition.lock()
        condition.broadcast()
        condition.unlock()
    }

    private func readLoop() throws {
        while running && ready {
            guard let message = try ws?.readMessage() else { break }
            do {
                let obj = try jsonObject(try decrypt(message))
                // 服务端目前只回 secure_ok 之外的空闲消息；收到未知类型只记日志。
                if stringField(obj, "type") == "secure_ping" {
                    // 无需回应，WS 层已有 ping/pong。
                }
            } catch {
                // 单条坏包不打断连接，交给心跳/超时判定。
            }
        }
        if !running { return }
        throw SecureWsFailure.illegal("服务端关闭连接")
    }

    // ── 发送循环 ─────────────────────────────────────────────────────────

    private func sendLoop() {
        while running {
            var payload = ""
            var used: [Item] = []
            var isDatagramBatch = false

            condition.lock()
            while running && (!ready || (keys.isEmpty && data.isEmpty)) {
                _ = condition.wait(until: Date(timeIntervalSinceNow: 0.5))
            }
            if !running {
                condition.unlock()
                return
            }
            if !keys.isEmpty {
                if let item = keys.removeFirst() {
                    used = [item]
                    if case .key(let json) = item {
                        payload = json
                    }
                }
            } else {
                var batch: [[String: Any]] = []
                var items: [Item] = []
                while items.count < 40 && !data.isEmpty {
                    guard let item = data.removeFirst() else { break }
                    items.append(item)
                    if case .datagram(let packet, let keyId) = item {
                        batch.append(["data": CryptoUtil.b64(packet), "k": keyId])
                    }
                }
                used = items
                isDatagramBatch = !items.isEmpty
                let body: [String: Any] = ["batch": batch]
                payload = (try? jsonText(body)) ?? "{\"batch\":[]}"
            }
            condition.unlock()

            do {
                guard let connection = ws else {
                    throw SecureWsFailure.illegal("连接已断开")
                }
                try connection.sendText(try encrypt(payload))
                if isDatagramBatch {
                    sentCounter.increment()
                }
            } catch {
                ready = false
                condition.lock()
                for item in used.reversed() {
                    switch item {
                    case .datagram:
                        data.prepend(item)
                    case .key:
                        keys.prepend(item)
                    }
                }
                condition.broadcast()
                condition.unlock()
                ws?.close()
                listener?.onDown(errorText(error))
            }
        }
    }

    // ── 心跳 ─────────────────────────────────────────────────────────────

    private func heartbeatLoop() {
        while running {
            if !pause(5) { return }
            if ready {
                do {
                    try ws?.sendPing()
                } catch {
                    ws?.close()
                }
            }
        }
    }

    // ── 加解密 ───────────────────────────────────────────────────────────

    private func encrypt(_ payload: String) throws -> String {
        c2sSeq += 1
        let seq = c2sSeq
        let nonce = c2sIv + bigEndian(seq)
        let cipher = try CryptoUtil.aesGcmEncrypt(key: c2sKey,
                                                  nonce: nonce,
                                                  aad: aad(direction: 1, seq: seq),
                                                  plain: Array(payload.utf8))
        return try jsonText([
            "type": "enc",
            "v": 1,
            "seq": seq,
            "d": CryptoUtil.b64(cipher),
        ])
    }

    private func decrypt(_ message: String) throws -> String {
        let obj = try jsonObject(message)
        guard stringField(obj, "type") == "enc" else {
            throw SecureWsFailure.illegal("期望 enc 信封，收到 \(stringField(obj, "type"))")
        }
        guard intField(obj, "v", 0) == 1 else {
            throw SecureWsFailure.illegal("enc 版本不匹配")
        }
        guard let boxed = obj["seq"] as? NSNumber else {
            throw SecureWsFailure.illegal("enc 序号缺失")
        }
        let seq = boxed.int64Value
        if seq != s2cSeq + 1 {
            throw SecureWsFailure.illegal("s2c 序号不连续: \(seq), 期望 \(s2cSeq + 1)")
        }
        guard let encoded = obj["d"] as? String else {
            throw SecureWsFailure.illegal("enc 密文缺失")
        }
        let nonce = s2cIv + bigEndian(seq)
        let plain = try CryptoUtil.aesGcmDecrypt(key: s2cKey,
                                                 nonce: nonce,
                                                 aad: aad(direction: 2, seq: seq),
                                                 data: try CryptoUtil.unb64(encoded))
        s2cSeq = seq
        return String(decoding: plain, as: UTF8.self)
    }

    private func aad(direction: Int, seq: Int64) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 14)
        out[0] = 0x53 // S
        out[1] = 0x52 // R
        out[2] = 0x57 // W
        out[3] = 0x31 // 1
        out[4] = 1
        out[5] = UInt8(truncatingIfNeeded: direction)
        let value = bigEndian(seq)
        out.replaceSubrange(6..<14, with: value)
        return out
    }

    private func bigEndian(_ value: Int64) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 8)
        var bits = UInt64(bitPattern: value)
        for index in stride(from: 7, through: 0, by: -1) {
            out[index] = UInt8(truncatingIfNeeded: bits)
            bits >>= 8
        }
        return out
    }

    // ── 工具 ─────────────────────────────────────────────────────────────

    private func jsonText(_ object: [String: Any]) throws -> String {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: []),
              let text = String(data: data, encoding: .utf8) else {
            throw SecureWsFailure.illegal("JSON 序列化失败")
        }
        return text
    }

    private func jsonObject(_ text: String) throws -> [String: Any] {
        guard let data = text.data(using: .utf8),
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw SecureWsFailure.illegal("JSON 解析失败")
        }
        return object
    }

    private func stringField(_ object: [String: Any], _ key: String) -> String {
        object[key] as? String ?? ""
    }

    private func intField(_ object: [String: Any], _ key: String, _ fallback: Int) -> Int {
        if let number = object[key] as? NSNumber { return number.intValue }
        if let text = object[key] as? String, let value = Int(text) { return value }
        return fallback
    }

    private func errorText(_ error: Error) -> String {
        if let described = error as? CustomStringConvertible {
            return described.description
        }
        return String(describing: error)
    }

    /// 分片睡眠，保证 stop() 后线程能在 200ms 内退出。
    private func pause(_ seconds: Double) -> Bool {
        var remaining = seconds
        while remaining > 0 && running {
            let chunk = min(0.2, remaining)
            Thread.sleep(forTimeInterval: chunk)
            remaining -= chunk
        }
        return running
    }
}
