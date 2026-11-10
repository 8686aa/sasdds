import Foundation

/**
 把 SOCKS5 中继与「TGCP 取 128B bank」「新赛季 16B key」「WS 上报」串起来。

 上报的载荷是「手机实际收发的那一版」：
   - 旧赛季：原样；
   - 新赛季接管后：下行是代理用 mobile_key 重新加密的密文，解码器拿 16B key
     就能解；服务器原始密文（用代理会话 key 加密）解码器解不开，不报。
 */
public final class CaptureRelay: RelayHooks {

    /// 单条 TCP 流的 TGCP 会话状态（安卓 TgcpState）。
    private final class TcpState {

        var sink: TcpSink?
        var pending: [UInt8] = []
        var session: TgcpSession?
        var decided = false
        var broken = false
        var plaintextLogged = false
        let lock = NSLock()
    }

    private let reporter: SecureWsClient
    private let log: (String) -> Void
    private let diag: (String) -> Void
    private let gate: UdpGate

    // 在 init 末尾建立（闭包需要 capturing self，放在 init 内可避开 lazy 的并发初始化问题）。
    private var season: SeasonBridge!

    private let statesLock = NSLock()
    private var tgcpStates: [Int64: TcpState] = [:]

    private let keyLock = NSLock()
    private var currentKeyIdValue = ""

    let tcpBanks = AtomicCounter()
    let seasonKeys = AtomicCounter()
    let udpReported = AtomicCounter()

    init(reporter: SecureWsClient,
         log: @escaping (String) -> Void,
         diag: @escaping (String) -> Void = { _ in }) {
        self.reporter = reporter
        self.log = log
        self.diag = diag
        gate = UdpGate(log: log)
        season = SeasonBridge(
            log: log,
            onReady: { [weak self] local, remote, key in
                self?.reportSeasonKey(local: local, remote: remote, key: key)
            }
        )
    }

    // ── TCP ─────────────────────────────────────────────────────────────

    public func onTcpAttach(flow: TcpFlow, sink: TcpSink) {
        let state = TcpState()
        state.sink = sink
        flow.state = state
        statesLock.lock()
        tgcpStates[flow.id] = state
        statesLock.unlock()
    }

    public func onTcpUp(flow: TcpFlow, data: [UInt8]) {
        handleTcp(flow: flow, data: data, up: true)
    }

    public func onTcpDown(flow: TcpFlow, data: [UInt8]) {
        handleTcp(flow: flow, data: data, up: false)
    }

    public func onTcpClosed(flow: TcpFlow) {
        statesLock.lock()
        let state = tgcpStates.removeValue(forKey: flow.id)
        statesLock.unlock()
        guard let state = state else { return }
        if let session = state.session {
            log("TGCP 会话结束 \(flow.remoteIp):\(flow.remotePort) 帧 \(session.frames) " +
                "解密 \(session.decryptedFrames) 明文 \(session.plaintextFrames)")
            session.close()
        }
        state.pending.removeAll()
    }

    private func handleTcp(flow: TcpFlow, data: [UInt8], up: Bool) {
        guard let state = flow.state as? TcpState else { return }
        if state.broken { return }
        guard let sink = state.sink else { return }

        if let session = state.session {
            feed(flow: flow, state: state, session: session, up: up, data: data)
            return
        }
        if state.decided {
            if up { sink.toServer(data) } else { sink.toClient(data) }
            return
        }
        if !up {
            // 服务端先说话说明不是我们所认识的双向握手，直接放行。
            state.decided = true
            sink.toClient(data)
            return
        }

        state.pending.append(contentsOf: data)
        let buffered = state.pending
        switch TgcpProtocol.sniff(buffered) {
        case 0:
            if buffered.count > 65536 {
                state.decided = true
                state.pending.removeAll()
                sink.toServer(buffered)
            }
        case 1:
            state.decided = true
            state.pending.removeAll()
            sink.toServer(buffered)
        default:
            state.pending.removeAll()
            let created = TgcpSession()
            state.session = created
            log("已识别加密会话 \(flow.remoteIp):\(flow.remotePort)")
            log("首帧 \(buffered.count) 字节")
            diag("[tgcp] 双密钥握手 flow=\(flow.remoteIp):\(flow.remotePort) " +
                "first=\(buffered.count)B head=\(CryptoUtil.hex(Array(buffered.prefix(32))))")
            feed(flow: flow, state: state, session: created, up: true, data: buffered)
            if created.directionMismatch {
                log("TGCP 方向字节与参考实现相反（已按收包侧处理） \(flow.remoteIp):\(flow.remotePort)")
                diag("[tgcp] 方向不匹配 flow=\(flow.remoteIp):\(flow.remotePort) " +
                    "frames=\(created.frames) 已按收包侧处理")
            }
        }
    }

    private func feed(flow: TcpFlow,
                      state: TcpState,
                      session: TgcpSession,
                      up: Bool,
                      data: [UInt8]) {
        // feed + 写回必须在同一个锁里：上下行两个泵线程若交错写同一个 socket，
        // 会把帧顺序打乱，表现为「帧头错误 / 密文未对齐 / 方向不匹配」。
        var observations: [TgcpObservation] = []
        do {
            state.lock.lock()
            defer { state.lock.unlock() }
            let output = try session.feed(up: up, input: data)
            state.sink?.toServer(output.toServer)
            state.sink?.toClient(output.toClient)
            observations = output.observations
        } catch {
            log("TGCP 会话中断 \(flow.remoteIp):\(flow.remotePort): \(message(error))")
            diag("[tgcp] 中断 flow=\(flow.remoteIp):\(flow.remotePort) " +
                "frames=\(session.frames) err=\(message(error))")
            // 一个字节都还没改写时降级为明文直通，别让协议差异把游戏连接打死。
            if session.frames == 0 {
                state.session = nil
                state.decided = true
                state.lock.lock()
                let sink = state.sink
                if up { sink?.toServer(data) } else { sink?.toClient(data) }
                state.lock.unlock()
            } else {
                state.broken = true
            }
            return
        }

        if session.plaintextFrames > 0 && !state.plaintextLogged {
            state.plaintextLogged = true
            log("TGCP 有明文帧直通 \(flow.remoteIp):\(flow.remotePort)")
        }
        for observation in observations {
            for bank in observation.banks {
                publishBank(flow: flow, bank: bank)
            }
        }
    }

    /// 128B bank：既上报对局密钥，也把前 16 字节交给新赛季桥接。
    private func publishBank(flow: TcpFlow, bank: [UInt8]) {
        let sha256 = CryptoUtil.hex(CryptoUtil.sha256(bank))
        let keyId = String(sha256.prefix(16))
        tcpBanks.increment()
        _ = try? season.setMobileKey(material: bank)
        diag("[bank] #\(tcpBanks.value) len=\(bank.count) sha256=\(sha256) " +
            "hex=\(CryptoUtil.hex(bank)) b64=\(CryptoUtil.b64(bank)) " +
            "flow=\(flow.remoteIp):\(flow.remotePort)")
        if keyId == currentKeyId { return }
        setCurrentKeyId(keyId)
        let message: [String: Any] = [
            "type": "battle_key",
            "key_id": keyId,
            "sha256": sha256,
            "material": CryptoUtil.b64(bank),
            "observed_ms": Int64(Date().timeIntervalSince1970 * 1000),
            "verified": true,
            "keyLength": 128,
            "protocol": "bank128",
        ]
        if let text = jsonText(message) {
            reporter.sendKey(text)
        }
        log("新增候选特征 #\(tcpBanks.value)（\(bank.count) 字节）")
    }

    private func reportSeasonKey(local: String, remote: String, key: [UInt8]) {
        let sha256 = CryptoUtil.hex(CryptoUtil.sha256(key))
        let keyId = String(sha256.prefix(16))
        seasonKeys.increment()
        setCurrentKeyId(keyId)
        diag("[season] #\(seasonKeys.value) len=\(key.count) hex=\(CryptoUtil.hex(key)) " +
            "b64=\(CryptoUtil.b64(key)) sha256=\(sha256) flow=\(local) > \(remote)")
        let message: [String: Any] = [
            "type": "battle_key",
            "key_id": keyId,
            "sha256": sha256,
            "material": CryptoUtil.b64(key),
            "observed_ms": Int64(Date().timeIntervalSince1970 * 1000),
            "verified": true,
            "keyLength": 16,
            "protocol": "season16",
            "flowLocal": local,
            "flowRemote": remote,
        ]
        if let text = jsonText(message) {
            reporter.sendKey(text)
        }
        log("已处理会话特征 #\(seasonKeys.value)（\(local) > \(remote)）")
    }

    // ── UDP ─────────────────────────────────────────────────────────────

    public func onUdpUp(clientIp: String,
                        clientPort: Int,
                        remoteIp: String,
                        remotePort: Int,
                        payload: [UInt8],
                        sink: UdpSink) {
        let local = "\(clientIp):\(clientPort)"
        let remote = "\(remoteIp):\(remotePort)"
        let known = season.ownsFlow(local: local, remote: remote, payload: payload)
        let actions: [(up: Bool, payload: [UInt8])]
        do {
            actions = try season.transform(up: true, local: local, remote: remote, payload: payload)
        } catch {
            log("[season] 上行改写失败 \(remote): \(message(error))")
            actions = [(true, payload)]
        }

        let reportable = gate.feed(up: true,
                                   clientIp: clientIp,
                                   clientPort: clientPort,
                                   remoteIp: remoteIp,
                                   remotePort: remotePort,
                                   payload: payload,
                                   known: known)
        for item in reportable {
            report(up: item.0,
                   payload: item.1,
                   clientIp: clientIp,
                   clientPort: clientPort,
                   remoteIp: remoteIp,
                   remotePort: remotePort)
        }
        for action in actions {
            if action.up { sink.toServer(action.payload) } else { sink.toClient(action.payload) }
        }
    }

    public func onUdpDown(clientIp: String,
                          clientPort: Int,
                          remoteIp: String,
                          remotePort: Int,
                          payload: [UInt8],
                          sink: UdpSink) {
        let local = "\(clientIp):\(clientPort)"
        let remote = "\(remoteIp):\(remotePort)"
        let known = season.ownsFlow(local: local, remote: remote, payload: payload)
        let actions: [(up: Bool, payload: [UInt8])]
        do {
            actions = try season.transform(up: false, local: local, remote: remote, payload: payload)
        } catch {
            log("[season] 下行改写失败 \(remote): \(message(error))")
            actions = [(false, payload)]
        }

        let reportable = gate.feed(up: false,
                                   clientIp: clientIp,
                                   clientPort: clientPort,
                                   remoteIp: remoteIp,
                                   remotePort: remotePort,
                                   payload: payload,
                                   known: known)
        for item in reportable {
            report(up: item.0,
                   payload: item.1,
                   clientIp: clientIp,
                   clientPort: clientPort,
                   remoteIp: remoteIp,
                   remotePort: remotePort)
        }
        for action in actions {
            if action.up { sink.toServer(action.payload) } else { sink.toClient(action.payload) }
        }
    }

    private func report(up: Bool,
                        payload: [UInt8],
                        clientIp: String,
                        clientPort: Int,
                        remoteIp: String,
                        remotePort: Int) {
        if payload.isEmpty { return }
        guard let client = parseIpv4(clientIp), let remote = parseIpv4(remoteIp) else { return }
        let packet: [UInt8]
        if up {
            packet = IpPacket.buildUdp(sourceIp: client,
                                       destinationIp: remote,
                                       sourcePort: clientPort,
                                       destinationPort: remotePort,
                                       payload: payload)
        } else {
            packet = IpPacket.buildUdp(sourceIp: remote,
                                       destinationIp: client,
                                       sourcePort: remotePort,
                                       destinationPort: clientPort,
                                       payload: payload)
        }
        reporter.submit(datagram: packet, keyId: currentKeyId)
        udpReported.increment()
    }

    private func parseIpv4(_ text: String) -> [UInt8]? {
        if let raw = IpPacket.ipv4(text) { return raw }
        guard let node = SocketIO.resolve(host: text) else { return nil }
        return IpPacket.ipv4(node.host)
    }

    // ── 上报闸门（对齐 app.py 的 _FlowFilter） ──────────────────────────

    /**
     只上报「远端为公网 + 按序命中握手长度模板」的 UDP，避免 DNS/组播等噪声
     占用解码器。命中前先缓冲、命中后整段补发；桥接确认的对局流直接放行。
     */
    private final class UdpFlow {

        var progress: [Int]
        var game = false
        var lastSeen: Double
        var pending: [(up: Bool, payload: [UInt8])] = []

        init(now: Double, templates: Int) {
            lastSeen = now
            progress = [Int](repeating: 0, count: templates)
        }
    }

    private final class UdpGate {

        static let templates: [[(Bool, Int)]] = [
            [(true, 33), (false, 25), (true, 33), (false, 25), (true, 35), (false, 31), (false, 10)],
            [(true, 33), (false, 25), (true, 33), (false, 25), (true, 77), (false, 69)],
            [(true, 33), (false, 25), (true, 33), (false, 25), (false, 45)],
        ]

        private let log: (String) -> Void
        private let lock = NSLock()
        private var flows: [String: UdpFlow] = [:]
        private var logged = 0

        init(log: @escaping (String) -> Void) {
            self.log = log
        }

        func feed(up: Bool,
                  clientIp: String,
                  clientPort: Int,
                  remoteIp: String,
                  remotePort: Int,
                  payload: [UInt8],
                  known: Bool) -> [(up: Bool, payload: [UInt8])] {
            if UdpGate.isPrivate(remoteIp) { return [] }

            lock.lock()
            defer { lock.unlock() }

            let key = "\(clientIp)|\(clientPort)|\(remoteIp)|\(remotePort)"
            let now = ProcessInfo.processInfo.systemUptime
            var flow = flows[key]
            if flow == nil {
                if logged < 5 {
                    logged += 1
                    log("[udp] 新流 \(remoteIp):\(remotePort) 首包 \(payload.count) 字节")
                }
                if !known && payload.count != 33 { return [] }
                if flows.count >= 1024 {
                    guard let oldest = flows.min(by: { $0.value.lastSeen < $1.value.lastSeen })?.key else {
                        return []
                    }
                    flows.removeValue(forKey: oldest)
                }
                let created = UdpFlow(now: now, templates: UdpGate.templates.count)
                flows[key] = created
                flow = created
            }
            guard let current = flow else { return [] }
            current.lastSeen = now

            if known && !current.game {
                current.game = true
                var out = current.pending
                current.pending.removeAll()
                out.append((up, payload))
                return out
            }
            if current.game {
                return [(up, payload)]
            }

            current.pending.append((up, payload))
            var completed = false
            for index in UdpGate.templates.indices {
                let template = UdpGate.templates[index]
                let step = current.progress[index]
                if step < template.count && template[step] == (up, payload.count) {
                    current.progress[index] = step + 1
                    if step + 1 == template.count {
                        completed = true
                    }
                }
            }

            if !completed {
                if current.pending.count > 64 {
                    flows.removeValue(forKey: key)
                    return []
                }
                return []
            }

            current.game = true
            let out = current.pending
            current.pending.removeAll()
            return out
        }

        private static func isPrivate(_ ip: String) -> Bool {
            let parts = ip.split(separator: ".", omittingEmptySubsequences: false)
            if parts.count != 4 { return true }
            var octets = [Int]()
            for part in parts {
                guard let value = Int(part), value >= 0, value <= 255 else { return true }
                octets.append(value)
            }
            let a = octets[0]
            let b = octets[1]
            if a == 10 || a == 127 || a == 0 { return true }
            if a == 172 && (16...31).contains(b) { return true }
            if a == 192 && b == 168 { return true }
            if a == 169 && b == 254 { return true }
            return false
        }
    }

    // ── 小工具 ───────────────────────────────────────────────────────────

    private var currentKeyId: String {
        keyLock.lock()
        defer { keyLock.unlock() }
        return currentKeyIdValue
    }

    private func setCurrentKeyId(_ value: String) {
        keyLock.lock()
        currentKeyIdValue = value
        keyLock.unlock()
    }

    private func jsonText(_ object: [String: Any]) -> String? {
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: []),
              let text = String(data: data, encoding: .utf8) else { return nil }
        return text
    }

    private func message(_ error: Error) -> String {
        if let described = error as? CustomStringConvertible {
            return described.description
        }
        return String(describing: error)
    }
}
