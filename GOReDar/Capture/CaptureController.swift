import UIKit
import AVFoundation
import Darwin

/**
 抓包控制器：替代安卓的 CaptureService（前台服务）。

 职责与安卓一致：解析节点地址 -> 建立 SecureWsClient -> 启动 Socks5Server 并挂上
 CaptureRelay。iOS 没有前台服务，这里用「后台任务 + 静音播放」维持进程存活，
 保证锁屏后 SOCKS5 与 WS 不被系统挂起（UIBackgroundModes 已配置 audio）。
 */
final class CaptureController: SecureWsListener {

    static let shared = CaptureController()

    private static let maxLogs = 40

    private let lock = NSLock()
    private let diagLock = NSLock()
    private let logFormatter: DateFormatter

    private var ws: SecureWsClient?
    private var relay: CaptureRelay?
    private var server: Socks5Server?
    private var stopping = true

    private var nodeText = ""
    private var socksText = ""
    private var wsState = "未连接"
    private var logs: [String] = []
    private var listenAddressValue = ""

    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    private var silence: AVAudioPlayer?
    private var keepAliveTimer: Timer?
    private var observers: [NSObjectProtocol] = []

    private init() {
        logFormatter = DateFormatter()
        logFormatter.dateFormat = "HH:mm:ss"
    }

    // ── 对外状态 ─────────────────────────────────────────────────────────

    /// 每次读取都按当前计数重新生成，页面每 0.9 秒拉一次。
    var stateJson: String {
        lock.lock()
        let server = self.server
        let client = self.ws
        let relay = self.relay
        let running = !stopping && server != nil
        let wsText = wsState
        let ip = listenAddressValue
        let listen = socksText
        let node = nodeText
        let lines = logs
        lock.unlock()

        let payload: [String: Any] = [
            "running": running,
            "ws": wsText,
            "listen": listen,
            "node": node,
            "ip": ip,
            "tcp": server?.activeTcp.value ?? Int64(0),
            "udp": server?.activeUdp.value ?? Int64(0),
            "refused": server?.refused.value ?? Int64(0),
            "banks": relay?.tcpBanks.value ?? Int64(0),
            "season": relay?.seasonKeys.value ?? Int64(0),
            "reported": relay?.udpReported.value ?? Int64(0),
            "sent": client?.sentBatches ?? Int64(0),
            "queued": client?.queued ?? 0,
            "dropped": client?.dropped ?? Int64(0),
            "logs": lines,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: []),
              let text = String(data: data, encoding: .utf8) else {
            return "{\"running\":false}"
        }
        return text
    }

    /// 最近 400 条诊断（含密钥等原始数据），只用于「一键上报日志」。
    var diagnostics: [String] {
        Diagnostics.shared.snapshot
    }

    /// 本机局域网 IPv4，优先 en0；没有则返回空串。
    var listenAddress: String {
        localIPv4()
    }

    // ── 启动 / 停止 ──────────────────────────────────────────────────────

    /// 返回 "" 表示已启动，否则返回中文错误。
    func start(node: String, port: UInt16) -> String {
        let target = node.trimmingCharacters(in: .whitespacesAndNewlines)
        let apiKey = SecureStore.get("api_key")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()

        guard !target.isEmpty, apiKey.count == 32 else {
            stop()
            return "配置不完整，未启动"
        }
        guard port >= 1 else {
            stop()
            return "端口需在 1-65535 之间"
        }

        // 与安卓 onStartCommand 一致：先停掉上一轮，再按新配置重建。
        stop()

        let parsed = parseNode(target)
        guard !parsed.host.isEmpty else {
            return "节点地址无效"
        }
        guard canBind(Int(port)) else {
            return "本地端口 \(port) 已被占用"
        }

        let client = SecureWsClient(host: parsed.host,
                                    port: parsed.port,
                                    apiKey: apiKey,
                                    listener: self)
        let hooks = CaptureRelay(reporter: client,
                                 log: { [weak self] message in self?.pushLog(message) },
                                 diag: { [weak self] message in self?.pushDiag(message) })
        let socks = Socks5Server(port: Int(port), hooks: hooks)

        lock.lock()
        ws = client
        relay = hooks
        server = socks
        nodeText = "\(parsed.host):\(parsed.port)"
        socksText = "0.0.0.0:\(port)"
        wsState = "未连接"
        stopping = false
        lock.unlock()

        pushDiag("配置 node=\(target) socks=\(port) ws=\(parsed.host):\(parsed.port)")

        client.start()
        socks.start()

        pushLog("本地接入已开启 \(socksText)")
        let ip = localIPv4()
        lock.lock()
        listenAddressValue = ip
        lock.unlock()
        if !ip.isEmpty {
            pushLog("设备接入地址：\(ip):\(port)")
        }

        beginKeepAlive()
        return ""
    }

    /// 允许重复调用。
    func stop() {
        lock.lock()
        let server = self.server
        let client = self.ws
        self.server = nil
        self.ws = nil
        self.relay = nil
        stopping = true
        wsState = "未连接"
        listenAddressValue = ""
        lock.unlock()

        server?.stop()
        client?.stop()
        endKeepAlive()
    }

    // ── WS 回调 ──────────────────────────────────────────────────────────

    func onReady() {
        lock.lock()
        wsState = "已就绪"
        lock.unlock()
        pushLog("数据通道已就绪")
    }

    func onDown(_ reason: String) {
        lock.lock()
        wsState = "断开重连"
        lock.unlock()
        pushLog("数据通道断开：\(reason)")
    }

    // ── 节点解析 ─────────────────────────────────────────────────────────

    /// 与安卓 CaptureService.parseNode 完全一致：
    /// 剥掉 ws:// / wss://、去掉末尾 '/'，最后一个冒号后是数字才当端口，否则 1082。
    private func parseNode(_ node: String) -> (host: String, port: Int) {
        var text = node
        if text.hasPrefix("ws://") {
            text.removeFirst(5)
        } else if text.hasPrefix("wss://") {
            text.removeFirst(6)
        }
        while text.hasSuffix("/") {
            text.removeLast()
        }
        if let colon = text.lastIndex(of: ":"), colon != text.startIndex {
            let portText = String(text[text.index(after: colon)...])
            if let value = Int(portText) {
                return (String(text[text.startIndex..<colon]), value)
            }
        }
        return (text, 1082)
    }

    private func canBind(_ port: Int) -> Bool {
        let handle = socket(AF_INET, SOCK_STREAM, 0)
        guard handle >= 0 else { return false }
        defer { Darwin.close(handle) }
        var one: Int32 = 1
        _ = setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        let any = SocketIO.NodeAddress(family: AF_INET, bytes: [0, 0, 0, 0], host: "0.0.0.0")
        // 只有 bind + listen 都成功才说明端口真正可用。
        return SocketIO.bind(handle, to: any, port: port) && listen(handle, 1) == 0
    }

    // ── 本机地址 ─────────────────────────────────────────────────────────

    private func localIPv4() -> String {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return "" }
        defer { freeifaddrs(first) }

        var best: (score: Int, ip: String)?
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let item = cursor {
            cursor = item.pointee.ifa_next
            guard let address = item.pointee.ifa_addr,
                  Int32(address.pointee.sa_family) == AF_INET else { continue }
            let name = String(cString: item.pointee.ifa_name)
            if name.hasPrefix("lo") { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(address,
                                     socklen_t(MemoryLayout<sockaddr_in>.size),
                                     &host,
                                     socklen_t(host.count),
                                     nil,
                                     0,
                                     NI_NUMERICHOST)
            guard result == 0 else { continue }
            let ip = String(cString: host)
            if ip.isEmpty { continue }

            // 扫码方需要能从局域网访问：en0（Wi-Fi）优先，其次其它网卡、私有网段。
            let score: Int
            if name.hasPrefix("en0") {
                score = 0
            } else if name.hasPrefix("en") {
                score = 1
            } else if localIsPrivate(ip) {
                score = 2
            } else {
                score = 3
            }
            if best == nil || score < best!.score {
                best = (score: score, ip: ip)
            }
        }
        return best?.ip ?? ""
    }

    private func localIsPrivate(_ host: String) -> Bool {
        let parts = host.split(separator: ".")
        guard parts.count == 4,
              let a = Int(parts[0]),
              let b = Int(parts[1]) else { return false }
        return a == 10 ||
            (a == 192 && b == 168) ||
            (a == 172 && (16...31).contains(b))
    }

    // ── 日志 ─────────────────────────────────────────────────────────────

    private func pushLog(_ message: String) {
        lock.lock()
        let stamp = logFormatter.string(from: Date())
        logs.append("\(stamp) \(message)")
        if logs.count > CaptureController.maxLogs {
            logs.removeFirst(logs.count - CaptureController.maxLogs)
        }
        lock.unlock()
        pushDiag(message)
    }

    /// 只进诊断缓冲，不进界面。
    private func pushDiag(_ message: String) {
        // Diagnostics 内部的 DateFormatter 非线程安全，这里串行化调用。
        diagLock.lock()
        Diagnostics.shared.log(message)
        diagLock.unlock()
    }

    // ── 后台保活 ─────────────────────────────────────────────────────────
    //
    // iOS 没有前台服务，锁屏/切后台后进程会被挂起，SOCKS5 与 WS 随之断开。
    // 这里用「后台音频」这个系统允许的场景维持进程存活：
    //   1. UIBackgroundModes=audio（Info.plist）+ AVAudioSession(.playback)
    //   2. 循环播放一段听不见的极低幅度音频，系统判定 App 正在放音 -> 不挂起
    //   3. 定时续期 beginBackgroundTask，补上音频被打断（来电等）的窗口
    //   4. 监听被打断/回前台/进后台，自动恢复播放

    private func beginKeepAlive() {
        registerKeepAliveObservers()
        startSilence()
        renewBackgroundTask()

        keepAliveTimer?.invalidate()
        keepAliveTimer = Timer.scheduledTimer(withTimeInterval: 25, repeats: true) { [weak self] _ in
            self?.resumeSilence()
            self?.renewBackgroundTask()
        }
    }

    private func registerKeepAliveObservers() {
        guard observers.isEmpty else { return }
        let center = NotificationCenter.default
        observers.append(center.addObserver(forName: AVAudioSession.interruptionNotification,
                                           object: AVAudioSession.sharedInstance(),
                                           queue: .main) { [weak self] note in
            self?.handleAudioInterruption(note)
        })
        observers.append(center.addObserver(forName: UIApplication.didEnterBackgroundNotification,
                                           object: nil,
                                           queue: .main) { [weak self] _ in
            self?.resumeSilence()
            self?.renewBackgroundTask()
        })
        observers.append(center.addObserver(forName: UIApplication.willEnterForegroundNotification,
                                           object: nil,
                                           queue: .main) { [weak self] _ in
            self?.resumeSilence()
        })
    }

    private func handleAudioInterruption(_ note: Notification) {
        guard let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
              let type = AVAudioSession.InterruptionType(rawValue: raw) else { return }
        if type == .ended {
            // 来电/闹钟等打断结束后，系统会把音频会话置为 inactive，必须重新激活。
            resumeSilence()
        }
    }

    private func startSilence() {
        guard silence == nil else { return }
        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)
        } catch {
            pushDiag("后台保活：音频会话激活失败 \(error.localizedDescription)")
        }
        guard let data = CaptureController.silentWave(),
              let player = try? AVAudioPlayer(data: data) else {
            pushDiag("后台保活：静音音频创建失败")
            return
        }
        player.numberOfLoops = -1
        player.volume = 0
        player.prepareToPlay()
        player.play()
        silence = player
        pushDiag("后台保活已开启")
    }

    /// 音频被系统打断后重新拉起；已经在播则什么都不做。
    private func resumeSilence() {
        guard let player = silence else { return }
        _ = try? AVAudioSession.sharedInstance().setActive(true)
        if !player.isPlaying {
            _ = player.play()
        }
    }

    private func renewBackgroundTask() {
        endBackgroundTaskOnly()
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "capture.keepalive") { [weak self] in
            self?.endBackgroundTaskOnly()
        }
    }

    private func endKeepAlive() {
        keepAliveTimer?.invalidate()
        keepAliveTimer = nil

        let center = NotificationCenter.default
        observers.forEach { center.removeObserver($0) }
        observers.removeAll()

        let hadPlayer = silence != nil
        silence?.stop()
        silence = nil
        if hadPlayer {
            _ = try? AVAudioSession.sharedInstance()
                .setActive(false, options: .notifyOthersOnDeactivation)
        }
        endBackgroundTaskOnly()
    }

    private func endBackgroundTaskOnly() {
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
        }
    }

    /// 1 秒 44.1kHz / 16bit / 单声道 WAV，采样值取最小幅度（1/32767），
    /// 人耳听不到，但系统会认为「正在播放音频」，从而保持后台运行。
    private static func silentWave() -> Data? {
        let sampleRate: UInt32 = 44100
        let frames: UInt32 = sampleRate        // 1 秒
        let dataSize = frames * 2              // 16bit 单声道
        var bytes: [UInt8] = []
        bytes.reserveCapacity(Int(44 + dataSize))

        func appendU16(_ value: UInt16) {
            bytes.append(UInt8(value & 0xff))
            bytes.append(UInt8((value >> 8) & 0xff))
        }

        func appendU32(_ value: UInt32) {
            bytes.append(UInt8(value & 0xff))
            bytes.append(UInt8((value >> 8) & 0xff))
            bytes.append(UInt8((value >> 16) & 0xff))
            bytes.append(UInt8((value >> 24) & 0xff))
        }

        bytes.append(contentsOf: Array("RIFF".utf8))
        appendU32(36 + dataSize)
        bytes.append(contentsOf: Array("WAVE".utf8))
        bytes.append(contentsOf: Array("fmt ".utf8))
        appendU32(16)
        appendU16(1)               // PCM
        appendU16(1)               // 单声道
        appendU32(sampleRate)
        appendU32(sampleRate * 2)  // byteRate = sampleRate * 1ch * 2B
        appendU16(2)               // blockAlign
        appendU16(16)              // 16 bit
        bytes.append(contentsOf: Array("data".utf8))
        appendU32(dataSize)

        // 最小幅度方波：避免全 0 被某些路径判定为静音丢帧。
        var sample: UInt16 = 1
        for _ in 0..<frames {
            let value: UInt16 = sample == 1 ? 1 : 0xFFFF
            appendU16(value)
            sample = sample == 1 ? 0 : 1
        }
        return Data(bytes)
    }
}
