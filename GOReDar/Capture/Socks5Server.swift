import Foundation
import Darwin

/// 线程安全的原子计数器，等价于安卓端的 AtomicLong。
public final class AtomicCounter {

    private let lock = NSLock()
    private var storage: Int64 = 0

    public init() {}

    public var value: Int64 {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    @discardableResult
    public func increment() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        storage += 1
        return storage
    }

    @discardableResult
    public func decrement() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        storage -= 1
        return storage
    }
}

/// POSIX socket 辅助层：地址解析、带超时的 connect、收发与超时设置。
enum SocketIO {

    /// IPv4 / IPv6 地址的原始字节表示（不含端口）。
    struct NodeAddress {
        let family: Int32
        let bytes: [UInt8]
        let host: String
    }

    typealias Endpoint = (host: String, port: Int, family: Int32, bytes: [UInt8])

    /// Darwin 上写已断开的 socket 会触发 SIGPIPE，必须显式关闭该信号。
    static func setNoSigPipe(_ fd: Int32) {
        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    static func setNoDelay(_ fd: Int32) {
        var one: Int32 = 1
        _ = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    /// 等价于 Java 的 `soTimeout`；`seconds == 0` 表示永不超时。
    static func setReadTimeout(_ fd: Int32, _ seconds: Int) {
        var tv = timeval(tv_sec: seconds, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    /// 阻塞写满整段数据；返回 false 表示连接已不可写。
    @discardableResult
    static func sendAll(_ fd: Int32, _ data: [UInt8]) -> Bool {
        if data.isEmpty { return true }
        if fd < 0 { return false }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { buf -> Int in
                guard let base = buf.baseAddress else { return -1 }
                return send(fd, base.advanced(by: offset), data.count - offset, 0)
            }
            if count < 0 {
                if errno == EINTR { continue }
                return false
            }
            if count == 0 { return false }
            offset += count
        }
        return true
    }

    // ── 地址转换 ─────────────────────────────────────────────────────────

    static func numericHost(_ family: Int32, _ bytes: [UInt8]) -> String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let capacity = socklen_t(buffer.count)
        let ok = bytes.withUnsafeBytes { src -> Bool in
            guard let base = src.baseAddress else { return false }
            return inet_ntop(family, base, &buffer, capacity) != nil
        }
        return ok ? String(cString: buffer) : ""
    }

    static func endpoint(from storage: sockaddr_storage) -> Endpoint? {
        var copy = storage
        switch Int32(copy.ss_family) {
        case AF_INET:
            return withUnsafePointer(to: &copy) { ptr -> Endpoint? in
                ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sa -> Endpoint? in
                    var raw = sa.pointee.sin_addr
                    let bytes = withUnsafeBytes(of: &raw) { Array($0) }
                    return (numericHost(AF_INET, bytes),
                            Int(UInt16(bigEndian: sa.pointee.sin_port)),
                            AF_INET,
                            bytes)
                }
            }
        case AF_INET6:
            return withUnsafePointer(to: &copy) { ptr -> Endpoint? in
                ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sa -> Endpoint? in
                    var raw = sa.pointee.sin6_addr
                    let bytes = withUnsafeBytes(of: &raw) { Array($0) }
                    return (numericHost(AF_INET6, bytes),
                            Int(UInt16(bigEndian: sa.pointee.sin6_port)),
                            AF_INET6,
                            bytes)
                }
            }
        default:
            return nil
        }
    }

    /// 读取 fd 的本端（peer=false）或对端（peer=true）地址。
    static func endpoint(_ fd: Int32, peer: Bool) -> Endpoint? {
        if fd < 0 { return nil }
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &storage) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                peer ? getpeername(fd, sa, &length) : getsockname(fd, sa, &length)
            }
        }
        guard result == 0 else { return nil }
        return endpoint(from: storage)
    }

    /// DNS 解析；优先 IPv4，与 Java 默认的 IPv4 优先策略一致。
    static func resolve(host: String) -> NodeAddress? {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let head = result else { return nil }
        defer { freeaddrinfo(head) }

        var ipv4: NodeAddress?
        var ipv6: NodeAddress?
        var cursor: UnsafeMutablePointer<addrinfo>? = head
        while let info = cursor {
            let family = info.pointee.ai_family
            if family == AF_INET, ipv4 == nil {
                let sa = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var raw = sa.sin_addr
                let bytes = withUnsafeBytes(of: &raw) { Array($0) }
                ipv4 = NodeAddress(family: AF_INET, bytes: bytes, host: numericHost(AF_INET, bytes))
            } else if family == AF_INET6, ipv6 == nil {
                let sa = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var raw = sa.sin6_addr
                let bytes = withUnsafeBytes(of: &raw) { Array($0) }
                ipv6 = NodeAddress(family: AF_INET6, bytes: bytes, host: numericHost(AF_INET6, bytes))
            }
            cursor = info.pointee.ai_next
        }
        return ipv4 ?? ipv6
    }

    // ── 连接 / 绑定 ──────────────────────────────────────────────────────

    /// 等价于 `Socket.connect(addr, 10000)`：非阻塞 connect + poll 超时。
    static func connect(_ fd: Int32, to node: NodeAddress, port: Int, timeout: Int) -> Bool {
        let originalFlags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, originalFlags | O_NONBLOCK)

        var result: Int32 = -1
        if node.family == AF_INET {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = in_port_t(UInt16(truncatingIfNeeded: port)).bigEndian
            node.bytes.withUnsafeBytes { src in
                withUnsafeMutableBytes(of: &address.sin_addr) { dst in
                    if let base = src.baseAddress {
                        dst.copyBytes(from: UnsafeRawBufferPointer(start: base, count: min(src.count, dst.count)))
                    }
                }
            }
            result = withUnsafePointer(to: &address) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        } else if node.family == AF_INET6 {
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            address.sin6_family = sa_family_t(AF_INET6)
            address.sin6_port = in_port_t(UInt16(truncatingIfNeeded: port)).bigEndian
            node.bytes.withUnsafeBytes { src in
                withUnsafeMutableBytes(of: &address.sin6_addr) { dst in
                    if let base = src.baseAddress {
                        dst.copyBytes(from: UnsafeRawBufferPointer(start: base, count: min(src.count, dst.count)))
                    }
                }
            }
            result = withUnsafePointer(to: &address) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        } else {
            _ = fcntl(fd, F_SETFL, originalFlags)
            return false
        }

        if result != 0 {
            guard errno == EINPROGRESS else {
                _ = fcntl(fd, F_SETFL, originalFlags)
                return false
            }
            var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&descriptor, 1, Int32(timeout * 1000))
            guard ready > 0 else {
                _ = fcntl(fd, F_SETFL, originalFlags)
                return false
            }
            var socketError: Int32 = 0
            var errorLength = socklen_t(MemoryLayout<Int32>.size)
            let got = getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength)
            guard got == 0, socketError == 0 else {
                _ = fcntl(fd, F_SETFL, originalFlags)
                return false
            }
        }
        _ = fcntl(fd, F_SETFL, originalFlags)
        return true
    }

    static func bind(_ fd: Int32, to node: NodeAddress, port: Int) -> Bool {
        if node.family == AF_INET {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = in_port_t(UInt16(truncatingIfNeeded: port)).bigEndian
            node.bytes.withUnsafeBytes { src in
                withUnsafeMutableBytes(of: &address.sin_addr) { dst in
                    if let base = src.baseAddress {
                        dst.copyBytes(from: UnsafeRawBufferPointer(start: base, count: min(src.count, dst.count)))
                    }
                }
            }
            return withUnsafePointer(to: &address) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    Darwin.bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            } == 0
        }
        var address = sockaddr_in6()
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = in_port_t(UInt16(truncatingIfNeeded: port)).bigEndian
        node.bytes.withUnsafeBytes { src in
            withUnsafeMutableBytes(of: &address.sin6_addr) { dst in
                if let base = src.baseAddress {
                    dst.copyBytes(from: UnsafeRawBufferPointer(start: base, count: min(src.count, dst.count)))
                }
            }
        }
        return withUnsafePointer(to: &address) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        } == 0
    }

    // ── UDP 收发 ─────────────────────────────────────────────────────────

    static func sendDatagram(_ fd: Int32, _ payload: [UInt8], to node: NodeAddress, port: Int) -> Bool {
        if fd < 0 || payload.isEmpty { return false }
        var result: Int = -1
        if node.family == AF_INET {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = in_port_t(UInt16(truncatingIfNeeded: port)).bigEndian
            node.bytes.withUnsafeBytes { src in
                withUnsafeMutableBytes(of: &address.sin_addr) { dst in
                    if let base = src.baseAddress {
                        dst.copyBytes(from: UnsafeRawBufferPointer(start: base, count: min(src.count, dst.count)))
                    }
                }
            }
            result = withUnsafePointer(to: &address) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    payload.withUnsafeBytes { buf in
                        sendto(fd, buf.baseAddress, payload.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
        } else {
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            address.sin6_family = sa_family_t(AF_INET6)
            address.sin6_port = in_port_t(UInt16(truncatingIfNeeded: port)).bigEndian
            node.bytes.withUnsafeBytes { src in
                withUnsafeMutableBytes(of: &address.sin6_addr) { dst in
                    if let base = src.baseAddress {
                        dst.copyBytes(from: UnsafeRawBufferPointer(start: base, count: min(src.count, dst.count)))
                    }
                }
            }
            result = withUnsafePointer(to: &address) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    payload.withUnsafeBytes { buf in
                        sendto(fd, buf.baseAddress, payload.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
            }
        }
        return result >= 0
    }

    /// 阻塞接收一个 UDP 报文；返回值为字节数，-1 表示失败（errno 由调用方判断）。
    static func recvFrom(_ fd: Int32, buffer: inout [UInt8], address: inout sockaddr_storage) -> Int {
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let capacity = buffer.count
        return withUnsafeMutablePointer(to: &address) { ptr -> Int in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                buffer.withUnsafeMutableBytes { buf -> Int in
                    recvfrom(fd, buf.baseAddress, capacity, 0, sa, &length)
                }
            }
        }
    }
}

/// 可重复关闭的 socket 句柄，等价于 Java Socket 的 close 幂等语义。
private final class SocketHandle {

    private let lock = NSLock()
    private var handle: Int32

    init(_ fd: Int32) {
        handle = fd
    }

    var raw: Int32 {
        lock.lock()
        defer { lock.unlock() }
        return handle
    }

    func close() {
        lock.lock()
        let fd = handle
        handle = -1
        lock.unlock()
        if fd >= 0 {
            shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
        }
    }
}

private enum SocketError: Error, CustomStringConvertible {
    case read(Int32)

    var description: String {
        switch self {
        case .read(let code):
            return String(cString: strerror(code))
        }
    }
}

/**
 最小 SOCKS5 服务端：RFC1928 CONNECT + RFC1928 UDP ASSOCIATE（无认证）。

 游戏设备经 tun2socks 把整机流量导到这里，TCP/UDP 都先过 RelayHooks：
   - TCP：TGCP hello 在此做双密钥 MITM，之后上下行都是明文，可用于提取 128B bank。
   - UDP：新赛季握手在此做 X25519 主动改包，之后下行用会话 key 解密、用手机
          的 mobile_key 重新加密；上报给解码器的仍是「转换前的原始载荷」。

 安卓端的「每连接一个线程」在 iOS 上由独立 DispatchQueue 复现：accept 一条专用队列，
 每条连接一条并发队列条目，连接内部的上行/下行各占一条队列，用 DispatchGroup 等待两者结束。
 */
public final class Socks5Server {

    public let port: Int

    private let hooks: RelayHooks

    private let stateLock = NSLock()
    private var _running = false
    private var serverFd: Int32 = -1

    private let setLock = NSLock()
    private var tcpHandles: [SocketHandle] = []
    private var udpHandles: [SocketHandle] = []

    private let flowIds = AtomicCounter()
    /// 仅用于诊断：打印前若干个 UDP 数据包来源，确认客户端判定是否正确。
    private let udpDebug = AtomicCounter()

    public let activeTcp = AtomicCounter()
    public let activeUdp = AtomicCounter()
    public let totalTcp = AtomicCounter()
    public let totalUdp = AtomicCounter()
    public let refused = AtomicCounter()

    private let acceptQueue = DispatchQueue(label: "socks-accept")
    private let connQueue = DispatchQueue(label: "socks-conn", attributes: .concurrent)

    public init(port: Int, hooks: RelayHooks) {
        self.port = port
        self.hooks = hooks
    }

    private var running: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _running
    }

    // ── 生命周期 ─────────────────────────────────────────────────────────

    public func start() {
        stateLock.lock()
        if _running {
            stateLock.unlock()
            return
        }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            stateLock.unlock()
            Diagnostics.shared.log("接入服务启动失败: socket 创建失败 \(String(cString: strerror(errno)))")
            return
        }
        SocketIO.setNoSigPipe(fd)
        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))

        let any = SocketIO.NodeAddress(family: AF_INET, bytes: [0, 0, 0, 0], host: "0.0.0.0")
        let bound = SocketIO.bind(fd, to: any, port: port) && listen(fd, 64) == 0
        guard bound else {
            stateLock.unlock()
            Diagnostics.shared.log("接入服务启动失败: 0.0.0.0:\(port) 不可用（\(String(cString: strerror(errno)))）")
            Darwin.close(fd)
            return
        }
        serverFd = fd
        _running = true
        stateLock.unlock()

        acceptQueue.async { [weak self] in
            self?.acceptLoop(fd)
        }
        Diagnostics.shared.log("接入服务已就绪 0.0.0.0:\(port)")
    }

    public func stop() {
        stateLock.lock()
        _running = false
        let fd = serverFd
        serverFd = -1
        stateLock.unlock()

        if fd >= 0 {
            shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
        }

        setLock.lock()
        let tcp = tcpHandles
        tcpHandles.removeAll()
        let udp = udpHandles
        udpHandles.removeAll()
        setLock.unlock()

        for handle in tcp { handle.close() }
        for handle in udp { handle.close() }
        Diagnostics.shared.log("接入服务已停止")
    }

    private func addTcp(_ handle: SocketHandle) {
        setLock.lock()
        tcpHandles.append(handle)
        setLock.unlock()
    }

    private func removeTcp(_ handle: SocketHandle) {
        setLock.lock()
        if let index = tcpHandles.firstIndex(where: { $0 === handle }) {
            tcpHandles.remove(at: index)
        }
        setLock.unlock()
    }

    private func addUdp(_ handle: SocketHandle) {
        setLock.lock()
        udpHandles.append(handle)
        setLock.unlock()
    }

    private func removeUdp(_ handle: SocketHandle) {
        setLock.lock()
        if let index = udpHandles.firstIndex(where: { $0 === handle }) {
            udpHandles.remove(at: index)
        }
        setLock.unlock()
    }

    // ── 接入循环 ─────────────────────────────────────────────────────────

    private func acceptLoop(_ listenFd: Int32) {
        while running {
            let clientFd = accept(listenFd, nil, nil)
            if clientFd < 0 {
                if errno == EINTR { continue }
                if running {
                    Diagnostics.shared.log("accept 失败: \(String(cString: strerror(errno)))")
                }
                break
            }
            SocketIO.setNoSigPipe(clientFd)
            let client = SocketHandle(clientFd)
            connQueue.async { [weak self] in
                self?.handle(client)
            }
        }
    }

    private func handle(_ client: SocketHandle) {
        addTcp(client)
        defer {
            removeTcp(client)
            client.close()
        }
        let clientFd = client.raw

        do {
            SocketIO.setNoDelay(clientFd)
            SocketIO.setReadTimeout(clientFd, 30)

            // greeting: VER NMETHODS METHODS...
            guard let greeting = try readExactly(clientFd, 2) else { return }
            guard greeting[0] == 5 else {
                Diagnostics.shared.log("未知接入请求（协议不匹配）")
                return
            }
            guard let methods = try readExactly(clientFd, Int(greeting[1])) else { return }
            guard methods.contains(0) else {
                _ = SocketIO.sendAll(clientFd, [5, 0xff])
                return
            }
            _ = SocketIO.sendAll(clientFd, [5, 0])

            guard let head = try readExactly(clientFd, 4) else { return }
            guard head[0] == 5, head[2] == 0 else { return }
            let command = Int(head[1])
            guard let target = try readTarget(clientFd, atyp: Int(head[3])) else { return }

            // 握手阶段用 30s 超时防呆；隧道建立后可能是长时间空闲的长连接，必须取消超时
            SocketIO.setReadTimeout(clientFd, 0)

            switch command {
            case 1:
                connect(client, clientFd, target)
            case 3:
                associate(client, clientFd, target)
            default:
                refused.increment()
                reply(clientFd, code: 0x07, address: localIPv4(clientFd), port: 0)
            }
        } catch {
            if running {
                Diagnostics.shared.log("连接处理失败: \(error)")
            }
        }
    }

    // ── CONNECT ─────────────────────────────────────────────────────────

    private func connect(_ client: SocketHandle, _ clientFd: Int32, _ target: Target) {
        let remoteFd = socket(target.address.family, SOCK_STREAM, 0)
        guard remoteFd >= 0 else {
            refused.increment()
            reply(clientFd, code: 0x05, address: localIPv4(clientFd), port: 0)
            return
        }
        let remote = SocketHandle(remoteFd)
        SocketIO.setNoSigPipe(remoteFd)
        SocketIO.setNoDelay(remoteFd)

        guard SocketIO.connect(remoteFd, to: target.address, port: target.port, timeout: 10) else {
            refused.increment()
            remote.close()
            reply(clientFd, code: 0x05, address: localIPv4(clientFd), port: 0)
            return
        }

        addTcp(remote)
        defer {
            removeTcp(remote)
            remote.close()
        }
        totalTcp.increment()
        activeTcp.increment()
        defer { activeTcp.decrement() }

        let local = SocketIO.endpoint(remoteFd, peer: false)
        reply(clientFd, code: 0x00, address: localIPv4(remoteFd), port: local?.port ?? 0)

        let clientPeer = SocketIO.endpoint(clientFd, peer: true)
        let remotePeer = SocketIO.endpoint(remoteFd, peer: true)
        let flow = TcpFlow(id: flowIds.increment(),
                           clientIp: clientPeer?.host ?? "",
                           clientPort: clientPeer?.port ?? 0,
                           remoteIp: remotePeer?.host ?? "",
                           remotePort: remotePeer?.port ?? 0)

        let remoteName = "\(target.host):\(target.port)"
        let sink = TcpSink(clientFd: clientFd, remoteFd: remoteFd)
        hooks.onTcpAttach(flow: flow, sink: sink)

        let group = DispatchGroup()
        let upQueue = DispatchQueue(label: "socks-up")
        let downQueue = DispatchQueue(label: "socks-down")

        // 上行：客户端 -> 服务器（TGCP 解密后重新加密）
        group.enter()
        upQueue.async { [self] in
            defer { group.leave() }
            var buffer = [UInt8](repeating: 0, count: 16384)
            let capacity = buffer.count
            var failed = false
            while running {
                let count = recv(clientFd, &buffer, capacity, 0)
                if count < 0 {
                    let code = errno
                    if code == EINTR { continue }
                    // 等价于安卓端吞掉 SocketTimeoutException
                    if code == EAGAIN || code == EWOULDBLOCK { break }
                    failed = true
                    if running {
                        Diagnostics.shared.log("TCP 上行中断 \(remoteName): \(String(cString: strerror(code)))")
                    }
                    break
                }
                if count == 0 { break }
                hooks.onTcpUp(flow: flow, data: Array(buffer[0..<count]))
            }
            if !failed {
                shutdown(remoteFd, SHUT_WR)
            }
        }

        // 下行：服务器 -> 客户端
        group.enter()
        downQueue.async { [self] in
            defer { group.leave() }
            var buffer = [UInt8](repeating: 0, count: 16384)
            let capacity = buffer.count
            var failed = false
            while running {
                let count = recv(remoteFd, &buffer, capacity, 0)
                if count < 0 {
                    let code = errno
                    if code == EINTR { continue }
                    // 等价于安卓端吞掉 SocketTimeoutException
                    if code == EAGAIN || code == EWOULDBLOCK { break }
                    failed = true
                    if running {
                        Diagnostics.shared.log("TCP 下行中断 \(remoteName): \(String(cString: strerror(code)))")
                    }
                    break
                }
                if count == 0 { break }
                hooks.onTcpDown(flow: flow, data: Array(buffer[0..<count]))
            }
            if !failed {
                shutdown(clientFd, SHUT_WR)
            }
        }

        group.wait()
        hooks.onTcpClosed(flow: flow)
    }

    // ── UDP ASSOCIATE ───────────────────────────────────────────────────

    private func associate(_ client: SocketHandle, _ clientFd: Int32, _ target: Target) {
        let udpFd = socket(AF_INET, SOCK_DGRAM, 0)
        let any = SocketIO.NodeAddress(family: AF_INET, bytes: [0, 0, 0, 0], host: "0.0.0.0")
        guard udpFd >= 0, SocketIO.bind(udpFd, to: any, port: 0) else {
            if udpFd >= 0 { Darwin.close(udpFd) }
            reply(clientFd, code: 0x01, address: localIPv4(clientFd), port: 0)
            return
        }
        SocketIO.setNoSigPipe(udpFd)
        let udp = SocketHandle(udpFd)
        addUdp(udp)
        defer {
            udp.close()
            removeUdp(udp)
            activeUdp.decrement()
        }
        totalUdp.increment()
        activeUdp.increment()

        let relayPort = SocketIO.endpoint(udpFd, peer: false)?.port ?? 0
        reply(clientFd, code: 0x00, address: localIPv4(clientFd), port: relayPort)
        let peer = SocketIO.endpoint(clientFd, peer: true)
        Diagnostics.shared.log("UDP ASSOCIATE 来自 \(peer?.host ?? ""):\(peer?.port ?? 0)，中继端口 \(relayPort)")

        // 常见客户端在 UDP ASSOCIATE 里把地址填 0.0.0.0:0，此时用 TCP 对端地址兜底。
        let requested = target.address
        let isAny = requested.bytes.allSatisfy { $0 == 0 }
        var clientAddress = requested
        if isAny, let peer = peer {
            clientAddress = SocketIO.NodeAddress(family: peer.family, bytes: peer.bytes, host: peer.host)
        }
        let clientPort = target.port != 0 ? target.port : (peer?.port ?? 0)
        let session = UdpSession(socket: udp, clientAddress: clientAddress, clientPort: clientPort)

        // 控制 TCP 关闭或读到 EOF 即结束关联。
        let control = DispatchQueue(label: "socks-udp-control")
        control.async { [self] in
            var buffer = [UInt8](repeating: 0, count: 256)
            let capacity = buffer.count
            while running {
                let count = recv(clientFd, &buffer, capacity, 0)
                if count < 0 {
                    if errno == EINTR { continue }
                    break
                }
                if count == 0 { break }
            }
            session.close()
        }

        udpLoop(session)

        session.close()
        client.close()
    }

    private final class UdpSession {

        let socket: SocketHandle

        private let lock = NSLock()
        private var _clientAddress: SocketIO.NodeAddress
        private var _clientPort: Int
        private var _closed = false
        /// 远端地址 -> 是否已确认是「服务器回包」，避免把无关 UDP 当成客户端。
        private var _peers: Set<String> = []

        init(socket: SocketHandle, clientAddress: SocketIO.NodeAddress, clientPort: Int) {
            self.socket = socket
            self._clientAddress = clientAddress
            self._clientPort = clientPort
        }

        var closed: Bool {
            lock.lock()
            defer { lock.unlock() }
            return _closed
        }

        var client: (address: SocketIO.NodeAddress, port: Int) {
            lock.lock()
            defer { lock.unlock() }
            return (_clientAddress, _clientPort)
        }

        func updateClient(_ address: SocketIO.NodeAddress, _ port: Int) {
            lock.lock()
            defer { lock.unlock() }
            _clientAddress = address
            _clientPort = port
        }

        func hasPeer(_ key: String) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return _peers.contains(key)
        }

        func addPeer(_ key: String) {
            lock.lock()
            defer { lock.unlock() }
            _peers.insert(key)
        }

        func close() {
            lock.lock()
            _closed = true
            lock.unlock()
            socket.close()
        }

        func send(_ payload: [UInt8], to address: SocketIO.NodeAddress, port: Int) {
            lock.lock()
            defer { lock.unlock() }
            _ = SocketIO.sendDatagram(socket.raw, payload, to: address, port: port)
        }
    }

    private func udpLoop(_ session: UdpSession) {
        let fd = session.socket.raw
        SocketIO.setReadTimeout(fd, 1)
        var buffer = [UInt8](repeating: 0, count: 65535)

        while running && !session.closed {
            var storage = sockaddr_storage()
            let count = SocketIO.recvFrom(fd, buffer: &buffer, address: &storage)
            if count < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK { continue }
                break
            }
            guard let source = SocketIO.endpoint(from: storage) else { continue }
            let payload = Array(buffer[0..<count])
            let sourceKey = "\(source.host):\(source.port)"
            let client = session.client

            let sameClientAddress = client.address.family == source.family
                && client.address.bytes == source.bytes
            let isClient: Bool
            if sameClientAddress && source.port == client.port {
                isClient = true
            } else if session.hasPeer(sourceKey) {
                isClient = false
            } else if looksLikeSocksUdp(payload) {
                isClient = true
            } else {
                isClient = false
            }

            if udpDebug.value < 8 {
                udpDebug.increment()
                Diagnostics.shared.log("[udp-dbg] 来源 \(source.host):\(source.port) 客户端=\(isClient) " +
                    "长度=\(payload.count) 头部=\(CryptoUtil.hex(Array(payload.prefix(8))))")
            }

            if isClient {
                if !sameClientAddress || source.port != client.port {
                    session.updateClient(SocketIO.NodeAddress(family: source.family,
                                                              bytes: source.bytes,
                                                              host: source.host),
                                         source.port)
                }
                handleUdpUp(session, payload)
            } else {
                session.addPeer(sourceKey)
                handleUdpDown(session,
                              SocketIO.NodeAddress(family: source.family, bytes: source.bytes, host: source.host),
                              source.port,
                              payload)
            }
        }
    }

    private func handleUdpUp(_ session: UdpSession, _ data: [UInt8]) {
        if data.count < 4 { return }
        if data[0] != 0 || data[1] != 0 { return } // 不支持非零 RSV
        let fragment = data[2]
        if fragment != 0 { return } // 不支持分片
        guard let parsed = readUdpAddress(data, offset: 3) else { return }
        let remote = parsed.address
        let offset = parsed.offset
        if data.count < offset + 2 { return }
        let remotePort = (Int(data[offset]) << 8) | Int(data[offset + 1])
        let payload = Array(data[(offset + 2)...])
        if payload.isEmpty { return }

        let client = session.client
        hooks.onUdpUp(clientIp: client.address.host,
                      clientPort: client.port,
                      remoteIp: remote.host,
                      remotePort: remotePort,
                      payload: payload,
                      sink: SessionSink(server: self, session: session, remote: remote, remotePort: remotePort))
    }

    private func handleUdpDown(_ session: UdpSession,
                               _ remote: SocketIO.NodeAddress,
                               _ remotePort: Int,
                               _ payload: [UInt8]) {
        let client = session.client
        hooks.onUdpDown(clientIp: client.address.host,
                        clientPort: client.port,
                        remoteIp: remote.host,
                        remotePort: remotePort,
                        payload: payload,
                        sink: SessionSink(server: self, session: session, remote: remote, remotePort: remotePort))
    }

    private final class SessionSink: UdpSink {

        private let server: Socks5Server
        private let session: UdpSession
        private let remote: SocketIO.NodeAddress
        private let remotePort: Int

        init(server: Socks5Server,
             session: UdpSession,
             remote: SocketIO.NodeAddress,
             remotePort: Int) {
            self.server = server
            self.session = session
            self.remote = remote
            self.remotePort = remotePort
        }

        func toServer(_ payload: [UInt8]) {
            if payload.isEmpty { return }
            session.send(payload, to: remote, port: remotePort)
        }

        func toClient(_ payload: [UInt8]) {
            if payload.isEmpty { return }
            let frame = server.buildUdpResponse(remote, remotePort, payload)
            let client = session.client
            session.send(frame, to: client.address, port: client.port)
        }
    }

    // ── 编解码 ──────────────────────────────────────────────────────────

    private struct Target {
        let host: String
        let address: SocketIO.NodeAddress
        let port: Int
    }

    private func readTarget(_ fd: Int32, atyp: Int) throws -> Target? {
        let address: SocketIO.NodeAddress
        switch atyp {
        case 1:
            guard let raw = try readExactly(fd, 4) else { return nil }
            address = SocketIO.NodeAddress(family: AF_INET,
                                           bytes: raw,
                                           host: SocketIO.numericHost(AF_INET, raw))
        case 3:
            guard let lengthByte = try readExactly(fd, 1) else { return nil }
            let length = Int(lengthByte[0])
            guard let raw = try readExactly(fd, length) else { return nil }
            let host = String(decoding: raw, as: UTF8.self)
            guard let resolved = SocketIO.resolve(host: host) else { return nil }
            address = resolved
        case 4:
            guard let raw = try readExactly(fd, 16) else { return nil }
            address = SocketIO.NodeAddress(family: AF_INET6,
                                           bytes: raw,
                                           host: SocketIO.numericHost(AF_INET6, raw))
        default:
            return nil
        }
        guard let portBytes = try readExactly(fd, 2) else { return nil }
        let port = (Int(portBytes[0]) << 8) | Int(portBytes[1])
        return Target(host: address.host, address: address, port: port)
    }

    /// ATYP + ADDR + PORT -> (地址, 下一个字段偏移)。
    private func readUdpAddress(_ data: [UInt8],
                                offset: Int) -> (address: SocketIO.NodeAddress, offset: Int)? {
        if data.count <= offset { return nil }
        switch Int(data[offset]) {
        case 1:
            if data.count < offset + 7 { return nil }
            let raw = Array(data[(offset + 1)..<(offset + 5)])
            let address = SocketIO.NodeAddress(family: AF_INET,
                                               bytes: raw,
                                               host: SocketIO.numericHost(AF_INET, raw))
            return (address, offset + 5)
        case 3:
            if data.count < offset + 2 { return nil }
            let length = Int(data[offset + 1])
            if data.count < offset + 2 + length { return nil }
            let host = String(decoding: data[(offset + 2)..<(offset + 2 + length)], as: UTF8.self)
            guard let address = SocketIO.resolve(host: host) else { return nil }
            return (address, offset + 2 + length)
        case 4:
            if data.count < offset + 17 { return nil }
            let raw = Array(data[(offset + 1)..<(offset + 17)])
            let address = SocketIO.NodeAddress(family: AF_INET6,
                                               bytes: raw,
                                               host: SocketIO.numericHost(AF_INET6, raw))
            return (address, offset + 17)
        default:
            return nil
        }
    }

    private func buildUdpResponse(_ remote: SocketIO.NodeAddress,
                                  _ remotePort: Int,
                                  _ payload: [UInt8]) -> [UInt8] {
        if remote.family == AF_INET, remote.bytes.count == 4 {
            var out = [UInt8](repeating: 0, count: 3 + 1 + 4 + 2 + payload.count)
            out[3] = 1
            out.replaceSubrange(4..<8, with: remote.bytes)
            out[8] = UInt8((remotePort >> 8) & 0xff)
            out[9] = UInt8(remotePort & 0xff)
            out.replaceSubrange(10..<(10 + payload.count), with: payload)
            return out
        }
        // 非 IPv4 回包：用域名形式塞回 4 段十进制，保证内网 tun2socks 可解析。
        let text = Array(remote.host.utf8)
        var out = [UInt8](repeating: 0, count: 3 + 1 + 1 + text.count + 2 + payload.count)
        out[3] = 3
        out[4] = UInt8(truncatingIfNeeded: text.count)
        out.replaceSubrange(5..<(5 + text.count), with: text)
        let at = 5 + text.count
        out[at] = UInt8((remotePort >> 8) & 0xff)
        out[at + 1] = UInt8(remotePort & 0xff)
        out.replaceSubrange((at + 2)..<(at + 2 + payload.count), with: payload)
        return out
    }

    private func reply(_ fd: Int32, code: Int, address: [UInt8]?, port: Int) {
        var out = [UInt8](repeating: 0, count: 10)
        out[0] = 5
        out[1] = UInt8(truncatingIfNeeded: code)
        out[3] = 1
        let ip = (address?.count == 4) ? address! : [0, 0, 0, 0]
        out.replaceSubrange(4..<8, with: ip)
        out[8] = UInt8((port >> 8) & 0xff)
        out[9] = UInt8(port & 0xff)
        _ = SocketIO.sendAll(fd, out)
    }

    private func readExactly(_ fd: Int32, _ size: Int) throws -> [UInt8]? {
        if size <= 0 { return [] }
        var out = [UInt8](repeating: 0, count: size)
        var offset = 0
        while offset < size {
            let count = out.withUnsafeMutableBytes { buf -> Int in
                guard let base = buf.baseAddress else { return -1 }
                return recv(fd, base.advanced(by: offset), size - offset, 0)
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw SocketError.read(errno)
            }
            if count == 0 { return nil }
            offset += count
        }
        return out
    }

    private func looksLikeSocksUdp(_ data: [UInt8]) -> Bool {
        if data.count < 4 { return false }
        if data[0] != 0 || data[1] != 0 || data[2] != 0 { return false }
        guard let end = readUdpAddressEndpoint(data, offset: 3) else { return false }
        return data.count > end + 2
    }

    private func readUdpAddressEndpoint(_ data: [UInt8], offset: Int) -> Int? {
        if data.count <= offset { return nil }
        switch Int(data[offset]) {
        case 1:
            return data.count >= offset + 5 ? offset + 5 : nil
        case 3:
            if data.count < offset + 2 { return nil }
            let length = Int(data[offset + 1])
            return data.count >= offset + 2 + length ? offset + 2 + length : nil
        case 4:
            return data.count >= offset + 17 ? offset + 17 : nil
        default:
            return nil
        }
    }

    /// 本端 IPv4 地址；非 IPv4 时回退 0.0.0.0（与安卓端 reply 的兜底一致）。
    private func localIPv4(_ fd: Int32) -> [UInt8]? {
        guard let endpoint = SocketIO.endpoint(fd, peer: false),
              endpoint.family == AF_INET,
              endpoint.bytes.count == 4 else { return nil }
        return endpoint.bytes
    }
}
