import Foundation
import Darwin

/// 一条 TCP 中继流的身份信息，供 TGCP MITM 绑定会话状态。
public final class TcpFlow {

    public let id: Int64
    public let clientIp: String
    public let clientPort: Int
    public let remoteIp: String
    public let remotePort: Int
    /// 中继钩子自定义的会话状态（安卓端为 `Any`，Swift 侧同为 `Any?`）。
    public var state: Any?

    public init(id: Int64,
                clientIp: String,
                clientPort: Int,
                remoteIp: String,
                remotePort: Int) {
        self.id = id
        self.clientIp = clientIp
        self.clientPort = clientPort
        self.remoteIp = remoteIp
        self.remotePort = remotePort
    }
}

/**
 TCP 双向写口。TGCP 在 state=1 时会缓冲上行帧，直到 server hello 到达才
 一起冲刷，此时处理下行的那一线程也要能写服务器，所以两边都给。

 对应安卓端的 OutputStream，这里直接持有 POSIX fd；读写互斥语义与
 `synchronized(lock)` 一致。
 */
public final class TcpSink {

    private let clientFd: Int32
    private let remoteFd: Int32
    private let lock = NSLock()

    public init(clientFd: Int32, remoteFd: Int32) {
        self.clientFd = clientFd
        self.remoteFd = remoteFd
    }

    public func toClient(_ data: [UInt8]) {
        if data.isEmpty { return }
        lock.lock()
        defer { lock.unlock() }
        _ = SocketIO.sendAll(clientFd, data)
    }

    public func toServer(_ data: [UInt8]) {
        if data.isEmpty { return }
        lock.lock()
        defer { lock.unlock() }
        _ = SocketIO.sendAll(remoteFd, data)
    }
}

/// UDP 双向发口；客户端地址由中继在发送时读取（可能随首包修正）。
public protocol UdpSink {
    func toServer(_ payload: [UInt8])
    func toClient(_ payload: [UInt8])
}

/**
 中继钩子。TCP/UDP 数据都先经过这里再转发，由钩子决定发什么、发不发：
   - TCP：TGCP 握手后改成明文，上下行都重加密；
   - UDP：新赛季接管时改写握手、重加密下行；
   - 钩子同时负责把「手机实际收发的载荷」上报给解码器。
 */
public protocol RelayHooks {
    func onTcpAttach(flow: TcpFlow, sink: TcpSink)
    func onTcpUp(flow: TcpFlow, data: [UInt8])
    func onTcpDown(flow: TcpFlow, data: [UInt8])
    func onTcpClosed(flow: TcpFlow)

    func onUdpUp(clientIp: String,
                 clientPort: Int,
                 remoteIp: String,
                 remotePort: Int,
                 payload: [UInt8],
                 sink: UdpSink)

    func onUdpDown(clientIp: String,
                   clientPort: Int,
                   remoteIp: String,
                   remotePort: Int,
                   payload: [UInt8],
                   sink: UdpSink)
}
