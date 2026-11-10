import Foundation
import Darwin

/// 与安卓端 WsConnection.kt 对齐的 WebSocket 错误。
enum WsConnectionError: Error, CustomStringConvertible {
    case illegal(String)

    var description: String {
        switch self {
        case .illegal(let message):
            return message
        }
    }
}

/**
 极简 WebSocket 客户端：只支持 ws:// 文本帧、ping/pong、close。

 安卓端用阻塞 Socket 手写握手与分帧，这里同样基于 POSIX fd 实现，保证
 「读取超时 = 断开重连」的判定与安卓一致（URLSessionWebSocketTask 没有读超时语义）。
 服务端只接受 ws://，wss:// 在安卓侧也只是剥掉前缀后按明文连接。
 */
final class WsConnection {

    private let host: String
    private let port: Int
    private let connectTimeoutMs: Int
    private let readTimeoutMs: Int

    private let stateLock = NSLock()
    private var fd: Int32 = -1
    private var closed = false
    private let writeLock = NSLock()

    init(host: String, port: Int, connectTimeoutMs: Int = 8000, readTimeoutMs: Int = 30000) {
        self.host = host
        self.port = port
        self.connectTimeoutMs = connectTimeoutMs
        self.readTimeoutMs = readTimeoutMs
    }

    // ── 连接 / 握手 ──────────────────────────────────────────────────────

    func connect() throws {
        guard let node = SocketIO.resolve(host: host) else {
            throw WsConnectionError.illegal("无法解析节点地址 \(host)")
        }
        let handle = socket(node.family, SOCK_STREAM, 0)
        guard handle >= 0 else {
            throw WsConnectionError.illegal("socket 创建失败: \(String(cString: strerror(errno)))")
        }
        SocketIO.setNoSigPipe(handle)
        SocketIO.setNoDelay(handle)
        SocketIO.setReadTimeout(handle, max(1, readTimeoutMs / 1000))

        guard SocketIO.connect(handle,
                               to: node,
                               port: port,
                               timeout: max(1, connectTimeoutMs / 1000)) else {
            Darwin.close(handle)
            throw WsConnectionError.illegal("连接 \(host):\(port) 失败")
        }

        stateLock.lock()
        fd = handle
        closed = false
        stateLock.unlock()

        do {
            try handshake()
        } catch {
            close()
            throw error
        }
    }

    private func handshake() throws {
        let key = CryptoUtil.b64(CryptoUtil.randomBytes(16))
        var request = ""
        request += "GET / HTTP/1.1\r\n"
        request += "Host: \(host):\(port)\r\n"
        request += "Upgrade: websocket\r\n"
        request += "Connection: Upgrade\r\n"
        request += "Sec-WebSocket-Key: \(key)\r\n"
        request += "Sec-WebSocket-Version: 13\r\n"
        request += "\r\n"
        try writeBytes(Array(request.utf8))

        let header = try readHttpHeader()
        let statusLine = header.components(separatedBy: "\r\n").first ?? ""
        if !statusLine.contains(" 101") {
            throw WsConnectionError.illegal("WebSocket 握手失败: \(statusLine)")
        }
    }

    private func readHttpHeader() throws -> String {
        var buffer: [UInt8] = []
        var last4: UInt32 = 0
        while true {
            let value = try readByte()
            buffer.append(UInt8(truncatingIfNeeded: value))
            last4 = (last4 << 8) | UInt32(truncatingIfNeeded: value)
            if last4 == 0x0d0a0d0a {
                return String(decoding: buffer, as: UTF8.self)
            }
            if buffer.count > 16 * 1024 {
                throw WsConnectionError.illegal("握手响应头过大")
            }
        }
    }

    // ── 发送 ─────────────────────────────────────────────────────────────

    func sendText(_ text: String) throws {
        try sendFrame(0x1, Array(text.utf8))
    }

    func sendPing() throws {
        try sendFrame(0x9, [])
    }

    private func sendFrame(_ opcode: Int, _ payload: [UInt8]) throws {
        writeLock.lock()
        defer { writeLock.unlock() }

        let handle = descriptor()
        guard handle >= 0 else {
            throw WsConnectionError.illegal("连接未建立")
        }

        var out: [UInt8] = [UInt8(0x80 | opcode)]
        if payload.count < 126 {
            // 客户端发出的帧必须置 MASK 位，否则服务端按协议错误直接断开。
            out.append(UInt8(0x80 | payload.count))
        } else if payload.count <= 0xFFFF {
            out.append(UInt8(0x80 | 126))
            out.append(UInt8((payload.count >> 8) & 0xff))
            out.append(UInt8(payload.count & 0xff))
        } else {
            out.append(UInt8(0x80 | 127))
            let length = UInt64(payload.count)
            for index in stride(from: 7, through: 0, by: -1) {
                out.append(UInt8(truncatingIfNeeded: length >> (UInt64(index) * 8)))
            }
        }

        let mask = CryptoUtil.randomBytes(4)
        out.append(contentsOf: mask)
        for index in payload.indices {
            out.append(payload[index] ^ mask[index & 3])
        }
        guard SocketIO.sendAll(handle, out) else {
            throw WsConnectionError.illegal("发送失败: \(String(cString: strerror(errno)))")
        }
    }

    private func writeBytes(_ bytes: [UInt8]) throws {
        let handle = descriptor()
        guard handle >= 0 else {
            throw WsConnectionError.illegal("连接未建立")
        }
        guard SocketIO.sendAll(handle, bytes) else {
            throw WsConnectionError.illegal("发送失败: \(String(cString: strerror(errno)))")
        }
    }

    // ── 接收 ─────────────────────────────────────────────────────────────

    /// 阻塞读取下一条文本消息。控制帧就地处理；连接关闭返回 nil。
    func readMessage() throws -> String? {
        var assembled: [UInt8]?
        while true {
            let first = try readByte()
            let fin = (first & 0x80) != 0
            let opcode = first & 0x0f
            let second = try readByte()
            let masked = (second & 0x80) != 0
            var length = UInt64(second & 0x7f)
            if length == 126 {
                let high = try readByte()
                let low = try readByte()
                length = UInt64((high << 8) | low)
            } else if length == 127 {
                length = 0
                for _ in 0..<8 {
                    length = (length << 8) | UInt64(try readByte())
                }
            }
            if length > 8 * 1024 * 1024 {
                throw WsConnectionError.illegal("WebSocket 帧过大: \(length)")
            }

            var mask: [UInt8]?
            if masked {
                mask = try readFully(4)
            }
            var payload = try readFully(Int(length))
            if let mask = mask {
                for index in payload.indices {
                    payload[index] = payload[index] ^ mask[index & 3]
                }
            }

            switch opcode {
            case 0x9:
                try sendFrame(0xA, payload)
            case 0xA:
                break
            case 0x8:
                return nil
            case 0x0:
                let previous = assembled ?? []
                assembled = previous + payload
                if fin {
                    return String(decoding: assembled ?? [], as: UTF8.self)
                }
            case 0x1, 0x2:
                if fin {
                    return String(decoding: payload, as: UTF8.self)
                }
                assembled = payload
            default:
                break
            }
        }
    }

    private func readByte() throws -> Int {
        let handle = descriptor()
        guard handle >= 0 else {
            throw WsConnectionError.illegal("连接已关闭")
        }
        var byte: UInt8 = 0
        while true {
            let count = recv(handle, &byte, 1, 0)
            if count < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    throw WsConnectionError.illegal("读取超时")
                }
                throw WsConnectionError.illegal("读取失败: \(String(cString: strerror(errno)))")
            }
            if count == 0 {
                throw WsConnectionError.illegal("连接已关闭")
            }
            return Int(byte)
        }
    }

    private func readFully(_ size: Int) throws -> [UInt8] {
        if size <= 0 { return [] }
        let handle = descriptor()
        guard handle >= 0 else {
            throw WsConnectionError.illegal("连接已关闭")
        }
        var out = [UInt8](repeating: 0, count: size)
        var offset = 0
        while offset < size {
            let count = out.withUnsafeMutableBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return -1 }
                return recv(handle, base.advanced(by: offset), size - offset, 0)
            }
            if count < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    throw WsConnectionError.illegal("读取超时")
                }
                throw WsConnectionError.illegal("读取失败: \(String(cString: strerror(errno)))")
            }
            if count == 0 {
                throw WsConnectionError.illegal("连接已关闭")
            }
            offset += count
        }
        return out
    }

    // ── 关闭 ─────────────────────────────────────────────────────────────

    func close() {
        stateLock.lock()
        if closed {
            stateLock.unlock()
            return
        }
        closed = true
        stateLock.unlock()

        // 先按协议发 close 帧，再断开底层 fd。
        _ = try? sendFrame(0x8, [])

        stateLock.lock()
        let handle = fd
        fd = -1
        stateLock.unlock()

        if handle >= 0 {
            shutdown(handle, SHUT_RDWR)
            Darwin.close(handle)
        }
    }

    private func descriptor() -> Int32 {
        stateLock.lock()
        defer { stateLock.unlock() }
        return fd
    }
}
