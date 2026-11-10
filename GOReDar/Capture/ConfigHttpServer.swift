import Foundation
import Network

/**
 只读 HTTP 配置服务：给 sing-box 客户端扫码导入用。

 sing-box 不认 socks5:// 链接，只接受
 `sing-box://import-remote-profile?url=<配置地址>`，而配置地址必须能真正下载到 JSON，
 所以本机起一个极简 HTTP 服务，把当前 SOCKS5 地址吐成 sing-box 配置。
 固定 1083 端口，只处理 GET /singbox.json。
 */
final class ConfigHttpServer {

    static let port: UInt16 = 1083

    private let queue = DispatchQueue(label: "goredar.config-http")
    private var listener: NWListener?
    private let body: () -> String

    init(body: @escaping () -> String) {
        self.body = body
    }

    @discardableResult
    func start() -> Bool {
        stop()
        guard let port = NWEndpoint.Port(rawValue: Self.port) else { return false }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        do {
            let listener = try NWListener(using: params, on: port)
            listener.newConnectionHandler = { [weak self] connection in
                self?.handle(connection)
            }
            listener.start(queue: queue)
            self.listener = listener
            return true
        } catch {
            return false
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    private func handle(_ connection: NWConnection) {
        connection.start(queue: queue)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, _, _ in
            guard let self = self else {
                connection.cancel()
                return
            }
            // 只解析请求行：GET /singbox.json HTTP/1.1
            let request = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let path = request.split(separator: " ").dropFirst().first.map(String.init) ?? ""
            let ok = path == "/singbox.json" || path == "/singbox.json/"
            let text = ok ? self.body() : "not found"
            let payload = Data(text.utf8)
            let head = "HTTP/1.1 \(ok ? "200 OK" : "404 Not Found")\r\n"
                + "Content-Type: \(ok ? "application/json; charset=utf-8" : "text/plain; charset=utf-8")\r\n"
                + "Content-Length: \(payload.count)\r\n"
                + "Cache-Control: no-store\r\n"
                + "Connection: close\r\n\r\n"
            var response = Data(head.utf8)
            response.append(payload)
            connection.send(content: response, completion: .contentProcessed { _ in
                connection.cancel()
            })
        }
    }
}
