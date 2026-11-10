import Foundation

/// 门户 666 接口封装（与安卓端完全一致的四个接口）。
enum PortalApi {

    /// 节点地址里去掉 ws:// wss:// 与端口，只留主机。
    static func host(of node: String) -> String {
        var text = node.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("ws://") { text.removeFirst(5) }
        if text.hasPrefix("wss://") { text.removeFirst(6) }
        if let colon = text.lastIndex(of: ":") {
            text = String(text[text.startIndex..<colon])
        }
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func session(_ timeout: TimeInterval) -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        config.waitsForConnectivity = false
        return URLSession(configuration: config)
    }

    private static func send(_ request: URLRequest,
                             timeout: TimeInterval,
                             completion: @escaping (Int, Data?, String) -> Void) {
        let task = session(timeout).dataTask(with: request) { data, response, error in
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            // code == 0 表示连 HTTP 响应都没拿到（连不上 / 超时 / 被系统拒绝），
            // 只有 0 分不出是哪一种，把系统给的描述一起带出去。
            completion(code, data, error?.localizedDescription ?? "")
        }
        task.resume()
    }

    /// code == 0 时的提示：把系统错误附上，否则只剩一个无信息量的 0。
    private static func connectHint(_ host: String, _ code: Int,
                                    _ detail: String, _ fallback: String) -> String {
        guard code == 0, !detail.isEmpty else { return fallback }
        return "无法连接 \(host):666 · \(detail)"
    }

    /// 启动检查：公告 / 最新版本 / 全局开关。
    static func appInfo(node: String, completion: @escaping (String) -> Void) {
        let host = host(of: node)
        guard !host.isEmpty, let url = URL(string: "http://\(host):666/api/app/info") else {
            completion("")
            return
        }
        send(URLRequest(url: url), timeout: 6) { _, data, _ in
            completion(data.flatMap { String(data: $0, encoding: .utf8) } ?? "")
        }
    }

    /// 接入登录：服务端校验归属 / 到期 / 禁用 / 全局开关。
    static func login(node: String, key: String,
                      completion: @escaping (Bool, String, String) -> Void) {
        let host = host(of: node)
        guard !host.isEmpty, let url = URL(string: "http://\(host):666/api/app/login") else {
            completion(false, "请填写接入节点", "")
            return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["key": key], options: [])
        send(request, timeout: 8) { code, data, detail in
            let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let json = (try? JSONSerialization.jsonObject(with: Data(body.utf8))) as? [String: Any] ?? [:]
            if (200...299).contains(code), json["ok"] as? Bool == true {
                let user = (json["user"] as? [String: Any])?["username"] as? String ?? ""
                completion(true, user, body)
            } else {
                // 服务端给了 error 就用它；拿不到响应时用系统错误说明原因。
                let message = json["error"] as? String
                    ?? Self.connectHint(host, code, detail, "登录失败 (\(code))")
                completion(false, message, body)
            }
        }
    }

    /// 按房间 Key 反查雷达分享链接。
    static func shareURL(node: String, key: String,
                         completion: @escaping (String, String) -> Void) {
        let host = host(of: node)
        var error = "无法连接雷达前端 \(host):666"
        guard !host.isEmpty,
              let url = URL(string: "http://\(host):666/api/share/by_key?key=\(key)") else {
            completion("", error)
            return
        }
        send(URLRequest(url: url), timeout: 6) { code, data, detail in
            let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let json = (try? JSONSerialization.jsonObject(with: Data(body.utf8))) as? [String: Any] ?? [:]
            if let shared = json["url"] as? String, !shared.isEmpty {
                completion(shared, "")
                return
            }
            error = json["error"] as? String
                ?? Self.connectHint(host, code, detail, error)
            completion("", error)
        }
    }

    /// 一键上报：日志与诊断数据打到 /api/debug/report。
    static func report(node: String, key: String, payload: Data,
                       completion: @escaping (Bool, String, Int) -> Void) {
        let host = host(of: node)
        guard !host.isEmpty,
              let url = URL(string: "http://\(host):666/api/debug/report?key=\(key)") else {
            completion(false, "请先完成节点接入配置", payload.count)
            return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = payload
        send(request, timeout: 8) { code, data, detail in
            let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let json = (try? JSONSerialization.jsonObject(with: Data(body.utf8))) as? [String: Any] ?? [:]
            if (200...299).contains(code), json["ok"] as? Bool == true {
                let logs = json["logs"] as? Int ?? 0
                let size = json["size"] as? Int ?? payload.count
                completion(true, Self.sizeText(logs: logs, size: size), logs)
            } else {
                let message = json["error"] as? String
                    ?? Self.connectHint(host, code, detail, "上报失败 (\(code))")
                completion(false, message, 0)
            }
        }
    }

    static func sizeText(logs: Int, size: Int) -> String {
        let text = size < 1024 ? "\(size) B" : String(format: "%.1f KB", Double(size) / 1024.0)
        return "已上报 \(logs) 条日志 · \(text)"
    }
}
