import UIKit

/// 与安卓 MainActivity 里的 JS 接口一一对应。
///
/// WKWebView 没有同步 JS 桥，这里用 `window.prompt` 做同步通道：页面里注入的
/// shim 把 `window.native.xxx()` 打包成 prompt，`WKUIDelegate` 同步回值。
/// 异步结果仍按安卓的方式回调 `window.onXxx(...)`。
final class NativeBridge {

    static let promptPrefix = "__GOREDAR__"

    static let shimSource = """
    (function () {
      function call(method, args) {
        try {
          var reply = prompt('\(NativeBridge.promptPrefix)' + JSON.stringify({ m: method, a: args || [] }));
          return reply === null || reply === undefined ? '' : String(reply);
        } catch (e) {
          return '';
        }
      }
      window.native = {
        state:        function () { return call('state'); },
        config:       function () { return call('config'); },
        save:         function (node, key, port) { call('save', [node || '', key || '', port || 0]); },
        startCapture: function (node, port) { return call('startCapture', [node || '', port || 0]); },
        stopCapture:  function () { call('stopCapture'); },
        copyText:     function (text) { call('copyText', [text || '']); },
        qr:           function (text) { return call('qr', [text || '']); },
        openRadar:    function () { call('openRadar'); },
        shareRadar:   function () { call('shareRadar'); },
        toast:        function (text) { call('toast', [text || '']); },
        appInfo:      function (node) { call('appInfo', [node || '']); },
        appLogin:     function (node, key, port) { call('appLogin', [node || '', key || '', port || 0]); },
        logout:       function () { call('logout'); },
        openUpdate:   function (url) { call('openUpdate', [url || '']); },
        reportLogs:   function () { call('reportLogs'); }
      };
    })();
    """

    weak var host: MainViewController?

    private(set) var loggedIn = false
    private(set) var user = ""

    private let nodeKey = "node"
    private let apiKeyKey = "api_key"
    private let portKey = "port"
    private let userKey = "user"

    // MARK: - 分发

    func handle(_ payload: String) -> String {
        guard let data = payload.data(using: .utf8),
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let method = json["m"] as? String else { return "" }
        let args = json["a"] as? [Any] ?? []

        switch method {
        case "state":
            return CaptureController.shared.stateJson
        case "config":
            return configJson()
        case "save":
            return saveConfig(args)
        case "startCapture":
            return startCapture(args)
        case "stopCapture":
            CaptureController.shared.stop()
            return ""
        case "copyText":
            UIPasteboard.general.string = string(args, 0)
            return ""
        case "qr":
            return QrRenderer.dataURL(string(args, 0))
        case "toast":
            host?.showToast(string(args, 0))
            return ""
        case "openRadar":
            resolveShare(open: true)
            return ""
        case "shareRadar":
            resolveShare(open: false)
            return ""
        case "appInfo":
            fetchAppInfo(string(args, 0))
            return ""
        case "appLogin":
            login(node: string(args, 0), key: string(args, 1), port: int(args, 2))
            return ""
        case "logout":
            logout()
            return ""
        case "openUpdate":
            openUpdate(string(args, 0))
            return ""
        case "reportLogs":
            reportLogs()
            return ""
        default:
            return ""
        }
    }

    // MARK: - 配置

    private func configJson() -> String {
        let node = SecureStore.get(nodeKey)
        let key = SecureStore.get(apiKeyKey)
        let port = Int(SecureStore.get(portKey)) ?? 1080
        let info = Bundle.main.infoDictionary ?? [:]
        let payload: [String: Any] = [
            "node": node,
            "port": port,
            "user": userOrStored(),
            "hasKey": key.count == 32,
            "ip": CaptureController.shared.listenAddress,
            "version": info["CFBundleShortVersionString"] as? String ?? "",
            "versionCode": info["CFBundleVersion"] as? String ?? "",
        ]
        return jsonString(payload)
    }

    private func userOrStored() -> String {
        if !user.isEmpty { return user }
        return SecureStore.get(userKey)
    }

    private func saveConfig(_ args: [Any]) -> String {
        let node = string(args, 0).trimmingCharacters(in: .whitespacesAndNewlines)
        let key = string(args, 1).trimmingCharacters(in: .whitespacesAndNewlines)
        let port = int(args, 2)
        if !node.isEmpty { SecureStore.put(nodeKey, node) }
        if key.count == 32 { SecureStore.put(apiKeyKey, key) }
        if port >= 1 && port <= 65535 { SecureStore.put(portKey, String(port)) }
        return ""
    }

    private func startCapture(_ args: [Any]) -> String {
        let node = string(args, 0).trimmingCharacters(in: .whitespacesAndNewlines)
        let port = int(args, 1)
        let key = SecureStore.get(apiKeyKey)
        guard !node.isEmpty else { return "请先登录接入账号" }
        guard key.count == 32 else { return "接入凭证无效，请重新登录" }
        guard port >= 1 && port <= 65535 else { return "端口需在 1-65535 之间" }
        SecureStore.put(nodeKey, node)
        SecureStore.put(portKey, String(port))
        return CaptureController.shared.start(node: node, port: UInt16(port))
    }

    // MARK: - 账号

    private func fetchAppInfo(_ node: String) {
        let target = node.isEmpty ? SecureStore.get(nodeKey) : node
        guard !target.isEmpty else { return }
        PortalApi.appInfo(node: target) { [weak self] raw in
            guard let self, !raw.isEmpty else { return }
            self.host?.evaluate("window.onAppInfo(\(jsLiteral(raw)))")
        }
    }

    private func login(node: String, key: String, port: Int) {
        let targetNode = node.trimmingCharacters(in: .whitespacesAndNewlines)
        let stored = SecureStore.get(apiKeyKey)
        let credential = key.count == 32 ? key : stored
        guard !targetNode.isEmpty else { returnLogin(false, "请填写接入节点", ""); return }
        guard credential.count == 32 else { returnLogin(false, "接入 Key 需为 32 位", ""); return }

        PortalApi.login(node: targetNode, key: credential) { [weak self] ok, message, body in
            guard let self else { return }
            if ok {
                SecureStore.put(self.nodeKey, targetNode)
                SecureStore.put(self.apiKeyKey, credential)
                if port >= 1 && port <= 65535 { SecureStore.put(self.portKey, String(port)) }
                SecureStore.put(self.userKey, message)
                self.user = message
                self.loggedIn = true
            }
            self.returnLogin(ok, message, body)
        }
    }

    private func returnLogin(_ ok: Bool, _ message: String, _ body: String) {
        host?.evaluate("window.onLogin(\(ok ? "true" : "false"), \(jsLiteral(message)), \(jsLiteral(body)))")
    }

    private func logout() {
        CaptureController.shared.stop()
        SecureStore.remove(apiKeyKey)
        SecureStore.remove(userKey)
        SecureStore.remove(nodeKey)
        user = ""
        loggedIn = false
        host?.evaluate("window.onLogout()")
    }

    // MARK: - 雷达

    private func resolveShare(open: Bool) {
        let node = SecureStore.get(nodeKey)
        let key = SecureStore.get(apiKeyKey)
        guard !node.isEmpty, key.count == 32 else {
            if open { host?.evaluate("window.onRadar(false, \(jsLiteral("请先登录接入账号")))") }
            else { host?.evaluate("window.onShare('', \(jsLiteral("请先登录接入账号")))") }
            return
        }
        PortalApi.shareURL(node: node, key: key) { [weak self] url, error in
            guard let self else { return }
            if open {
                if !url.isEmpty {
                    self.host?.openRadar(url)
                    self.host?.evaluate("window.onRadar(true, \(jsLiteral(""))) ")
                } else {
                    self.host?.evaluate("window.onRadar(false, \(jsLiteral(error)))")
                }
            } else {
                self.host?.evaluate("window.onShare(\(jsLiteral(url)), \(jsLiteral(error)))")
            }
        }
    }

    private func openUpdate(_ url: String) {
        guard let target = URL(string: url), !url.isEmpty else { return }
        DispatchQueue.main.async {
            UIApplication.shared.open(target, options: [:], completionHandler: nil)
        }
    }

    // MARK: - 诊断上报

    private func reportLogs() {
        let node = SecureStore.get(nodeKey)
        let key = SecureStore.get(apiKeyKey)
        guard !node.isEmpty, key.count == 32 else {
            host?.evaluate("window.onReport(false, \(jsLiteral("请先完成接入配置")))")
            return
        }
        let info = Bundle.main.infoDictionary ?? [:]
        let payload: [String: Any] = [
            "platform": "ios",
            "version": info["CFBundleShortVersionString"] as? String ?? "",
            "versionCode": info["CFBundleVersion"] as? String ?? "",
            "device": UIDevice.current.model,
            "system": "\(UIDevice.current.systemName) \(UIDevice.current.systemVersion)",
            "time": ISO8601DateFormatter().string(from: Date()),
            "state": (try? JSONSerialization.jsonObject(with: Data(CaptureController.shared.stateJson.utf8))) ?? [:],
            "logs": CaptureController.shared.diagnostics,
        ]
        guard let body = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
            host?.evaluate("window.onReport(false, \(jsLiteral("上报数据生成失败")))")
            return
        }
        PortalApi.report(node: node, key: key, payload: body) { [weak self] ok, message, _ in
            self?.host?.evaluate("window.onReport(\(ok ? "true" : "false"), \(jsLiteral(message)))")
        }
    }

    // MARK: - 参数工具

    private func string(_ args: [Any], _ index: Int) -> String {
        guard index < args.count else { return "" }
        if let text = args[index] as? String { return text }
        if let number = args[index] as? NSNumber { return number.stringValue }
        return ""
    }

    private func int(_ args: [Any], _ index: Int) -> Int {
        guard index < args.count else { return 0 }
        if let number = args[index] as? NSNumber { return number.intValue }
        if let text = args[index] as? String { return Int(text) ?? 0 }
        return 0
    }

    private func jsonString(_ object: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: []),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    private func jsLiteral(_ text: String) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: [text], options: []),
              var json = String(data: data, encoding: .utf8) else { return "\"\"" }
        json.removeFirst()
        json.removeLast()
        return json
    }
}
