import UIKit
import WebKit

/// 纯 WebView 外壳：界面全部在 ui/index.html，这里只负责承载与原生桥。
final class MainViewController: UIViewController {

    private var web: WKWebView!
    private var ticker: Timer?
    private let bridge = NativeBridge()
    private let toastLabel = InsetLabel()

    override var preferredStatusBarStyle: UIStatusBarStyle { .darkContent }
    override var supportedInterfaceOrientations: UIInterfaceOrientationMask { .portrait }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .white

        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        config.userContentController.addUserScript(
            WKUserScript(source: NativeBridge.shimSource,
                         injectionTime: .atDocumentStart,
                         forMainFrameOnly: true)
        )

        web = WKWebView(frame: view.bounds, configuration: config)
        web.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        web.isOpaque = false
        web.backgroundColor = .white
        web.scrollView.backgroundColor = .white
        web.scrollView.contentInsetAdjustmentBehavior = .never
        web.uiDelegate = self
        web.navigationDelegate = self
        view.addSubview(web)

        bridge.host = self

        // XcodeGen 默认按文件加入资源，index.html 可能落在包根或 ui/ 下，两处都找。
        let entry = Bundle.main.url(forResource: "index", withExtension: "html", subdirectory: "ui")
            ?? Bundle.main.url(forResource: "index", withExtension: "html")
        guard let entry else {
            assertionFailure("缺少 ui/index.html 资源")
            return
        }
        web.loadFileURL(entry, allowingReadAccessTo: entry.deletingLastPathComponent())

        setupToast()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        ticker?.invalidate()
        ticker = Timer.scheduledTimer(withTimeInterval: 0.9, repeats: true) { [weak self] _ in
            self?.pushState()
        }
        RunLoop.main.add(ticker!, forMode: .common)
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        ticker?.invalidate()
        ticker = nil
    }

    deinit {
        ticker?.invalidate()
    }

    // MARK: - 与页面交互

    private func pushState() {
        evaluate("window.onState(\(CaptureController.shared.stateJson))")
    }

    func evaluate(_ script: String) {
        DispatchQueue.main.async { [weak self] in
            self?.web?.evaluateJavaScript(script, completionHandler: nil)
        }
    }

    func showToast(_ text: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.toastLabel.text = text
            self.toastLabel.alpha = 0
            UIView.animate(withDuration: 0.2) {
                self.toastLabel.alpha = 1
            } completion: { _ in
                UIView.animate(withDuration: 0.25, delay: 1.5, options: []) {
                    self.toastLabel.alpha = 0
                }
            }
        }
    }

    func openRadar(_ url: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            let radar = RadarViewController(urlString: url)
            radar.modalPresentationStyle = .fullScreen
            self.present(radar, animated: true)
        }
    }

    private func setupToast() {
        toastLabel.translatesAutoresizingMaskIntoConstraints = false
        toastLabel.backgroundColor = UIColor(white: 0.15, alpha: 0.92)
        toastLabel.textColor = .white
        toastLabel.font = UIFont.systemFont(ofSize: 13, weight: .medium)
        toastLabel.textAlignment = .center
        toastLabel.numberOfLines = 0
        toastLabel.layer.cornerRadius = 10
        toastLabel.layer.masksToBounds = true
        toastLabel.alpha = 0
        view.addSubview(toastLabel)
        NSLayoutConstraint.activate([
            toastLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            toastLabel.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -48),
            toastLabel.widthAnchor.constraint(lessThanOrEqualTo: view.widthAnchor, constant: -64),
        ])
    }
}

/// 带内边距的提示条，模拟安卓 Toast 的留白。
private final class InsetLabel: UILabel {

    private let insets = UIEdgeInsets(top: 8, left: 14, bottom: 8, right: 14)

    override func drawText(in rect: CGRect) {
        super.drawText(in: rect.inset(by: insets))
    }

    override var intrinsicContentSize: CGSize {
        let size = super.intrinsicContentSize
        return CGSize(width: size.width + insets.left + insets.right,
                      height: size.height + insets.top + insets.bottom)
    }
}

extension MainViewController: WKUIDelegate {

    /// JS 同步桥：window.native.xxx() 通过 prompt 调到这里，返回值直接回给 JS。
    func webView(_ webView: WKWebView,
                 runJavaScriptTextInputPanelWithPrompt prompt: String,
                 defaultText: String?,
                 initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping (String?) -> Void) {
        guard prompt.hasPrefix(NativeBridge.promptPrefix) else {
            completionHandler(nil)
            return
        }
        let payload = String(prompt.dropFirst(NativeBridge.promptPrefix.count))
        completionHandler(bridge.handle(payload))
    }
}

extension MainViewController: WKNavigationDelegate {

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        pushState()
        evaluate("window.onResume()")
    }
}
