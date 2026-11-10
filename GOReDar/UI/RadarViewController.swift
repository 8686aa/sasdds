import UIKit
import WebKit

/// 内置雷达：全屏 WebView 打开 666 前端的分享页，左上角悬浮返回，方向跟随手机。
/// 对齐安卓 RadarActivity：沉浸式全屏（隐藏状态栏与 Home 指示条）、内容铺满整屏。
final class RadarViewController: UIViewController {

    static private(set) var isPresented = false

    private static let background = UIColor(red: 11 / 255, green: 18 / 255, blue: 32 / 255, alpha: 1)
    private static let buttonSize: CGFloat = 44

    private let urlString: String
    private var web: WKWebView!
    private let backButton = UIButton(type: .system)

    init(urlString: String) {
        self.urlString = urlString
        super.init(nibName: nil, bundle: nil)
        modalPresentationStyle = .fullScreen
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override var supportedInterfaceOrientations: UIInterfaceOrientationMask { .allButUpsideDown }
    override var prefersStatusBarHidden: Bool { true }
    override var prefersHomeIndicatorAutoHidden: Bool { true }

    override func viewDidLoad() {
        super.viewDidLoad()
        RadarViewController.isPresented = true
        view.backgroundColor = RadarViewController.background

        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        config.defaultWebpagePreferences.allowsContentJavaScript = true

        web = WKWebView(frame: view.bounds, configuration: config)
        web.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        web.backgroundColor = RadarViewController.background
        web.isOpaque = false
        web.scrollView.backgroundColor = RadarViewController.background
        // 安卓是 immersive 全屏，这里是关键差异：默认 .automatic 会按安全区给网页留黑边，
        // 导致雷达页上下出现条带、看起来没铺满。改成 .never 让内容真正顶到屏幕边缘。
        web.scrollView.contentInsetAdjustmentBehavior = .never
        web.scrollView.bounces = false
        web.scrollView.contentInset = .zero
        web.scrollView.scrollIndicatorInsets = .zero
        web.navigationDelegate = self
        // 安卓硬件返回键在可回退时走网页历史，iOS 用左缘滑动等价实现。
        web.allowsBackForwardNavigationGestures = true
        view.addSubview(web)

        setupBackButton()

        guard let url = URL(string: urlString) else {
            showErrorPage()
            return
        }
        web.load(URLRequest(url: url))
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        setNeedsStatusBarAppearanceUpdate()
        setNeedsUpdateOfHomeIndicatorAutoHidden()
        updateSupportedOrientations()
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        RadarViewController.isPresented = false
    }

    // ── 返回按钮（对齐 bg_float_back.xml：44dp 圆形、白色 95%、1dp #330EA5E9 描边） ──

    private func setupBackButton() {
        let tint = UIColor(red: 15 / 255, green: 23 / 255, blue: 42 / 255, alpha: 1)
        let symbol = UIImage.SymbolConfiguration(pointSize: 19, weight: .semibold)
        backButton.setImage(UIImage(systemName: "chevron.left", withConfiguration: symbol), for: .normal)
        backButton.tintColor = tint
        backButton.backgroundColor = UIColor(white: 1, alpha: 0.95)
        backButton.layer.cornerRadius = RadarViewController.buttonSize / 2
        backButton.layer.borderWidth = 1
        backButton.layer.borderColor = UIColor(red: 14 / 255, green: 165 / 255, blue: 233 / 255,
                                               alpha: 0.2).cgColor
        backButton.layer.shadowColor = UIColor.black.cgColor
        backButton.layer.shadowOpacity = 0.25
        backButton.layer.shadowRadius = 8
        backButton.layer.shadowOffset = CGSize(width: 0, height: 3)
        backButton.translatesAutoresizingMaskIntoConstraints = false
        backButton.addTarget(self, action: #selector(closeRadar), for: .touchUpInside)
        view.addSubview(backButton)

        let size = RadarViewController.buttonSize
        NSLayoutConstraint.activate([
            backButton.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor,
                                                constant: 16),
            backButton.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor,
                                            constant: 16),
            backButton.widthAnchor.constraint(equalToConstant: size),
            backButton.heightAnchor.constraint(equalToConstant: size),
        ])
    }

    // ── 退出 ─────────────────────────────────────────────────────────────

    /// 与安卓一致：点击悬浮返回直接关闭雷达页（网页历史由左缘滑动处理）。
    @objc private func closeRadar() {
        dismiss(animated: true) { [weak self] in
            self?.presentingViewController?.updateSupportedOrientations()
        }
    }

    private func showErrorPage() {
        let html = """
        <html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head>
        <body style="margin:0;background:#0B1220;color:#E2E8F0;font-family:sans-serif;
                     display:flex;align-items:center;justify-content:center;height:100vh">
          <div style="text-align:center;padding:24px">
            <div style="font-size:18px;font-weight:600;margin-bottom:8px">雷达加载失败</div>
            <div style="font-size:13px;color:#94A3B8;line-height:1.7">
              请确认电脑端前端(666 端口)已启动，<br>且手机与电脑在同一局域网。
            </div>
          </div>
        </body></html>
        """
        web.loadHTMLString(html, baseURL: nil)
    }
}

extension RadarViewController: WKNavigationDelegate {

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        showErrorPage()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        showErrorPage()
    }
}

private extension UIViewController {

    /// 让系统重新询问 supportedInterfaceOrientations（关闭雷达后回到竖屏）。
    func updateSupportedOrientations() {
        if #available(iOS 16.0, *) {
            setNeedsUpdateOfSupportedInterfaceOrientations()
        } else {
            UIDevice.current.setValue(UIInterfaceOrientation.portrait.rawValue, forKey: "orientation")
        }
    }
}
