import UIKit
import WebKit

/// 内置雷达：全屏 WebView 打开 666 前端的分享页，左上角悬浮返回，方向跟随手机。
final class RadarViewController: UIViewController {

    static private(set) var isPresented = false

    private let urlString: String
    private var web: WKWebView!
    private let backButton = UILabel()

    init(urlString: String) {
        self.urlString = urlString
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override var supportedInterfaceOrientations: UIInterfaceOrientationMask { .allButUpsideDown }
    override var prefersStatusBarHidden: Bool { true }
    override var prefersHomeIndicatorAutoHidden: Bool { true }

    override func viewDidLoad() {
        super.viewDidLoad()
        RadarViewController.isPresented = true
        view.backgroundColor = UIColor(red: 11 / 255, green: 18 / 255, blue: 32 / 255, alpha: 1)

        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        web = WKWebView(frame: view.bounds, configuration: config)
        web.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        web.backgroundColor = view.backgroundColor
        web.isOpaque = false
        web.scrollView.backgroundColor = view.backgroundColor
        web.navigationDelegate = self
        view.addSubview(web)

        backButton.text = "‹"
        backButton.textAlignment = .center
        backButton.font = UIFont.systemFont(ofSize: 26, weight: .semibold)
        backButton.textColor = UIColor(red: 15 / 255, green: 23 / 255, blue: 42 / 255, alpha: 1)
        backButton.backgroundColor = .white
        backButton.layer.cornerRadius = 22
        backButton.layer.shadowColor = UIColor.black.cgColor
        backButton.layer.shadowOpacity = 0.25
        backButton.layer.shadowRadius = 8
        backButton.layer.shadowOffset = CGSize(width: 0, height: 3)
        backButton.isUserInteractionEnabled = true
        backButton.translatesAutoresizingMaskIntoConstraints = false
        backButton.addGestureRecognizer(UITapGestureRecognizer(target: self, action: #selector(goBack)))
        view.addSubview(backButton)
        NSLayoutConstraint.activate([
            backButton.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 16),
            backButton.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
            backButton.widthAnchor.constraint(equalToConstant: 44),
            backButton.heightAnchor.constraint(equalToConstant: 44),
        ])

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
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        RadarViewController.isPresented = false
    }

    @objc private func goBack() {
        if web.canGoBack {
            web.goBack()
        } else {
            dismiss(animated: true)
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
