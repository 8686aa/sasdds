import UIKit
import CoreImage

/// 二维码渲染：与安卓一致，输出 data:image/png;base64，页面直接当 <img src> 用。
enum QrRenderer {

    static func dataURL(_ text: String) -> String {
        guard !text.isEmpty,
              let message = text.data(using: .utf8),
              let filter = CIFilter(name: "CIQRCodeGenerator") else { return "" }
        filter.setValue(message, forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage else { return "" }

        let scale: CGFloat = 8
        let margin: CGFloat = 16
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let size = CGSize(width: scaled.extent.width + margin * 2,
                          height: scaled.extent.height + margin * 2)

        let renderer = UIGraphicsImageRenderer(size: size)
        let image = renderer.image { ctx in
            UIColor.white.setFill()
            ctx.fill(CGRect(origin: .zero, size: size))
            guard let cg = CIContext().createCGImage(scaled, from: scaled.extent) else { return }
            UIImage(cgImage: cg).draw(in: CGRect(x: margin, y: margin,
                                                 width: scaled.extent.width,
                                                 height: scaled.extent.height))
        }
        guard let png = image.pngData() else { return "" }
        return "data:image/png;base64," + png.base64EncodedString()
    }
}
