import Foundation

/// 诊断日志：与安卓 CaptureService 的 diag 环形缓冲等价，供「一键上报日志」取用。
final class Diagnostics {

    static let shared = Diagnostics()

    private let queue = DispatchQueue(label: "goredar.diag")
    private var buffer: [String] = []
    private let limit = 400
    private let formatter: DateFormatter

    private init() {
        formatter = DateFormatter()
        formatter.dateFormat = "MM-dd HH:mm:ss.SSS"
    }

    func log(_ text: String) {
        let line = "\(formatter.string(from: Date())) \(text)"
        NSLog("[GOReDar] %@", line)
        queue.async {
            self.buffer.append(line)
            if self.buffer.count > self.limit {
                self.buffer.removeFirst(self.buffer.count - self.limit)
            }
        }
    }

    var snapshot: [String] {
        queue.sync { buffer }
    }

    /// 落到沙盒 Documents/goredar-diag.log（密封后写，避免明文外泄）。
    func flushToDisk() {
        let lines = snapshot
        guard !lines.isEmpty else { return }
        let text = lines.joined(separator: "\n")
        let sealed = SecureStore.seal(Data(text.utf8))
        guard let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
        let url = dir.appendingPathComponent("goredar-diag.log")
        try? sealed.write(to: url, options: .atomic)
    }
}
