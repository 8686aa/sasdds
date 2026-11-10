import Foundation

/// 与安卓端 `IllegalArgumentException` 等价的错误。
public enum TgcpFailure: Error, CustomStringConvertible {
    case illegal(String)

    public var description: String {
        switch self {
        case .illegal(let message):
            return message
        }
    }
}

/// 无符号大整数（小端 32 位分肢）。只覆盖 TGCP DH 需要的正数运算，
/// 用来替代安卓端的 `java.math.BigInteger`（iOS 无内置任意精度整数）。
public enum TgcpBig {

    public struct Number: Equatable {

        /// 小端 32 位分肢；零值用空数组表示，最高分肢恒非零。
        fileprivate var limbs: [UInt32]

        fileprivate init(limbs: [UInt32]) {
            var value = limbs
            while let last = value.last, last == 0 {
                value.removeLast()
            }
            self.limbs = value
        }

        public init(_ value: UInt32) {
            self.init(limbs: [value])
        }

        /// 大端无符号字节，等价于 `BigInteger(1, bytes)`。
        public init(bytes: [UInt8]) {
            var limbs = [UInt32](repeating: 0, count: (bytes.count + 3) / 4)
            if !limbs.isEmpty {
                var index = 0
                for byte in bytes.reversed() {
                    limbs[index >> 2] |= UInt32(byte) << ((index & 3) * 8)
                    index += 1
                }
            }
            self.init(limbs: limbs)
        }

        public var isZero: Bool {
            limbs.isEmpty
        }

        public var bitLength: Int {
            guard let top = limbs.last else { return 0 }
            return limbs.count * 32 - top.leadingZeroBitCount
        }

        /// 对应 `BigInteger.toByteArray()` 去掉前导 0：最短无符号大端，零值返回 [0]。
        public func bigEndianBytes() -> [UInt8] {
            guard !limbs.isEmpty else { return [0] }
            var out = [UInt8]()
            out.reserveCapacity(limbs.count * 4)
            for limb in limbs.reversed() {
                out.append(UInt8(truncatingIfNeeded: limb >> 24))
                out.append(UInt8(truncatingIfNeeded: limb >> 16))
                out.append(UInt8(truncatingIfNeeded: limb >> 8))
                out.append(UInt8(truncatingIfNeeded: limb))
            }
            var start = 0
            while start < out.count - 1 && out[start] == 0 {
                start += 1
            }
            return Array(out[start...])
        }
    }

    // ── 正数运算 ─────────────────────────────────────────────────────────

    fileprivate static func compare(_ a: Number, _ b: Number) -> Int {
        if a.limbs.count != b.limbs.count {
            return a.limbs.count < b.limbs.count ? -1 : 1
        }
        var index = a.limbs.count - 1
        while index >= 0 {
            if a.limbs[index] != b.limbs[index] {
                return a.limbs[index] < b.limbs[index] ? -1 : 1
            }
            index -= 1
        }
        return 0
    }

    /// 要求 a >= b。
    fileprivate static func subtract(_ a: Number, _ b: Number) -> Number {
        var out = a.limbs
        var borrow: Int64 = 0
        for index in 0..<out.count {
            let sub = index < b.limbs.count ? Int64(b.limbs[index]) : 0
            var value = Int64(out[index]) - sub - borrow
            if value < 0 {
                value += 0x1_0000_0000
                borrow = 1
            } else {
                borrow = 0
            }
            out[index] = UInt32(value)
        }
        return Number(limbs: out)
    }

    fileprivate static func multiply(_ a: Number, _ b: Number) -> Number {
        if a.limbs.isEmpty || b.limbs.isEmpty {
            return Number(0)
        }
        var out = [UInt32](repeating: 0, count: a.limbs.count + b.limbs.count + 1)
        for i in 0..<a.limbs.count {
            var carry: UInt64 = 0
            let left = UInt64(a.limbs[i])
            for j in 0..<b.limbs.count {
                let current = UInt64(out[i + j]) + left * UInt64(b.limbs[j]) + carry
                out[i + j] = UInt32(truncatingIfNeeded: current)
                carry = current >> 32
            }
            var index = i + b.limbs.count
            while carry > 0 {
                let current = UInt64(out[index]) + carry
                out[index] = UInt32(truncatingIfNeeded: current)
                carry = current >> 32
                index += 1
            }
        }
        return Number(limbs: out)
    }

    /// 逐位长除取模：商丢弃，只保留余数（被除数约 1024 位，模 512 位）。
    fileprivate static func modulo(_ value: Number, _ modulus: Number) -> Number {
        let m = modulus.limbs
        let n = m.count
        if n == 0 || value.limbs.isEmpty {
            return Number(0)
        }
        var rem = [UInt32](repeating: 0, count: n + 1)
        var bit = value.bitLength - 1
        while bit >= 0 {
            var carry: UInt32 = 0
            for index in 0..<rem.count {
                let next = rem[index] >> 31
                rem[index] = (rem[index] << 1) | carry
                carry = next
            }
            if (value.limbs[bit >> 5] >> (bit & 31)) & 1 == 1 {
                rem[0] |= 1
            }
            var greaterOrEqual = rem[n] != 0
            if !greaterOrEqual {
                greaterOrEqual = true
                var index = n - 1
                while index >= 0 {
                    if rem[index] != m[index] {
                        greaterOrEqual = rem[index] > m[index]
                        break
                    }
                    index -= 1
                }
            }
            if greaterOrEqual {
                var borrow: Int64 = 0
                for index in 0..<n {
                    var current = Int64(rem[index]) - Int64(m[index]) - borrow
                    if current < 0 {
                        current += 0x1_0000_0000
                        borrow = 1
                    } else {
                        borrow = 0
                    }
                    rem[index] = UInt32(current)
                }
                rem[n] = 0
            }
            bit -= 1
        }
        return Number(limbs: rem)
    }

    /// 对应 `BigInteger.modPow`（指数与模均为正数）。
    public static func modPow(_ base: Number, _ exponent: Number, _ modulus: Number) -> Number {
        if modulus.isZero {
            return Number(0)
        }
        var result = Number(1)
        let reduced = modulo(base, modulus)
        var bit = exponent.bitLength - 1
        while bit >= 0 {
            result = modulo(multiply(result, result), modulus)
            if (exponent.limbs[bit >> 5] >> (bit & 31)) & 1 == 1 {
                result = modulo(multiply(result, reduced), modulus)
            }
            bit -= 1
        }
        return result
    }
}

/**
 TGCP 双密钥 MITM（与安卓 `TgcpProtocol` / 参考实现 TgcpProtocol.cs 对齐）。

 代理在 client hello 里把手机公钥换成自己的 Y，在 server hello 里把服务器公钥换成自己的 X：
   `_clientKey = MD5(DH(手机公钥, x))` 上行用它解、下行用它加密
   `_serverKey = MD5(DH(服务器公钥, y))` 下行用它解、上行用它加密
 */
public enum TgcpProtocol {

    public static let MAGIC: [UInt8] = [0x33, 0x66, 0x00, 0x0B, 0x00, 0x0C]

    public static let IV: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

    public static let PRIME = TgcpBig.Number(bytes: (try? CryptoUtil.unhex(PRIME_HEX)) ?? [])

    private static let PRIME_HEX =
        "97981e0aade0de72e29cd2789193562547bad2591fb7e59c523923dddecebcca" +
        "e49bdcd4b8ec39022b0bd95d4af8fd3cd600919393255c1084c2fd5abb2fede3"

    private static let MAX_BODY = 16 * 1024 * 1024
    private static let MAX_HEADER = 65536

    private static let bankToken = try! NSRegularExpression(
        pattern: "(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{171}=)(?![A-Za-z0-9+/=])"
    )

    // ── 帧头 ─────────────────────────────────────────────────────────────

    public static func lengths(_ data: [UInt8]) throws -> (header: Int, body: Int) {
        guard data.count >= 21 else { throw TgcpFailure.illegal("TGCP 帧头过短") }
        guard Array(data[0..<6]) == MAGIC else { throw TgcpFailure.illegal("TGCP 帧头错误") }
        let h = readU32(data, 13)
        let b = readU32(data, 17)
        guard h >= 21 && h <= MAX_HEADER && b <= MAX_BODY else {
            throw TgcpFailure.illegal("TGCP 帧长度超出范围")
        }
        return (h, b)
    }

    /// 0 = 数据还不够，1 = 不是 TGCP，2 = 确认是 TGCP 的 client hello。
    public static func sniff(_ prefix: [UInt8]) -> Int {
        let n = min(prefix.count, MAGIC.count)
        if Array(prefix[0..<n]) != Array(MAGIC[0..<n]) {
            return 1
        }
        if prefix.count < 21 {
            return 0
        }
        do {
            let (h, b) = try lengths(prefix)
            if readU16(prefix, 6) != 0x1001 || h < 88 {
                return 1
            }
            if prefix.count >= 24 && Array(prefix[21..<24]) != [3, 0, 64] {
                return 1
            }
            let end = h + b
            if end < h {
                // 安卓端在 copyOfRange 里抛异常，同样落到下面的 catch。
                return 1
            }
            if prefix.count < end {
                return 0
            }
            _ = try TgcpFrame(header: Array(prefix[0..<h]),
                              body: Array(prefix[h..<end])).publicKey(0x1001)
            return 2
        } catch {
            return 1
        }
    }

    // ── 密钥 ─────────────────────────────────────────────────────────────

    public struct KeyPair {
        /// 对应 Kotlin 的 `private` 字段（Swift 关键字需转义）。
        public let `private`: TgcpBig.Number
        /// 对应 Kotlin 的 `public` 字段。
        public let `public`: TgcpBig.Number
    }

    public static func keyPair() -> KeyPair {
        var raw = CryptoUtil.randomBytes(64)
        raw[0] = (raw[0] & 0x7f) | 0x40
        let value = TgcpBig.Number(bytes: raw)
        let derived = TgcpBig.modPow(TgcpBig.Number(2), value, PRIME)
        return KeyPair(`private`: value, `public`: derived)
    }

    public static func validatePublic(_ value: TgcpBig.Number) throws {
        let primeMinusOne = TgcpBig.subtract(PRIME, TgcpBig.Number(1))
        guard TgcpBig.compare(value, TgcpBig.Number(1)) > 0 &&
              TgcpBig.compare(value, primeMinusOne) < 0 else {
            throw TgcpFailure.illegal("DH 公开值越界")
        }
    }

    public static func publicBytes(_ value: TgcpBig.Number) throws -> [UInt8] {
        try unsignedBigEndian(value, 64)
    }

    public static func derive(_ peer: TgcpBig.Number, _ privateValue: TgcpBig.Number) throws -> [UInt8] {
        try validatePublic(peer)
        let shared = TgcpBig.modPow(peer, privateValue, PRIME)
        try validatePublic(shared)
        // 参考实现用 BigInteger.ToByteArray(true, true)：最短大端、不补前导零。
        return CryptoUtil.md5(shared.bigEndianBytes())
    }

    // ── 填充 / 加解密 ────────────────────────────────────────────────────

    public static func unpad(_ padded: [UInt8]) throws -> [UInt8] {
        guard padded.count >= 16 else { throw TgcpFailure.illegal("TGCP 密文过短") }
        let padding = Int(padded[padded.count - 1])
        guard padding >= 6 && padding <= 21 && padding <= padded.count else {
            throw TgcpFailure.illegal("TGCP 填充长度错误")
        }
        let tail = Array(padded[(padded.count - 6)..<(padded.count - 1)])
        guard tail == Array("tsf4g".utf8) else {
            throw TgcpFailure.illegal("TGCP 填充标记校验失败")
        }
        let length = padded.count - padding
        let expected = (length % 16 >= 11 ? 32 : 16) - length % 16
        guard padding == expected else {
            throw TgcpFailure.illegal("TGCP 填充长度错误")
        }
        return Array(padded[0..<length])
    }

    public static func decryptPadded(_ body: [UInt8], key: [UInt8]) throws -> [UInt8] {
        guard !body.isEmpty && body.count % 16 == 0 else {
            throw TgcpFailure.illegal("TGCP 密文未对齐")
        }
        return try CryptoUtil.aesCbcDecrypt(key: key, iv: IV, data: body)
    }

    public static func encryptPadded(_ padded: [UInt8], key: [UInt8]) throws -> [UInt8] {
        try CryptoUtil.aesCbcEncrypt(key: key, iv: IV, data: padded)
    }

    public static func encrypt(_ plain: [UInt8], key: [UInt8]) throws -> [UInt8] {
        let padding = (plain.count % 16 >= 11 ? 32 : 16) - plain.count % 16
        var result = plain + [UInt8](repeating: 0, count: padding)
        let marker = Array("tsf4g".utf8)
        result.replaceSubrange((result.count - 6)..<(result.count - 1), with: marker)
        result[result.count - 1] = UInt8(padding)
        return try encryptPadded(result, key: key)
    }

    /// 在明文里扫 128 字节 bank（base64 形态 171 字符 + `=`）。
    public static func banks(_ plain: [UInt8]) -> [[UInt8]] {
        let text = String(bytes: plain, encoding: .isoLatin1) ?? ""
        let full = text as NSString
        let range = NSRange(location: 0, length: full.length)
        var out: [[UInt8]] = []
        for match in bankToken.matches(in: text, options: [], range: range) {
            let candidate = full.substring(with: match.range(at: 1))
            guard let bank = try? CryptoUtil.unb64(candidate) else { continue }
            if bank.count == 128 && CryptoUtil.b64(bank) == candidate {
                out.append(bank)
            }
        }
        return out
    }

    public static func unsignedBigEndian(_ value: TgcpBig.Number, _ size: Int) throws -> [UInt8] {
        let raw = value.bigEndianBytes()
        guard raw.count <= size else {
            throw TgcpFailure.illegal("DH 公开值超过 \(size) 字节")
        }
        return [UInt8](repeating: 0, count: size - raw.count) + raw
    }

    // ── 字节序 ───────────────────────────────────────────────────────────

    public static func readU16(_ data: [UInt8], _ at: Int) -> Int {
        (Int(data[at]) << 8) | Int(data[at + 1])
    }

    /// 与 Kotlin 的 Int 一致：可能是负数（高位为 1 时按 32 位补码解释）。
    public static func readU32(_ data: [UInt8], _ at: Int) -> Int {
        let value = (UInt32(data[at]) << 24) |
            (UInt32(data[at + 1]) << 16) |
            (UInt32(data[at + 2]) << 8) |
            UInt32(data[at + 3])
        return Int(Int32(bitPattern: value))
    }

    public static func writeU32(_ data: inout [UInt8], _ at: Int, _ value: Int) {
        let bits = UInt32(truncatingIfNeeded: value)
        data[at] = UInt8(truncatingIfNeeded: bits >> 24)
        data[at + 1] = UInt8(truncatingIfNeeded: bits >> 16)
        data[at + 2] = UInt8(truncatingIfNeeded: bits >> 8)
        data[at + 3] = UInt8(truncatingIfNeeded: bits)
    }
}

/// 一帧 TGCP：header 至少 21 字节，body 为密文或空。
public struct TgcpFrame {

    public let header: [UInt8]
    public let body: [UInt8]

    public init(header: [UInt8], body: [UInt8]) {
        self.header = header
        self.body = body
    }

    public var command: Int {
        TgcpProtocol.readU16(header, 6)
    }

    public var sequence: Int {
        TgcpProtocol.readU32(header, 9)
    }

    public func wire() -> [UInt8] {
        var result = header + body
        TgcpProtocol.writeU32(&result, 17, body.count)
        return result
    }

    public func publicKey(_ command: Int) throws -> TgcpBig.Number {
        guard self.command == command,
              header.count >= 88,
              Array(header[21..<24]) == [3, 0, 64] else {
            throw TgcpFailure.illegal("TGCP hello 格式不匹配")
        }
        let value = TgcpBig.Number(bytes: Array(header[24..<88]))
        try TgcpProtocol.validatePublic(value)
        return value
    }

    public func replacePublic(_ value: TgcpBig.Number, _ newBody: [UInt8]) throws -> TgcpFrame {
        var copy = header
        let bytes = try TgcpProtocol.publicBytes(value)
        copy.replaceSubrange(24..<88, with: bytes)
        return TgcpFrame(header: copy, body: newBody)
    }
}

/// 按方向缓存 TCP 字节流并切帧（安卓 FrameBuffer 的等价实现）。
public final class FrameBuffer {

    private var bytes = [UInt8](repeating: 0, count: 4096)
    private var start = 0
    private var end = 0

    public init() {}

    public var count: Int {
        end - start
    }

    public func append(_ data: [UInt8]) throws {
        let limit = 2 * (16 * 1024 * 1024 + 65536)
        guard count + data.count <= limit else {
            throw TgcpFailure.illegal("TGCP 缓冲超限")
        }
        if bytes.count - end < data.count {
            let wanted = max(count + data.count, min(bytes.count * 2, limit))
            var replacement = [UInt8](repeating: 0, count: wanted)
            if count > 0 {
                replacement.replaceSubrange(0..<count, with: bytes[start..<end])
            }
            end = count
            start = 0
            bytes = replacement
        }
        if !data.isEmpty {
            bytes.replaceSubrange(end..<(end + data.count), with: data)
        }
        end += data.count
    }

    public func take() throws -> TgcpFrame? {
        if count < 21 {
            return nil
        }
        let headEnd = start + min(count, 21)
        let (h, b) = try TgcpProtocol.lengths(Array(bytes[start..<headEnd]))
        let end2 = h + b
        guard end2 >= h else {
            throw TgcpFailure.illegal("TGCP 帧长度超出范围")
        }
        if count < end2 {
            return nil
        }
        let frame = TgcpFrame(header: Array(bytes[start..<(start + h)]),
                              body: Array(bytes[(start + h)..<(start + h + b)]))
        start += end2
        if start == end {
            start = 0
            end = 0
        }
        return frame
    }
}

public struct TgcpObservation {
    public let up: Bool
    public let command: Int
    public let sequence: Int
    public let plain: [UInt8]
    public let banks: [[UInt8]]

    public init(up: Bool, command: Int, sequence: Int, plain: [UInt8], banks: [[UInt8]]) {
        self.up = up
        self.command = command
        self.sequence = sequence
        self.plain = plain
        self.banks = banks
    }
}

public struct TgcpOutput {
    public let toServer: [UInt8]
    public let toClient: [UInt8]
    public let observations: [TgcpObservation]

    public init(toServer: [UInt8], toClient: [UInt8], observations: [TgcpObservation]) {
        self.toServer = toServer
        self.toClient = toClient
        self.observations = observations
    }
}

/// 单条 TCP 流的 TGCP 双密钥会话状态机。
public final class TgcpSession {

    private var x: TgcpBig.Number
    private var y: TgcpBig.Number
    private let publicX: TgcpBig.Number
    private let publicY: TgcpBig.Number
    private var clientKey: [UInt8]?
    private var serverKey: [UInt8]?
    private let buffers = [FrameBuffer(), FrameBuffer()]
    private var finished = [false, false]
    private var seenBanks = Set<String>()
    private let lock = NSRecursiveLock()

    public private(set) var state = 0
    public private(set) var frames: Int64 = 0

    /// 见过与参考实现相反的 Header[8]（仅用于诊断日志）。
    public private(set) var directionMismatch = false

    /// 无法按 tsf4g 解密、按明文原样转发的帧数（仅用于诊断日志）。
    public private(set) var plaintextFrames = 0

    /// 成功解密（说明 MITM 双密钥生效）的帧数，仅用于诊断日志。
    public private(set) var decryptedFrames = 0

    public init() {
        let first = TgcpProtocol.keyPair()
        let second = TgcpProtocol.keyPair()
        x = first.`private`
        publicX = first.`public`
        y = second.`private`
        publicY = second.`public`
    }

    // 上下行由两个泵线程并发喂入，缓冲区/状态机必须串行化，否则会串帧、报「帧头错误」。
    public func feed(up: Bool, input: [UInt8]) throws -> TgcpOutput {
        lock.lock()
        defer { lock.unlock() }

        guard state >= 0 && !finished[up ? 0 : 1] else {
            throw TgcpFailure.illegal("TGCP 会话已结束")
        }

        var toServer: [UInt8] = []
        var toClient: [UInt8] = []
        var observations: [TgcpObservation] = []

        try buffers[up ? 0 : 1].append(input)

        func drain(_ direction: Bool) throws {
            let buffer = buffers[direction ? 0 : 1]
            while !(direction && state == 1) {
                guard let taken = try buffer.take() else { break }
                var frame = taken
                // 方向以实际收包侧为准：实测客户端发来的 hello，Header[8] 也可能是 1，
                // 与参考实现的约定相反。这里只做记录、不再中断会话，否则整条连接会被丢掉。
                if Int(frame.header[8]) != (direction ? 0 : 1) {
                    directionMismatch = true
                }
                if state == 0 {
                    if !direction || !frame.body.isEmpty {
                        throw TgcpFailure.illegal("当前配置要求空体 client hello")
                    }
                    let peer = try frame.publicKey(0x1001)
                    clientKey = try TgcpProtocol.derive(peer, x)
                    toServer.append(contentsOf: try frame.replacePublic(publicY, []).wire())
                    state = 1
                    frames += 1
                    continue
                }
                if state == 1 {
                    if direction {
                        throw TgcpFailure.illegal("服务端 hello 尚未到达")
                    }
                    let peer = try frame.publicKey(0x1002)
                    serverKey = try TgcpProtocol.derive(peer, y)
                    frame = try frame.replacePublic(publicX, frame.body)
                    state = 2
                    x = TgcpBig.Number(0)
                    y = TgcpBig.Number(0)
                } else if frame.command == 0x1001 || frame.command == 0x1002 {
                    throw TgcpFailure.illegal("意外的重复 TGCP hello")
                }
                guard let source = direction ? clientKey : serverKey,
                      let target = direction ? serverKey : clientKey else {
                    throw TgcpFailure.illegal("TGCP 会话缺少密钥")
                }
                if !frame.body.isEmpty {
                    // 少量帧（如 cmd=0x5002）不走 tsf4g 加密：解不开就按明文原样转发，
                    // 只顺带扫一遍 128B 密钥，别让个别帧把整条连接打断。
                    var raw: [UInt8]?
                    var plainBody: [UInt8]?
                    do {
                        let decrypted = try TgcpProtocol.decryptPadded(frame.body, key: source)
                        raw = decrypted
                        plainBody = try TgcpProtocol.unpad(decrypted)
                    } catch {
                        raw = nil
                        plainBody = nil
                    }
                    let plain = plainBody ?? frame.body
                    var candidates: [[UInt8]] = []
                    for bank in TgcpProtocol.banks(plain) {
                        let fingerprint = CryptoUtil.hex(CryptoUtil.sha256(bank))
                        if seenBanks.insert(fingerprint).inserted {
                            candidates.append(bank)
                        }
                        if seenBanks.count > 1024 {
                            throw TgcpFailure.illegal("会话候选密钥数量超限")
                        }
                    }
                    observations.append(TgcpObservation(up: direction,
                                                        command: frame.command,
                                                        sequence: frame.sequence,
                                                        plain: plain,
                                                        banks: candidates))
                    if let raw = raw {
                        decryptedFrames += 1
                        frame = TgcpFrame(header: frame.header,
                                          body: try TgcpProtocol.encryptPadded(raw, key: target))
                    } else {
                        plaintextFrames += 1
                    }
                }
                let wired = frame.wire()
                if direction {
                    toServer.append(contentsOf: wired)
                } else {
                    toClient.append(contentsOf: wired)
                }
                frames += 1
            }
        }

        do {
            try drain(up)
            if state == 2 {
                try drain(!up)
            }
        } catch {
            state = -1
            throw error
        }
        return TgcpOutput(toServer: toServer, toClient: toClient, observations: observations)
    }

    public func close() {
        state = -1
        x = TgcpBig.Number(0)
        y = TgcpBig.Number(0)
    }
}
