import Foundation
import CryptoKit
import CommonCrypto
import Darwin

/// 与安卓端 Crypto.kt 一一对应的加密工具集。
///
/// 说明：
///   - X25519 / Ed25519 由 CryptoKit 提供，输出均为 32 字节原始表示，与 BouncyCastle 的
///     `encoded` 完全一致；
///   - AES-GCM 使用 CryptoKit，返回「密文 + 16 字节 tag」，与 JCE 的
///     `AES/GCM/NoPadding` 输出布局一致；
///   - AES-CBC 无填充模式 CryptoKit 不支持，改用 CommonCrypto 的 CCCrypt；
///   - iOS 没有任意精度整数类型，`bigInteger` / `unsignedBigEndian` 用无符号大端字节数组
///     表示同一个值（安卓端这两个函数只做正整数的字节补齐）。
public enum CryptoUtil {

    /// 与安卓端 require()/异常等价的错误类型。
    public enum Failure: Error, CustomStringConvertible {
        case invalidHex
        case invalidBase64
        case integerOverflow(Int)
        case crypto(String)

        public var description: String {
            switch self {
            case .invalidHex:
                return "非法 hex"
            case .invalidBase64:
                return "非法 base64"
            case .integerOverflow(let size):
                return "大整数超过 \(size) 字节"
            case .crypto(let detail):
                return detail
            }
        }
    }

    private static let hexTable: [Character] = Array("0123456789abcdef")

    // ── 随机数 / 编码 ─────────────────────────────────────────────────────

    public static func randomBytes(_ size: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: size)
        if size > 0 {
            arc4random_buf(&bytes, size)
        }
        return bytes
    }

    public static func hex(_ bytes: [UInt8]) -> String {
        var out = ""
        out.reserveCapacity(bytes.count * 2)
        for value in bytes {
            out.append(hexTable[Int(value >> 4)])
            out.append(hexTable[Int(value & 0x0f)])
        }
        return out
    }

    public static func unhex(_ text: String) throws -> [UInt8] {
        let chars = Array(text)
        guard chars.count % 2 == 0 else { throw Failure.invalidHex }
        var out = [UInt8](repeating: 0, count: chars.count / 2)
        for i in 0..<out.count {
            guard let hi = chars[i * 2].hexDigitValue,
                  let lo = chars[i * 2 + 1].hexDigitValue else { throw Failure.invalidHex }
            out[i] = UInt8((hi << 4) | lo)
        }
        return out
    }

    public static func b64(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
    }

    public static func unb64(_ text: String) throws -> [UInt8] {
        // 对应安卓 Base64.getMimeDecoder()：忽略换行等非法字符
        if let data = Data(base64Encoded: text, options: .ignoreUnknownCharacters) {
            return Array(data)
        }
        // Java 解码器允许省略末尾的 '='，Swift 需要手动补齐
        var padded = text.filter { !$0.isWhitespace }
        switch padded.count % 4 {
        case 2:
            padded += "=="
        case 3:
            padded += "="
        case 1:
            throw Failure.invalidBase64
        default:
            break
        }
        guard let data = Data(base64Encoded: padded, options: .ignoreUnknownCharacters) else {
            throw Failure.invalidBase64
        }
        return Array(data)
    }

    // ── 摘要 / MAC / KDF ─────────────────────────────────────────────────

    public static func sha256(_ data: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(data)))
    }

    public static func sha512(_ data: [UInt8]) -> [UInt8] {
        Array(SHA512.hash(data: Data(data)))
    }

    public static func md5(_ data: [UInt8]) -> [UInt8] {
        Array(Insecure.MD5.hash(data: Data(data)))
    }

    public static func hmacSha256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        let symmetric = SymmetricKey(data: Data(key))
        return Array(HMAC<SHA256>.authenticationCode(for: Data(data), using: symmetric))
    }

    public static func hkdfSha256(ikm: [UInt8], salt: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
        let prk = hmacSha256(key: salt, data: ikm)
        var out = [UInt8](repeating: 0, count: length)
        var previous: [UInt8] = []
        var offset = 0
        var counter: UInt8 = 1
        while offset < length {
            var block = previous
            block.append(contentsOf: info)
            block.append(counter)
            previous = hmacSha256(key: prk, data: block)
            let take = min(previous.count, length - offset)
            out.replaceSubrange(offset..<(offset + take), with: previous[0..<take])
            offset += take
            counter = counter &+ 1
        }
        return out
    }

    // ── AES-GCM ──────────────────────────────────────────────────────────

    public static func aesGcmEncrypt(key: [UInt8],
                                     nonce: [UInt8],
                                     aad: [UInt8],
                                     plain: [UInt8]) throws -> [UInt8] {
        let symmetric = SymmetricKey(data: Data(key))
        let nonceBox = try AES.GCM.Nonce(data: Data(nonce))
        let sealed = try AES.GCM.seal(Data(plain),
                                      using: symmetric,
                                      nonce: nonceBox,
                                      authenticating: Data(aad))
        // JCE 的 doFinal 只输出 密文||tag，这里去掉 CryptoKit 自动附加的 nonce
        return Array(sealed.ciphertext) + Array(sealed.tag)
    }

    public static func aesGcmDecrypt(key: [UInt8],
                                     nonce: [UInt8],
                                     aad: [UInt8],
                                     data: [UInt8]) throws -> [UInt8] {
        guard data.count >= 16 else { throw Failure.crypto("AES-GCM 数据长度不足") }
        let tagStart = data.count - 16
        let nonceBox = try AES.GCM.Nonce(data: Data(nonce))
        let box = try AES.GCM.SealedBox(nonce: nonceBox,
                                        ciphertext: Data(data[0..<tagStart]),
                                        tag: Data(data[tagStart...]))
        let plain = try AES.GCM.open(box, using: SymmetricKey(data: Data(key)), authenticating: Data(aad))
        return Array(plain)
    }

    // ── AES-CBC（无填充）────────────────────────────────────────────────

    public static func aesCbcDecrypt(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
        try cbc(CCOperation(kCCDecrypt), key: key, iv: iv, data: data)
    }

    public static func aesCbcEncrypt(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
        try cbc(CCOperation(kCCEncrypt), key: key, iv: iv, data: data)
    }

    private static func cbc(_ operation: CCOperation,
                            key: [UInt8],
                            iv: [UInt8],
                            data: [UInt8]) throws -> [UInt8] {
        if data.isEmpty { return [] }
        var out = [UInt8](repeating: 0, count: data.count + Int(kCCBlockSizeAES128))
        let capacity = out.count
        var moved = 0
        let status = key.withUnsafeBytes { keyBuf -> CCCryptorStatus in
            iv.withUnsafeBytes { ivBuf -> CCCryptorStatus in
                data.withUnsafeBytes { dataBuf -> CCCryptorStatus in
                    CCCrypt(operation,
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0), // 0 = 无填充，对应 AES/CBC/NoPadding
                            keyBuf.baseAddress, key.count,
                            ivBuf.baseAddress,
                            dataBuf.baseAddress, data.count,
                            &out, capacity,
                            &moved)
                }
            }
        }
        guard status == kCCSuccess else {
            throw Failure.crypto("AES-CBC 失败(\(status))")
        }
        return Array(out.prefix(moved))
    }

    // ── 比较 / 大整数 ────────────────────────────────────────────────────

    public static func constantTimeEquals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[i] ^ b[i]
        }
        return diff == 0
    }

    /// 等价于 `BigInteger(1, bytes)`：去掉前导零，保留无符号大端字节。
    public static func bigInteger(_ bytes: [UInt8]) -> [UInt8] {
        var start = 0
        while start < bytes.count && bytes[start] == 0 {
            start += 1
        }
        return Array(bytes[start...])
    }

    /// 等价于 `unsignedBigEndian`：左补零到固定长度，超长报错。
    public static func unsignedBigEndian(_ magnitude: [UInt8], size: Int) throws -> [UInt8] {
        let value = bigInteger(magnitude)
        guard value.count <= size else { throw Failure.integerOverflow(size) }
        var out = [UInt8](repeating: 0, count: size)
        if !value.isEmpty {
            out.replaceSubrange((size - value.count)..<size, with: value)
        }
        return out
    }

    // ── X25519 / Ed25519 ────────────────────────────────────────────────

    public static func x25519KeyPair() -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        return (Array(privateKey.rawRepresentation), Array(privateKey.publicKey.rawRepresentation))
    }

    public static func x25519(privateKey: [UInt8], peerPublic: [UInt8]) throws -> [UInt8] {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(privateKey))
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(peerPublic))
        let shared = try priv.sharedSecretFromKeyAgreement(with: pub)
        return shared.withUnsafeBytes { Array($0) }
    }

    public static func x25519Public(privateKey: [UInt8]) throws -> [UInt8] {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(privateKey))
        return Array(priv.publicKey.rawRepresentation)
    }

    public static func ed25519Verify(publicKey: [UInt8],
                                     message: [UInt8],
                                     signature: [UInt8]) -> Bool {
        guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(publicKey)) else {
            return false
        }
        return pub.isValidSignature(Data(signature), for: Data(message))
    }
}
