import Foundation

/// 与安卓端 `require()` / `IllegalArgumentException` 等价的错误。
public enum SeasonFailure: Error, CustomStringConvertible {
    case illegal(String)

    public var description: String {
        switch self {
        case .illegal(let message):
            return message
        }
    }
}

/**
 新赛季 16 字节会话 key 的密码学原语（与安卓 `SeasonCrypto` / pytho/gui/seasoncrypto.py 对齐）。

     shared = X25519(d, V)
     K      = SHA512(shared || C || V)[:16]

 下行包首字节最低位为 1 是明文，否则首字节保留、其余按 XTEA-CBC(32 轮) 解密。
 */
public enum SeasonCrypto {

    private static let DELTA: UInt32 = 0x9E37_79B9

    // 1.201.37119 内置配置：exchange_public(32) || signing_public(32) || 签名(64)
    private static let SERVER_CONFIG_B64 =
        "HSoSI+AYuDE2Vvn0g2cheMsH+jMBFzjpnLUmg7Qhwg1wPUwPFwp/Yv85JaoKI351vVNW0FJ4Pnej" +
        "ggi64jEQHji1CXdMHLMwd4yDJ+mDcNTpUrnSP8A4JtTTctgTLOw0jQDkgQJjGu09OkazGfF1PJ" +
        "Xp6O8pNWyw5IdKARnl7Ao="

    // 校验上面那段配置的 Ed25519 根公钥
    private static let ROOT_PUBLIC_B64 = "47jOvrq+hd5SJ0Ju4LYsJ/Q5ep0Kxp6P9Q94WlfAjao="

    public static let CONTROL7_LEN = 69
    public static let CONTROL7_BODY_LEN = 64

    // ── 内置配置 ─────────────────────────────────────────────────────────

    private static let builtIn: (exchange: [UInt8], signing: [UInt8], identifier: Int) = {
        let config = (try? CryptoUtil.unb64(SERVER_CONFIG_B64)) ?? []
        let root = (try? CryptoUtil.unb64(ROOT_PUBLIC_B64)) ?? []
        guard config.count == 128 else {
            fatalError("内置服务端配置长度错误")
        }
        let exchange = Array(config[0..<32])
        let signing = Array(config[32..<64])
        let identifier = Int(Int32(bitPattern: SeasonCrypto.crc32(exchange)))
        // 内置常量损坏才会验不过；不阻断运行，只留给人看。
        let ok = CryptoUtil.ed25519Verify(publicKey: root,
                                          message: Array(config[0..<64]),
                                          signature: Array(config[64..<128]))
        guard ok else {
            fatalError("内置服务端配置签名校验失败")
        }
        return (exchange, signing, identifier)
    }()

    public static var exchangePublic: [UInt8] { builtIn.exchange }
    public static var signingPublic: [UInt8] { builtIn.signing }

    /// type-7 参数：服务端交换公钥的 CRC32。
    public static var identifier: Int { builtIn.identifier }

    private static let crcTable: [UInt32] = (0..<256).map { index in
        var value = UInt32(index)
        for _ in 0..<8 {
            value = (value & 1) != 0 ? (0xEDB8_8320 ^ (value >> 1)) : (value >> 1)
        }
        return value
    }

    /// java.util.zip.CRC32（反射多项式 0xEDB88320）。
    private static func crc32(_ bytes: [UInt8]) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            crc = crcTable[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }

    // ── XTEA-CBC ─────────────────────────────────────────────────────────

    private static func words(_ key: [UInt8]) throws -> [UInt32] {
        guard key.count == 16 else { throw SeasonFailure.illegal("会话 key 必须为 16 字节") }
        return (0..<4).map { readU32(key, $0 * 4) }
    }

    public static func xteaCbcDecrypt(_ data: [UInt8], key: [UInt8]) throws -> [UInt8] {
        let w = try words(key)
        var out = data
        var prevA: UInt32 = 0
        var prevB: UInt32 = 0
        var at = 0
        while at <= data.count - 8 {
            let cipherA = readU32(data, at)
            let cipherB = readU32(data, at + 4)
            var total = DELTA &* 32
            var b = cipherB
            var a = cipherA
            for _ in 0..<32 {
                b = b &- ((((a << 4) ^ (a >> 5)) &+ a) ^
                    (total &+ w[Int((total >> 11) & 3)]))
                total = total &- DELTA
                a = a &- ((((b << 4) ^ (b >> 5)) &+ b) ^
                    (total &+ w[Int(total & 3)]))
            }
            writeU32(&out, at, a ^ prevA)
            writeU32(&out, at + 4, b ^ prevB)
            prevB = cipherB
            prevA = cipherA
            at += 8
        }
        return out
    }

    public static func xteaCbcEncrypt(_ data: [UInt8], key: [UInt8]) throws -> [UInt8] {
        let w = try words(key)
        var out = data
        var prevA: UInt32 = 0
        var prevB: UInt32 = 0
        var at = 0
        while at <= data.count - 8 {
            var a = readU32(data, at) ^ prevA
            var b = readU32(data, at + 4) ^ prevB
            var total: UInt32 = 0
            for _ in 0..<32 {
                a = a &+ ((((b << 4) ^ (b >> 5)) &+ b) ^
                    (total &+ w[Int(total & 3)]))
                total = total &+ DELTA
                b = b &+ ((((a << 4) ^ (a >> 5)) &+ a) ^
                    (total &+ w[Int((total >> 11) & 3)]))
            }
            writeU32(&out, at, a)
            writeU32(&out, at + 4, b)
            prevB = b
            prevA = a
            at += 8
        }
        return out
    }

    public static func decryptDownlink(_ payload: [UInt8], key: [UInt8]) throws -> [UInt8] {
        guard key.count == 16 else { throw SeasonFailure.illegal("会话 key 必须为 16 字节") }
        guard !payload.isEmpty else { throw SeasonFailure.illegal("UDP 载荷为空") }
        if payload[0] & 1 != 0 { return payload }
        let decrypted = try xteaCbcDecrypt(Array(payload[1...]), key: key)
        return [payload[0]] + decrypted
    }

    public static func encryptDownlink(_ plain: [UInt8], key: [UInt8]) throws -> [UInt8] {
        guard key.count == 16 else { throw SeasonFailure.illegal("会话 key 必须为 16 字节") }
        guard !plain.isEmpty else { throw SeasonFailure.illegal("UDP 载荷为空") }
        if plain[0] & 1 != 0 { return plain }
        let encrypted = try xteaCbcEncrypt(Array(plain[1...]), key: key)
        return [plain[0]] + encrypted
    }

    // ── key 派生 ─────────────────────────────────────────────────────────

    public static func sessionKey(_ shared: [UInt8],
                                  _ clientPublic: [UInt8],
                                  _ serverPublic: [UInt8]) throws -> [UInt8] {
        guard shared.count == 32 && clientPublic.count == 32 && serverPublic.count == 32 else {
            throw SeasonFailure.illegal("X25519 共享密钥必须为 32 字节")
        }
        let digest = CryptoUtil.sha512(shared + clientPublic + serverPublic)
        return Array(digest[0..<16])
    }

    // ── type-7 控制帧 ────────────────────────────────────────────────────

    public struct Control7 {

        public let parameter: Int
        public let data: [UInt8]

        public init(parameter: Int, data: [UInt8]) {
            self.parameter = parameter
            self.data = data
        }

        public var clientPublic: [UInt8] {
            Array(data[0..<32])
        }

        public var firstDigest: [UInt8] {
            Array(data[32..<48])
        }

        public var secondDigest: [UInt8] {
            Array(data[48..<64])
        }

        public func digestChainMatches() -> Bool {
            if data.count != SeasonCrypto.CONTROL7_BODY_LEN {
                return false
            }
            return CryptoUtil.constantTimeEquals(
                CryptoUtil.md5(clientPublic + firstDigest),
                secondDigest
            )
        }

        public func sharedSecretMatches(_ shared: [UInt8]) -> Bool {
            if !digestChainMatches() {
                return false
            }
            return CryptoUtil.constantTimeEquals(
                CryptoUtil.md5(clientPublic + shared),
                firstDigest
            )
        }
    }

    public static func parseControl7(_ payload: [UInt8]) throws -> Control7 {
        guard payload.count == CONTROL7_LEN else {
            throw SeasonFailure.illegal("不是 69 字节的 type-7 控制帧")
        }
        guard (payload[0] & 31) == 15 else {
            throw SeasonFailure.illegal("type-7 控制帧首字节不匹配")
        }
        guard bitLengthLittleEndian(payload) == 550 else {
            throw SeasonFailure.illegal("type-7 控制帧终止位非法")
        }
        // bits >> 5 后低 544 位：等价于对 69 字节小端值做 5 位移位再裁到 68 字节。
        var body = [UInt8](repeating: 0, count: 68)
        for index in 0..<68 {
            body[index] = (payload[index] >> 5) | (payload[index + 1] << 3)
        }
        return Control7(parameter: readIntLE(body, 0), data: Array(body[4..<68]))
    }

    public static func control7(_ parameter: Int, _ body: [UInt8]) throws -> [UInt8] {
        guard body.count == CONTROL7_BODY_LEN else {
            throw SeasonFailure.illegal("type-7 body 必须为 64 字节")
        }
        var raw = [UInt8](repeating: 0, count: 68)
        raw[0] = UInt8(truncatingIfNeeded: parameter)
        raw[1] = UInt8(truncatingIfNeeded: parameter >> 8)
        raw[2] = UInt8(truncatingIfNeeded: parameter >> 16)
        raw[3] = UInt8(truncatingIfNeeded: parameter >> 24)
        raw.replaceSubrange(4..<68, with: body)
        // encoded = (value << 5) | 15 | (1 << 549)
        var encoded = [UInt8](repeating: 0, count: CONTROL7_LEN)
        var carry: UInt16 = 0
        for index in 0..<68 {
            let current = (UInt16(raw[index]) << 5) | carry
            encoded[index] = UInt8(truncatingIfNeeded: current)
            carry = current >> 8
        }
        encoded[68] = UInt8(truncatingIfNeeded: carry)
        encoded[0] |= 0x0F
        encoded[68] |= 0x20
        return encoded
    }

    // ── 验签 ─────────────────────────────────────────────────────────────

    public static func verifyAck(_ ack: Control7,
                                 _ clientPublic: [UInt8],
                                 _ signingPublic: [UInt8]) -> Bool {
        guard clientPublic.count == 32, signingPublic.count == 32, ack.data.count == 64 else {
            return false
        }
        var signed = Array(clientPublic[0..<32])
        signed.append(UInt8(truncatingIfNeeded: ack.parameter))
        signed.append(UInt8(truncatingIfNeeded: ack.parameter >> 8))
        signed.append(UInt8(truncatingIfNeeded: ack.parameter >> 16))
        signed.append(UInt8(truncatingIfNeeded: ack.parameter >> 24))
        return CryptoUtil.ed25519Verify(publicKey: signingPublic,
                                        message: signed,
                                        signature: ack.data)
    }

    /**
     代理自己的控制帧与服务端 ACK 必须属于同一场认证。
     ACK 参数位实测恒为 0，签名覆盖的是 `client_public || 帧里的参数`。
     */
    public static func matchesTranscript(client: Control7, ack: Control7) -> Bool {
        if client.parameter != identifier {
            return false
        }
        if !client.digestChainMatches() {
            return false
        }
        if verifyAck(Control7(parameter: ack.parameter, data: ack.data),
                     client.clientPublic,
                     signingPublic) {
            return true
        }
        if ack.parameter != identifier {
            return verifyAck(Control7(parameter: identifier, data: ack.data),
                             client.clientPublic,
                             signingPublic)
        }
        return false
    }

    // ── 小工具 ───────────────────────────────────────────────────────────

    /// 小端字节序列里最高有效位的位长（对应 BigInteger.bitLength()）。
    private static func bitLengthLittleEndian(_ bytes: [UInt8]) -> Int {
        var index = bytes.count - 1
        while index >= 0 && bytes[index] == 0 {
            index -= 1
        }
        if index < 0 {
            return 0
        }
        let top = bytes[index]
        return index * 8 + (8 - top.leadingZeroBitCount)
    }

    public static func readU32(_ data: [UInt8], _ at: Int) -> UInt32 {
        UInt32(data[at]) |
            (UInt32(data[at + 1]) << 8) |
            (UInt32(data[at + 2]) << 16) |
            (UInt32(data[at + 3]) << 24)
    }

    public static func writeU32(_ data: inout [UInt8], _ at: Int, _ value: UInt32) {
        data[at] = UInt8(truncatingIfNeeded: value)
        data[at + 1] = UInt8(truncatingIfNeeded: value >> 8)
        data[at + 2] = UInt8(truncatingIfNeeded: value >> 16)
        data[at + 3] = UInt8(truncatingIfNeeded: value >> 24)
    }

    public static func readIntLE(_ data: [UInt8], _ at: Int) -> Int {
        Int(Int32(bitPattern: readU32(data, at)))
    }
}
