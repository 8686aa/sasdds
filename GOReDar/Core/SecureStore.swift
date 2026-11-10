import Foundation
import Security
import CryptoKit

/// 本机凭证保险箱：所有接入配置只以 Keychain 条目保存，界面永远拿不到明文。
enum SecureStore {

    private static let service = "com.starradar.capture"

    static func get(_ key: String) -> String {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data,
              let text = String(data: data, encoding: .utf8) else { return "" }
        query.removeAll()
        return text
    }

    static func put(_ key: String, _ value: String) {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        let attrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add.merge(attrs) { _, new in new }
            SecItemAdd(add as CFDictionary, nil)
        }
    }

    static func remove(_ key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// 诊断数据落盘前的密封：AES-GCM，密钥只存 Keychain，文件即便被导出也无法直接阅读。
    static func seal(_ data: Data) -> Data {
        guard let keyData = KeychainKey.material(),
              let key = try? SymmetricKey(data: keyData),
              let sealed = try? AES.GCM.seal(data, using: key),
              let combined = sealed.combined else { return data }
        return combined
    }

    private enum KeychainKey {
        static func material() -> Data? {
            let stored = get("seal_key")
            if stored.count == 32 { return Data(stored.utf8) }
            var bytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            let hex = bytes.map { String(format: "%02x", $0) }.joined()
            put("seal_key", hex)
            return Data(hex.utf8)
        }
    }
}
