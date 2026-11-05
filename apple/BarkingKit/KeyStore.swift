import Foundation
import Security

/// The database key in the keychain (spec iOS foundations §4.2): 32 random
/// bytes, shared with the extension, "after first unlock, this device only".
public struct KeyStore: Sendable {
    public struct Failure: Error, Equatable { public let status: OSStatus }

    let service: String
    let accessGroup: String?

    public init(service: String = "com.nakocorp.barking.db", accessGroup: String?) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func query() -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "db-key",
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    /// The key; `nil` if it is missing or the keychain is not available yet
    /// (before the first unlock after a reboot). Never creates anything.
    public func read() throws -> Data? {
        var q = query()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        switch status {
        case errSecSuccess: return item as? Data
        case errSecItemNotFound, errSecInteractionNotAllowed: return nil
        default: throw Failure(status: status)
        }
    }

    /// Draws and stores a new key; fails if one exists already.
    public func create() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let drawn = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard drawn == errSecSuccess else { throw Failure(status: drawn) }
        let key = Data(bytes)
        var q = query()
        q[kSecValueData as String] = key
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw Failure(status: status) }
        return key
    }

    /// Test helper.
    func delete() throws {
        let status = SecItemDelete(query() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure(status: status)
        }
    }
}
