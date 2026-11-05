import Foundation
import Security

/// Keychain items by account: the `KeyStore`'s storage.
public protocol KeyEntries: Sendable {
    /// `nil` if missing or not readable yet (before the first unlock).
    func get(_ account: String) throws -> Data?
    /// Fails with `errSecDuplicateItem` if the item exists.
    func add(_ account: String, _ value: Data) throws
    /// Deleting a missing item is not an error.
    func delete(_ account: String) throws
}

/// Generic passwords of one service, shared with the extension, "after first
/// unlock, this device only".
struct KeychainEntries: KeyEntries {
    let service: String
    let accessGroup: String?

    private func query(_ account: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    func get(_ account: String) throws -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        switch status {
        case errSecSuccess: return item as? Data
        case errSecItemNotFound, errSecInteractionNotAllowed: return nil
        default: throw KeyStore.Failure(status: status)
        }
    }

    func add(_ account: String, _ value: Data) throws {
        var q = query(account)
        q[kSecValueData as String] = value
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeyStore.Failure(status: status) }
    }

    func delete(_ account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyStore.Failure(status: status)
        }
    }
}

/// The database key (spec iOS foundations §4.2, spec §7): 32 random bytes,
/// wrapped by the Secure Enclave (`db-key-wrapped`). Without an enclave it
/// stays in clear in the keychain (`db-key`), as before; a clear key left by
/// an earlier version is wrapped at its first read.
public struct KeyStore: Sendable {
    public struct Failure: Error, Equatable { public let status: OSStatus }
    /// `db-key-wrapped` exists but does not unwrap (enclave key missing:
    /// backup restored on another iPhone). Nothing is overwritten.
    public struct Unavailable: Error {}

    static let legacyAccount = "db-key"
    static let wrappedAccount = "db-key-wrapped"

    let entries: any KeyEntries
    let wrapper: (any KeyWrapper)?

    public init(service: String = "com.nakocorp.barking.db", accessGroup: String?) {
        self.init(entries: KeychainEntries(service: service, accessGroup: accessGroup),
                  wrapper: EnclaveKey.isAvailable ? EnclaveKey(accessGroup: accessGroup) : nil)
    }

    init(entries: any KeyEntries, wrapper: (any KeyWrapper)?) {
        self.entries = entries
        self.wrapper = wrapper
    }

    /// `secure-enclave` or `keychain`, for the transparency view.
    public var protection: String {
        guard wrapper?.hardware == true, (try? entries.get(Self.wrappedAccount)) != nil else { return "keychain" }
        return "secure-enclave"
    }

    /// The key in clear; `nil` if it is missing or the keychain is not
    /// available yet (before the first unlock after a reboot). Creates
    /// nothing but the wrapped copy of a clear key.
    public func read() throws -> Data? {
        // Clear key first: a migration writes the wrapped key before deleting
        // the clear one, so a reader in between still finds one of them.
        let legacy = try entries.get(Self.legacyAccount)
        if let wrapped = try entries.get(Self.wrappedAccount) {
            let key: Data
            do {
                guard let wrapper else { throw Unavailable() }
                key = try wrapper.unwrap(wrapped)
            } catch let f as Failure where f.status == errSecInteractionNotAllowed {
                return nil
            } catch {
                // An interrupted migration left the clear key: it still opens.
                if let legacy { return legacy }
                throw Unavailable()
            }
            // Finishes a migration cut between its two writes.
            if legacy != nil { try? entries.delete(Self.legacyAccount) }
            return key
        }
        guard let legacy else { return nil }
        if let wrapper { migrate(legacy, with: wrapper) }
        return legacy
    }

    /// Wraps a clear key, then deletes it: an interruption never loses it. A
    /// failure leaves the clear key, tried again at the next read.
    private func migrate(_ key: Data, with wrapper: any KeyWrapper) {
        guard let blob = try? wrapper.wrap(key) else { return }
        do {
            try entries.add(Self.wrappedAccount, blob)
        } catch let f as Failure where f.status == errSecDuplicateItem {
            // The app and the extension migrated together: the other copy
            // wraps the same key.
        } catch {
            return
        }
        try? entries.delete(Self.legacyAccount)
    }

    /// Draws and stores a new key; fails if one exists already, clear or wrapped.
    public func create() throws -> Data {
        guard try entries.get(Self.legacyAccount) == nil, try entries.get(Self.wrappedAccount) == nil else {
            throw Failure(status: errSecDuplicateItem)
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        let drawn = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard drawn == errSecSuccess else { throw Failure(status: drawn) }
        let key = Data(bytes)
        if let wrapper {
            try entries.add(Self.wrappedAccount, try wrapper.wrap(key))
        } else {
            try entries.add(Self.legacyAccount, key)
        }
        return key
    }

    /// A new key in place of any existing one: only when the database it
    /// opened is gone (reinstall: iOS keeps keychain items, not the container).
    /// The enclave key goes too: a new identity gets a new one.
    public func replace() throws -> Data {
        try delete()
        return try create()
    }

    /// The wrapped key, a clear one and the enclave key. Tries all of them,
    /// throws the first failure.
    func delete() throws {
        var first: (any Error)?
        for account in [Self.wrappedAccount, Self.legacyAccount] {
            do { try entries.delete(account) } catch { first = first ?? error }
        }
        do { try wrapper?.delete() } catch { first = first ?? error }
        if let first { throw first }
    }
}
