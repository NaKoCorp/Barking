import CryptoKit
import Foundation
import Security

/// Wraps the database key (spec §7.1): only the wrapped key is stored.
public protocol KeyWrapper: Sendable {
    func wrap(_ key: Data) throws -> Data
    func unwrap(_ blob: Data) throws -> Data
    /// Deletes the wrapping key; deleting a missing one is not an error.
    func delete() throws
    /// `true` for the Secure Enclave.
    var hardware: Bool { get }
}

/// A P-256 key in the Secure Enclave (spec §7.1): "after first unlock, this
/// device only", no biometric flag (the extension uses it without the user),
/// in the keychain group shared with the extension. It never leaves the
/// enclave; a backup restored on another iPhone does not carry it.
public struct EnclaveKey: KeyWrapper {
    public static let tag = "com.nakocorp.barking.dbwrap"
    static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM

    let accessGroup: String?

    public init(accessGroup: String?) { self.accessGroup = accessGroup }

    /// No enclave on the simulator and on old hardware.
    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    public var hardware: Bool { true }

    private func query() -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(Self.tag.utf8),
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    /// Every key under the tag: the app and the extension may each have
    /// created one during a concurrent migration; a blob opens with one of them.
    private func privateKeys() throws -> [SecKey] {
        var q = query()
        q[kSecReturnRef as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitAll
        var items: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &items)
        switch status {
        case errSecSuccess: return (items as? [SecKey]) ?? []
        case errSecItemNotFound: return []
        default: throw KeyStore.Failure(status: status)
        }
    }

    private func create() throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error)
        else { throw error!.takeRetainedValue() as Error }
        var privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data(Self.tag.utf8),
            kSecAttrAccessControl as String: access,
        ]
        if let accessGroup { privateAttributes[kSecAttrAccessGroup as String] = accessGroup }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: privateAttributes,
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }

    public func wrap(_ key: Data) throws -> Data {
        let priv = try privateKeys().first ?? create()
        guard let pub = SecKeyCopyPublicKey(priv) else { throw KeyStore.Failure(status: errSecInvalidKeyRef) }
        var error: Unmanaged<CFError>?
        guard let blob = SecKeyCreateEncryptedData(pub, Self.algorithm, key as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return blob as Data
    }

    /// Throws `KeyStore.Failure(errSecInteractionNotAllowed)` before the
    /// first unlock, `errSecItemNotFound` without a key.
    public func unwrap(_ blob: Data) throws -> Data {
        let keys = try privateKeys()
        var last: any Error = KeyStore.Failure(status: errSecItemNotFound)
        for priv in keys {
            var error: Unmanaged<CFError>?
            if let key = SecKeyCreateDecryptedData(priv, Self.algorithm, blob as CFData, &error) {
                return key as Data
            }
            if let error { last = error.takeRetainedValue() as Error }
        }
        throw last
    }

    public func delete() throws {
        let status = SecItemDelete(query() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyStore.Failure(status: status)
        }
    }
}

/// AES-GCM in memory, for the tests: the `KeyStore` logic without an enclave.
/// Copies share their key, as copies of `EnclaveKey` share the enclave's.
public struct SoftwareKey: KeyWrapper {
    public struct Missing: Error {}

    private final class Box: @unchecked Sendable {
        let lock = NSLock()
        var key: SymmetricKey?
    }

    private let box = Box()

    public init() {}

    public var hardware: Bool { false }

    /// The wrapping key exists.
    public var exists: Bool { box.lock.withLock { box.key != nil } }

    public func wrap(_ key: Data) throws -> Data {
        let k = box.lock.withLock { () -> SymmetricKey in
            if let k = box.key { return k }
            let k = SymmetricKey(size: .bits256)
            box.key = k
            return k
        }
        guard let blob = try AES.GCM.seal(key, using: k).combined else { throw Missing() }
        return blob
    }

    public func unwrap(_ blob: Data) throws -> Data {
        guard let k = box.lock.withLock({ box.key }) else { throw Missing() }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: blob), using: k)
    }

    public func delete() throws { box.lock.withLock { box.key = nil } }
}
