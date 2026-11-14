import Foundation
import UserNotifications

/// The relay the app was built with: Info.plist keys filled from the build
/// settings `BARKING_RELAY_*` (empty in the repository, set in the
/// git-ignored `Local.xcconfig`), and `BARKING_APS_ENVIRONMENT`.
public enum PushRelay {
    /// Whether iOS lets the app show notifications: the wake subscription
    /// only exists then (denied or not yet asked: push off).
    public static func allows(_ status: UNAuthorizationStatus) -> Bool {
        switch status {
        case .authorized, .provisional, .ephemeral: true
        case .denied, .notDetermined: false
        @unknown default: false
        }
    }

    /// What to give the core for `token`; `nil` (push off) when no relay was
    /// built in or a key is malformed.
    public static func settings(info: [String: Any], token: Data) -> PushSettings? {
        func value(_ key: String) -> String {
            (info[key] as? String ?? "").trimmingCharacters(in: .whitespaces)
        }
        let host = value("BarkingRelayHost")
        guard !host.isEmpty, !token.isEmpty,
              let port = UInt16(value("BarkingRelayPort")), port > 0,
              let sealId = UInt8(value("BarkingRelaySealId")),
              let seal = bytes(hex: value("BarkingRelaySealPublic")), seal.count == 32
        else { return nil }
        return PushSettings(relayHost: host, relayPort: port, relayId: value("BarkingRelayId"),
                            sealKeyId: sealId, sealPublic: seal, apnsToken: token,
                            sandbox: value("BarkingApnsEnvironment") != "production")
    }

    private static func bytes(hex: String) -> Data? {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var out = Data(capacity: hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
    }
}
