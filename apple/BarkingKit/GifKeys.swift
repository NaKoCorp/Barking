import Foundation

/// The GIF provider keys the app was built with: the Info.plist key
/// `BarkingKlipyKey`, filled from the build setting `BARKING_KLIPY_KEY`
/// (empty in the repository, set in the git-ignored `Local.xcconfig`).
/// The app hands it to the core at each start; it is never stored.
public enum GifKeys {
    /// The Klipy key, trimmed; nil when the build has none.
    public static func klipy(info: [String: Any]) -> String? {
        let key = (info["BarkingKlipyKey"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return key.isEmpty ? nil : key
    }
}
