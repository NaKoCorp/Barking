import Foundation

/// The name a requester declares for themselves, shown in quotes wherever
/// they are not a contact yet: it is what they say, not a verified identity.
public enum DeclaredName {
    /// The language `bundle` shows its strings in: the quotes must match the
    /// text around them. Not `Bundle.main`: in the notification extension it
    /// has no .lproj, while the strings come from BarkingKit's bundle. A
    /// bundle that is itself one `.lproj` (tests) is that language.
    public static func textLocale(_ bundle: Bundle = Bundle(for: NotificationContent.Marker.self)) -> Locale {
        if bundle.bundleURL.pathExtension == "lproj" {
            return Locale(identifier: bundle.bundleURL.deletingPathExtension().lastPathComponent)
        }
        return Locale(identifier: bundle.preferredLocalizations.first ?? "en")
    }

    /// `name` between the locale's quotation marks (“Léa”, « Léa » with
    /// no-break spaces as in the app's French strings). No name, or only
    /// spaces: the first 8 characters of `fingerprint`, quoted too. The
    /// default locale is the language of BarkingKit's strings.
    public static func quoted(_ name: String, fingerprint: String, locale: Locale = textLocale()) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let shown = trimmed.isEmpty ? String(fingerprint.prefix(8)) : trimmed
        let open = locale.quotationBeginDelimiter ?? "“"
        let close = locale.quotationEndDelimiter ?? "”"
        if locale.language.languageCode == .french {
            return "\(open)\u{00A0}\(shown)\u{00A0}\(close)"
        }
        return "\(open)\(shown)\(close)"
    }
}
