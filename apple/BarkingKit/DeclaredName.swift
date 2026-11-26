import Foundation

/// The name a requester declares for themselves, shown in quotes wherever
/// they are not a contact yet: it is what they say, not a verified identity.
public enum DeclaredName {
    /// The language the app's strings are shown in.
    public static var textLocale: Locale {
        Locale(identifier: Bundle.main.preferredLocalizations.first ?? "en")
    }

    /// `name` between the locale's quotation marks (“Léa”, « Léa » with
    /// no-break spaces as in the app's French strings). No name, or only
    /// spaces: the first 8 characters of `fingerprint`, quoted too.
    /// The default locale is the app's text language, so that the quotes
    /// match the strings around them (an English text on a German phone
    /// keeps “ ”).
    public static func quoted(_ name: String, fingerprint: String, locale: Locale = textLocale) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let shown = trimmed.isEmpty ? String(fingerprint.prefix(8)) : name
        let open = locale.quotationBeginDelimiter ?? "“"
        let close = locale.quotationEndDelimiter ?? "”"
        if locale.language.languageCode == .french {
            return "\(open)\u{00A0}\(shown)\u{00A0}\(close)"
        }
        return "\(open)\(shown)\(close)"
    }
}
