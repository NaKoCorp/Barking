import XCTest
@testable import BarkingKit

final class DeclaredNameTests: XCTestCase {
    /// « Léa », with a no-break space (U+00A0) inside, as in the app's strings.
    func testFrenchQuotes() {
        XCTAssertEqual(DeclaredName.quoted("Léa", fingerprint: "ABCDEF0123456789", locale: Locale(identifier: "fr_FR")),
                       "«\u{00A0}Léa\u{00A0}»")
    }

    func testEnglishQuotes() {
        XCTAssertEqual(DeclaredName.quoted("Léa", fingerprint: "ABCDEF0123456789", locale: Locale(identifier: "en_US")),
                       "“Léa”")
    }

    /// No name (or only spaces): the first 8 characters of the fingerprint, still quoted.
    func testEmptyNameUsesFingerprint() {
        let en = Locale(identifier: "en_US")
        XCTAssertEqual(DeclaredName.quoted("", fingerprint: "ABCDEF0123456789", locale: en), "“ABCDEF01”")
        XCTAssertEqual(DeclaredName.quoted("  \n", fingerprint: "ABCDEF0123456789", locale: en), "“ABCDEF01”")
    }

    /// Without a locale: the quotes of the app's text language.
    func testDefaultLocaleFollowsTextLanguage() {
        let lang = Bundle.main.preferredLocalizations.first ?? "en"
        let expected = DeclaredName.quoted("Léa", fingerprint: "F", locale: Locale(identifier: lang))
        XCTAssertEqual(DeclaredName.quoted("Léa", fingerprint: "F"), expected)
    }
}
