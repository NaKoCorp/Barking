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

    /// Surrounding spaces are not part of the name.
    func testNameIsTrimmed() {
        XCTAssertEqual(DeclaredName.quoted("  Léa \n", fingerprint: "F", locale: Locale(identifier: "en_US")), "“Léa”")
    }

    /// The text locale is the strings bundle's language, a bare .lproj included.
    func testTextLocaleOfLprojBundle() throws {
        let kit = Bundle(for: NotificationContent.Marker.self)
        let fr = try XCTUnwrap(kit.path(forResource: "fr", ofType: "lproj").flatMap(Bundle.init(path:)))
        XCTAssertEqual(DeclaredName.textLocale(fr).language.languageCode, .french)
    }
}
