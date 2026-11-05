import XCTest

final class LocalizationTests: XCTestCase {
    private func table(_ lang: String, _ name: String = "Localizable", _ type: String = "strings") -> NSDictionary? {
        Bundle.main.path(forResource: name, ofType: type, inDirectory: nil, forLocalization: lang)
            .flatMap { NSDictionary(contentsOfFile: $0) }
    }

    func testEveryKeyHasFrench() throws {
        let fr = try XCTUnwrap(table("fr"))
        XCTAssertGreaterThanOrEqual(fr.count, 170)
        for (k, v) in fr {
            XCTAssertFalse((v as? String ?? "").isEmpty, "empty French value for \(k)")
        }
        for key in ["Create my identity", "Chats", "The numbers match", "Link a new device", "Sync now",
                    "This is not a Barking card", "✓ verified · safety code matched"] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
    }

    func testPluralsInBothLanguages() throws {
        for lang in ["en", "fr"] {
            let d = try XCTUnwrap(table(lang, "Localizable", "stringsdict"), lang)
            for key in ["%lld packets pending", "%lld unread", "%lld of 8 devices"] {
                let rule = (d[key] as? NSDictionary)?["n"] as? NSDictionary
                XCTAssertNotNil(rule?["one"], "\(lang) \(key)")
                XCTAssertNotNil(rule?["other"], "\(lang) \(key)")
            }
        }
    }
}
