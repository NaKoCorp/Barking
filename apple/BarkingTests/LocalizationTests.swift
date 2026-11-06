import XCTest
@testable import BarkingKit

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
                    "This is not a Barking card", "✓ verified · safety code matched", "Make admin",
                    "Transfer pending", "This device was removed from your account", "Reset this device",
                    "Disconnect this device", "Remove %@", "Handing over to %@…",
                    "Everything on this iPhone will be erased. Your contacts will not be told. To get your identity back, you will need the 24-word phrase.",
                    "The handover to %@ did not finish. Nothing was erased: this device is still your admin.",
                    "Message path", "Internet relay · %@", "%@'s phone", "Path not recorded",
                    "a sealed packet of %@ for a mailbox that changes every day. Not the sender, not the text. The IP address of whoever deposited it."] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
    }

    /// Every key the core can log (`logKeys()`) and every arg token has an
    /// English and a French text, with the same placeholders.
    func testEveryLogKeyHasBothLanguages() throws {
        let en = try XCTUnwrap(table("en", "Log"))
        let fr = try XCTUnwrap(table("fr", "Log"))
        let keys = logKeys() + logArgTokens().map { "log.arg.\($0)" }
        XCTAssertGreaterThanOrEqual(logKeys().count, 26)
        for key in keys {
            let e = en[key] as? String ?? ""
            let f = fr[key] as? String ?? ""
            XCTAssertFalse(e.isEmpty, "no English text for \(key)")
            XCTAssertFalse(f.isEmpty, "no French text for \(key)")
            let placeholders = { (s: String) in
                s.matches(of: /%(\d)\$@/).map { String($0.output.1) }.sorted()
            }
            XCTAssertEqual(placeholders(e), placeholders(f), "placeholders of \(key)")
        }
    }

    func testTransparencyStringsInFrench() throws {
        let fr = try XCTUnwrap(table("fr"))
        for key in ["Transparency", "Security only", "Where my data is", "Devices",
                    "Database key protected by the Secure Enclave", "Database key protected by the keychain only",
                    "Nothing yet", "Today", "Yesterday"] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
    }

    func testPluralsInBothLanguages() throws {
        for lang in ["en", "fr"] {
            let d = try XCTUnwrap(table(lang, "Localizable", "stringsdict"), lang)
            for key in ["%lld packets pending", "%lld unread", "%lld of 8 devices", "Internet · %lld relays"] {
                let rule = (d[key] as? NSDictionary)?["n"] as? NSDictionary
                XCTAssertNotNil(rule?["one"], "\(lang) \(key)")
                XCTAssertNotNil(rule?["other"], "\(lang) \(key)")
            }
        }
    }
}
