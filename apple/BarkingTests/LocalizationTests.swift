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
    /// English and a French text (in Log.strings, or Log.stringsdict for a
    /// plural), with the same placeholders.
    func testEveryLogKeyHasBothLanguages() throws {
        let keys = logKeys() + logArgTokens().map { "log.arg.\($0)" }
        XCTAssertGreaterThanOrEqual(logKeys().count, 26)
        XCTAssertGreaterThanOrEqual(logArgTokens().count, 31)
        let placeholders = { (s: String) in
            s.matches(of: /%(\d)\$@/).map { String($0.output.1) }.sorted()
        }
        var texts: [String: [String: String]] = [:]
        for lang in ["en", "fr"] {
            let strings = try XCTUnwrap(table(lang, "Log"))
            let plurals = table(lang, "Log", "stringsdict")
            for key in keys {
                var text = strings[key] as? String ?? ""
                if text.isEmpty, let rule = (plurals?[key] as? NSDictionary)?["count"] as? NSDictionary {
                    XCTAssertNotNil(rule["one"], "\(lang) \(key) one")
                    text = rule["other"] as? String ?? ""
                }
                XCTAssertFalse(text.isEmpty, "no \(lang) text for \(key)")
                texts[key, default: [:]][lang] = text
            }
        }
        for (key, t) in texts {
            XCTAssertEqual(placeholders(t["en"] ?? ""), placeholders(t["fr"] ?? ""), "placeholders of \(key)")
        }
    }

    func testTransparencyStringsInFrench() throws {
        let fr = try XCTUnwrap(table("fr"))
        for key in ["Transparency", "Everything", "Keys and devices", "Change the lock",
                    "Keys and devices: key changes, devices added or removed, unreadable messages — the events to watch first.", "Where my data is", "Devices",
                    "Database key protected by the Secure Enclave", "Database key protected by the keychain only",
                    "Nothing yet", "Today", "Yesterday", "Wrapped by a key that never leaves this iPhone's chip.",
                    "Kept in the keychain, without the Secure Enclave.",
                    "Your contacts and messages are kept here, encrypted with SQLCipher.",
                    "Tap to show the whole text"] {
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

    /// Final review 6: logged before the new list leaves, the removal cannot
    /// say the contacts already stopped encrypting for the device.
    func testDeviceRemovedSaysOnceTheyReceiveTheList() throws {
        let en = try XCTUnwrap(table("en", "Log")?["log.device_removed"] as? String)
        let fr = try XCTUnwrap(table("fr", "Log")?["log.device_removed"] as? String)
        XCTAssertTrue(en.contains("will no longer encrypt anything for it once they receive the new device list"), en)
        XCTAssertTrue(fr.contains("ne chiffreront plus rien pour lui dès qu’ils auront reçu la nouvelle liste d’appareils"), fr)
    }

    /// Final review 8, 9: new texts have French.
    func testFinalReviewStringsInFrench() throws {
        let fr = try XCTUnwrap(table("fr"))
        for key in ["Barking could not finish erasing. Try again.", "Disconnect %@?"] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
    }

    /// UI review B2: every new form text has French, and the strings the
    /// forms dropped are gone.
    func testFormStringsInFrench() throws {
        let fr = try XCTUnwrap(table("fr"))
        for key in ["Type your name to continue.", "Name this device to continue.", "Your name",
                    "Shown on your other devices, and to your contacts in your card.", "Recovery phrase",
                    "Suggested password", "Type my own password", "Hidden", "Show", "Hide", "Copied", "Paste",
                    "too weak", "strong", "Password strength", "strong, accepted", "too weak, not accepted",
                    "Edit", "Save", "Saved", "Not saved. Try again.", "Show larger",
                    "My QR code. A contact scans it to add you.",
                    "After adding, compare the safety code with %@ to be sure it is them.",
                    "The camera is not available. Linking needs it to scan your other device's code.",
                    "Address", "Lock after", "Immediately"] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
        XCTAssertEqual(fr["Type your name to continue."] as? String, "Indiquez votre nom pour continuer.")
        // Fix round 1: the PDF reason, the alias failure, natural French for the footer.
        XCTAssertEqual(fr["Choose a password to continue."] as? String, "Choisissez un mot de passe pour continuer.")
        XCTAssertEqual(fr["Shown on your other devices, and to your contacts in your card."] as? String,
                       "Affiché sur vos autres appareils, et transmis à vos contacts dans votre carte.")
        for unused in ["how your messages travel", "weak", "fair", "Your name, as contacts see it"] {
            XCTAssertNil(fr[unused], "unused French string \(unused)")
        }
    }

    /// UI review B3: the safety-code flow, the danger zones and the hold.
    func testSafetyStringsInFrench() throws {
        let fr = try XCTUnwrap(table("fr"))
        for key in ["Verify", "Verified", "The numbers do not match",
                    "Don't send anything sensitive yet. Compare again in person or on a call you trust.",
                    "The history is kept.", "Asks for confirmation first."] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
        // Review B3 #10: a section label, not a command.
        XCTAssertEqual(fr["Verify"] as? String, "Vérification")
        XCTAssertEqual(fr["Don't send anything sensitive yet. Compare again in person or on a call you trust."] as? String,
                       "N’envoyez encore rien de sensible. Comparez à nouveau en personne ou lors d’un appel de confiance.")
        // The mismatch is a sheet now, and the verified banner has no Undo.
        for unused in ["Do not trust this contact until you meet", "✓ Contact marked as verified"] {
            XCTAssertNil(fr[unused], "unused French string \(unused)")
        }
    }
}
