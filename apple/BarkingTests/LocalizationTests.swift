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
                    "Keys and devices: key changes, devices added or removed, unreadable messages. These are the events to watch first.", "Where my data is", "Devices",
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

    /// UI review B4: messaging and status strings land in both languages.
    func testMessagingStringsInFrench() throws {
        let fr = try XCTUnwrap(table("fr"))
        let frPlurals = try XCTUnwrap(table("fr", "Localizable", "stringsdict"))
        let enPlurals = try XCTUnwrap(table("en", "Localizable", "stringsdict"))
        for key in ["Pick one word per row.", "See the 24 words again", "Word %lld", "Recover (%lld/24)",
                    "Word %lld is not in the word list.", "Check now",
                    "Opens the 3-word check.", "Check three words while you still have your copy.",
                    "Opens the safety code.", "verified", "not verified", "Unreachable · nothing is lost",
                    "Checking…", "Up to date", "Still unreachable · nothing waits", "%lld KB", "expires %@"] where fr[key] == nil {
            XCTFail("missing French for \(key)")
        }
        for key in ["Still unreachable · %lld packets wait", "Sent %lld packets", "%lld messages received"] {
            XCTAssertNotNil(frPlurals[key], "missing French plural for \(key)")
            XCTAssertNotNil(enPlurals[key], "missing English plural for \(key)")
        }
        XCTAssertEqual(fr["%lld KB"] as? String, "%lld Ko")
        for unused in ["Word no. %lld", "Check three words before you close the app.", "Unreachable", "word", "Recover"] {
            XCTAssertNil(fr[unused], "unused French string \(unused)")
        }
    }

    /// Every journal title exists in English and French (Log.strings).
    func testEveryLogTitleHasBothLanguages() throws {
        for lang in ["en", "fr"] {
            let strings = try XCTUnwrap(table(lang, "Log"))
            for key in logKeys() where key != "log.packet_sealed" {
                XCTAssertNotNil(strings["log.title.\(key.dropFirst(4))"], "\(lang) title of \(key)")
            }
            for variant in ["intro_mailbox", "daily_mailbox"] {
                XCTAssertNotNil(strings["log.title.packet_sealed.\(variant)"], "\(lang) packet title \(variant)")
            }
            XCTAssertNotNil(strings["log.body.packet_sealed"], "\(lang) packet body")
        }
    }

    /// Review B4 fix round: the paste lines, the wording nits, and no key
    /// written twice in the French table (a later edit to one copy would
    /// be shadowed by the other).
    func testFixRoundStringsInFrench() throws {
        let fr = try XCTUnwrap(table("fr"))
        let frPlurals = try XCTUnwrap(table("fr", "Localizable", "stringsdict"))
        let enPlurals = try XCTUnwrap(table("en", "Localizable", "stringsdict"))
        for key in ["The clipboard holds no words.", "Pasted. The clipboard was cleared.", "Pasted."] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
        let found = "Found %lld words; 24 are needed. The clipboard was cleared."
        XCTAssertNotNil(frPlurals[found])
        XCTAssertNotNil(enPlurals[found])
        XCTAssertEqual(fr["Still unreachable · nothing waits"] as? String, "Toujours injoignable · rien en attente")
        for lang in ["en", "fr"] {
            let log = try XCTUnwrap(table(lang, "Log"))
            XCTAssertEqual(log["log.title.seal_skipped"] as? String,
                           lang == "en" ? "Not encrypted for a device of %1$@" : "Non chiffré pour un appareil de %1$@")
        }
        // The bundle's copy is compiled; read the keys from the source.
        let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Barking/fr.lproj/Localizable.strings")
        let text = try String(contentsOf: source, encoding: .utf8)
        let keys = text.split(separator: "\n").compactMap { line -> String? in
            guard line.hasPrefix("\""), let end = line.dropFirst().firstIndex(of: "\"") else { return nil }
            return String(line[line.index(after: line.startIndex)..<end])
        }
        let dupes = Dictionary(grouping: keys, by: { $0 }).filter { $0.value.count > 1 }.keys
        XCTAssertTrue(dupes.isEmpty, "French keys written twice: \(dupes.sorted())")
    }

    /// UI review B5: no em-dash in any user-facing text (U-39), the words
    /// left on Recover as a plural (one and other, EN and FR), and the new
    /// link-sheet and paste lines in French.
    func testPolishStrings() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        for lang in ["en", "fr"] {
            for name in ["Localizable", "Log"] {
                for type in ["strings", "stringsdict"] {
                    guard let t = table(lang, name, type) else { continue }
                    let text = "\(t)"
                    XCTAssertFalse(text.contains("—"), "em-dash in \(lang) \(name).\(type)")
                }
            }
        }
        // String literals in the app's Swift code (comments may keep theirs).
        let files = FileManager.default.enumerator(at: root.appendingPathComponent("Barking"), includingPropertiesForKeys: nil)?
            .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" } ?? []
        XCTAssertGreaterThan(files.count, 40)
        for file in files {
            let lines = try String(contentsOf: file, encoding: .utf8).split(separator: "\n")
            for line in lines {
                let code = line.components(separatedBy: "//").first ?? ""
                XCTAssertFalse(code.contains("—"), "em-dash in \(file.lastPathComponent): \(line)")
            }
        }
        for lang in ["en", "fr"] {
            let plurals = try XCTUnwrap(table(lang, "Localizable", "stringsdict"))
            let rule = try XCTUnwrap((plurals["%lld words left to fill in."] as? NSDictionary)?["n"] as? NSDictionary, lang)
            XCTAssertEqual(rule["one"] as? String, lang == "en" ? "%lld word left to fill in." : "Encore %lld mot à saisir.")
            XCTAssertEqual(rule["other"] as? String, lang == "en" ? "%lld words left to fill in." : "Encore %lld mots à saisir.")
            let found = try XCTUnwrap((plurals["Found %lld words; 24 are needed."] as? NSDictionary)?["n"] as? NSDictionary, lang)
            XCTAssertNotNil(found["one"])
        }
        let fr = try XCTUnwrap(table("fr"))
        XCTAssertNil(fr["Words left to fill in: %lld."], "the old reason is gone")
        XCTAssertNil(fr["The clipboard holds no text."], "the old paste line is gone")
        for unused in ["⚠︎ not sent, tap to retry", "queued", "not sent"] {
            XCTAssertNil(fr[unused], "unused French string \(unused)")
        }
        XCTAssertEqual(fr["Link this device"] as? String, "Lier cet appareil")
        XCTAssertEqual(fr["Link a device"] as? String, "Lier un appareil")
        XCTAssertEqual(fr["Nothing was pasted."] as? String, "Rien n’a été collé.")
        XCTAssertEqual(fr["The clipboard holds no words."] as? String, "Le presse-papiers ne contient aucun mot.")
        for key in ["Pasted.", "Expires in %@ · usable once", "Valid until %@ and usable once.", "This code has expired.", "New code",
                    "On the new device, tap Link to an existing device and scan this code.",
                    "Then tap Scan the new device's code and scan the code it shows.",
                    "Link code. The new device scans it.",
                    "everything: it is the sender.", "everything: it is the recipient."] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
    }

    /// Spec Lot M §7.1: the bubble's states, menu, VoiceOver values and
    /// announcements, in both languages.
    func testDeliveryBubbleStrings() throws {
        let fr = try XCTUnwrap(table("fr"))
        let expected: [String: String] = [
            "Pending": "En attente", "On the network": "Sur le réseau", "Received": "Reçu",
            "Not delivered": "Non distribué", "Retry": "Réessayer",
            "Copy": "Copier", "Details": "Détails", "Delete": "Supprimer", "Deliveries": "Envois",
            "Pending since %@": "En attente depuis %@", "On the network since %@": "Sur le réseau depuis %@",
            "Received at %@": "Reçu à %@", "Not delivered. Expired at %@.": "Non distribué. Expiré à %@.",
            "Sent from another of your devices": "Envoyé depuis un autre de vos appareils",
            "Opens the message details.": "Ouvre le détail du message.",
            "Message received by %@.": "Message reçu par %@.",
            "Message not delivered. Retry is in the actions.": "Message non distribué. Réessayer est dans les actions.",
            "Keep": "Garder",
        ]
        for (key, value) in expected {
            XCTAssertEqual(fr[key] as? String, value, key)
        }
        for lang in ["en", "fr"] {
            let plurals = try XCTUnwrap(table(lang, "Localizable", "stringsdict"))
            for key in ["%lld messages received by %@.", "Received at %@, on %lld of %lld devices"] {
                XCTAssertNotNil(plurals[key], "\(lang) plural \(key)")
            }
        }
        let en = "%lld messages received by %@."
        XCTAssertEqual(String.localizedStringWithFormat(NSLocalizedString(en, comment: ""), 2, "Sam"), "2 messages received by Sam.")
    }

    /// Spec Lot M §7.2: the message sheet, in French, with a non-breaking
    /// space before the colon; its numbers through the stringsdict.
    func testMessageSheetStrings() throws {
        let fr = try XCTUnwrap(table("fr"))
        let expected: [String: String] = [
            "Show all": "Tout afficher", "Delivery": "Acheminement",
            "Sealed and saved on this iPhone": "Scellé et enregistré sur cet iPhone",
            "Deposited on relay %@": "Déposé sur le relais %@", "Deposited on a relay": "Déposé sur un relais",
            "Received on all their devices": "Reçu sur tous ses appareils",
            "%@’s devices": "Appareils de %@", "Removed device": "Appareil retiré",
            "pending": "en attente", "not delivered": "non distribué", "on the network %@": "sur le réseau %@",
            "Copy for your other devices: pending.": "Copie pour vos autres appareils\u{00A0}: en attente.",
            "Sent from another of your devices. Its delivery is tracked there.":
                "Envoyé depuis un autre de vos appareils. Son acheminement est suivi là-bas.",
            "Delete message": "Supprimer le message",
            "Details unavailable. The message itself is unchanged.": "Détails indisponibles. Le message lui-même n’a pas changé.",
            "everything: it is the sender.": "tout\u{00A0}: c’est l’expéditeur.",
            "None of %@’s devices picked it up within 24 hours. The relay erased it on %@.":
                "Aucun appareil de %1$@ ne l’a relevé en 24\u{00A0}h. Le relais l’a effacé le %2$@.",
            "None of %@’s devices picked it up within 24 hours. The relay erased it.":
                "Aucun appareil de %@ ne l’a relevé en 24\u{00A0}h. Le relais l’a effacé.",
            "Expired before a relay accepted it. It never left this iPhone.":
                "Expiré avant qu’un relais l’accepte. Il n’a jamais quitté cet iPhone.",
            "Could see: a sealed packet of %@ for a mailbox that changes every day. Not the sender, not the text. The IP address of whoever deposited it.":
                "A pu voir\u{00A0}: un paquet scellé de %@ pour une boîte aux lettres qui change chaque jour. Ni l’expéditeur, ni le texte. L’adresse IP de qui l’a déposé.",
            "Could see: a sealed packet for a mailbox that changes every day. Not the sender, not the text. The IP address of whoever deposited it.":
                "A pu voir\u{00A0}: un paquet scellé pour une boîte aux lettres qui change chaque jour. Ni l’expéditeur, ni le texte. L’adresse IP de qui l’a déposé.",
        ]
        for (key, value) in expected {
            XCTAssertEqual(fr[key] as? String, value, key)
        }
        for lang in ["en", "fr"] {
            let plurals = try XCTUnwrap(table(lang, "Localizable", "stringsdict"))
            for key in ["%lld devices · %@", "%lld devices", "Received on %lld of %lld devices",
                        "Received on %lld of %lld devices."] {
                XCTAssertNotNil(plurals[key], "\(lang) plural \(key)")
            }
        }
    }

    /// No em dash (U+2014) in the EN and FR string tables, read from the sources.
    func testNoEmDashInStrings() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        var read = 0
        for lang in ["en", "fr"] {
            for file in ["Localizable.strings", "Localizable.stringsdict", "Log.strings", "Log.stringsdict"] {
                let url = root.appendingPathComponent("Barking/\(lang).lproj/\(file)")
                guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
                read += 1
                for (n, line) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated()
                where line.contains("\u{2014}") {
                    XCTFail("em dash in \(lang)/\(file):\(n + 1): \(line)")
                }
            }
        }
        XCTAssertEqual(read, 8)
    }
}
