import XCTest
@testable import Barking
@testable import BarkingKit

/// The composer's disappearing-delay picker (spec iOS deletion/ephemeral §5.5).
@MainActor
final class EphemeralPickerTests: XCTestCase {
    private let fr = (bundle: Bundle.strings(for: Locale(identifier: "fr")), locale: Locale(identifier: "fr"))
    private let en = (bundle: Bundle.strings(for: Locale(identifier: "en")), locale: Locale(identifier: "en"))

    private func make(_ d: FakeDevice, name: String = "Bob") -> ConversationModel {
        d.contactList = [Contact(fingerprint: "b", alias: nil, displayName: name, verified: false)]
        return ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
    }

    func testPresets() {
        XCTAssertEqual(EphemeralDelay.presets.map(\.seconds), [300, 3600, 86400, 604_800])
    }

    func testCustomBounds() {
        XCTAssertNil(EphemeralDelay.custom(days: 0, hours: 0, minutes: 0))
        XCTAssertEqual(EphemeralDelay.custom(days: 0, hours: 0, minutes: 1)?.seconds, 60)
        XCTAssertEqual(EphemeralDelay.custom(days: 7, hours: 0, minutes: 0)?.seconds, 604_800)
        XCTAssertNil(EphemeralDelay.custom(days: 7, hours: 0, minutes: 1))
        XCTAssertEqual(EphemeralDelay.custom(days: 1, hours: 2, minutes: 3)?.seconds, 86_400 + 7_200 + 180)
        XCTAssertNil(EphemeralDelay.custom(days: -1, hours: 0, minutes: 5), "a negative part is refused")
    }

    func testShortLabels() {
        let labels = EphemeralDelay.presets.map { $0.shortLabel(bundle: en.bundle, locale: en.locale) }
        XCTAssertEqual(labels, ["5 min", "1 h", "1 d", "7 d"])
        let custom = EphemeralDelay.custom(days: 1, hours: 2, minutes: 3)
        XCTAssertEqual(custom?.shortLabel(bundle: fr.bundle, locale: fr.locale), "1\u{00A0}j 2\u{00A0}h 3\u{00A0}min")
        XCTAssertEqual(EphemeralDelay.presets[0].shortLabel(bundle: fr.bundle, locale: fr.locale), "5\u{00A0}min")
    }

    func testLongLabelsArePlural() {
        func label(_ d: Int, _ h: Int, _ m: Int, _ l: (bundle: Bundle, locale: Locale)) -> String? {
            EphemeralDelay.custom(days: d, hours: h, minutes: m)?.longLabel(bundle: l.bundle, locale: l.locale)
        }
        XCTAssertEqual(label(0, 1, 0, en), "1 hour")
        XCTAssertEqual(label(0, 3, 0, en), "3 hours")
        XCTAssertEqual(label(2, 0, 0, en), "2 days")
        XCTAssertEqual(label(1, 0, 0, fr), "1 jour")
        XCTAssertEqual(label(0, 3, 0, fr), "3 heures")
        XCTAssertEqual(label(0, 0, 5, fr), "5\u{00A0}min")
        XCTAssertEqual(label(1, 2, 0, fr), "1 jour 2 heures")
    }

    func testSendResetsDelay() async {
        let d = FakeDevice()
        let m = make(d)
        await m.onAppear()
        m.ttl = 300
        m.draft = "hello"
        await m.send()
        XCTAssertEqual(d.sentTtls.count, 1)
        XCTAssertEqual(d.sentTtls.first ?? nil, 300)
        XCTAssertNil(m.ttl)
        m.draft = "again"
        await m.send()
        XCTAssertEqual(d.sentTtls.last ?? 0, nil, "the next send has no delay")
    }

    func testFailedSendKeepsDelay() async {
        let d = FakeDevice()
        d.sendError = BarkingError.Locked
        let m = make(d)
        await m.onAppear()
        m.ttl = 3600
        m.draft = "hello"
        await m.send()
        XCTAssertEqual(m.ttl, 3600, "the draft is kept, so is its delay")
    }

    func testDelayResetWhenTheConversationDisappears() async {
        let m = make(FakeDevice())
        await m.onAppear()
        m.ttl = 300
        m.onDisappear()
        XCTAssertNil(m.ttl)
    }

    func testDelayNotInDraft() async {
        let d = FakeDevice()
        let m = make(d)
        await m.onAppear()
        m.ttl = 300
        m.draft = "brouillon"
        await m.saveDraft()
        XCTAssertEqual(d.drafts["b"], "brouillon", "only the text is stored")
        let again = make(d)
        await again.onAppear()
        XCTAssertEqual(again.draft, "brouillon")
        XCTAssertNil(again.ttl)
    }

    func testBannerCopyFR() async {
        let m = make(FakeDevice(), name: "Alice")
        await m.onAppear()
        XCTAssertNil(m.ephemeralBanner(bundle: fr.bundle, locale: fr.locale), "no delay, no banner")
        m.ttl = 300
        XCTAssertEqual(m.ephemeralBanner(bundle: fr.bundle, locale: fr.locale),
                       "S’efface 5\u{00A0}min après l’envoi chez vous, 5\u{00A0}min après lecture chez Alice. Alice peut faire une capture d’écran.")
        m.ttl = 7200
        XCTAssertEqual(m.ephemeralBanner(bundle: en.bundle, locale: en.locale),
                       "Disappears 2 hours after sending for you, 2 hours after reading for Alice. Alice can take a screenshot.")
    }

    func testMenuAndSheetStringsExistInBothLanguages() {
        for key in ["No delay", "5 min", "1 hour", "1 day", "1 week", "Custom…", "Custom delay", "Set"] {
            XCTAssertNotEqual(fr.bundle.localizedString(forKey: key, value: "\u{0}", table: nil), "\u{0}", "French for \(key)")
        }
        XCTAssertEqual(fr.bundle.localizedString(forKey: "Custom…", value: nil, table: nil), "Personnalisé…")
        XCTAssertEqual(fr.bundle.localizedString(forKey: "Set", value: nil, table: nil), "Choisir")
    }
}
