import UIKit
import XCTest
@testable import Barking

/// Foundations of the UI review (B1): the states of the shared components,
/// read from the same tables the views draw with.
@MainActor
final class ComponentTests: XCTestCase {
    private func color(_ name: String, _ style: UIUserInterfaceStyle) -> UIColor {
        let traits = UITraitCollection(userInterfaceStyle: style)
        guard let c = UIColor(named: name, in: Bundle.main, compatibleWith: traits) else {
            XCTFail("missing color \(name)")
            return .clear
        }
        return c.resolvedColor(with: traits)
    }

    // MARK: Fingerprint

    func testFingerprintShortIsFourGroupsWithAMiddleDot() {
        let fp = "zab2-2ccf-kzfa-fsms-q7ws-a2bd-3k1x-pp0e"
        XCTAssertEqual(FingerprintFormat.grouped(fp, form: .short), "zab2 2ccf\u{00A0}· kzfa fsms")
    }

    func testFingerprintFullPutsADotEveryTwoGroups() {
        let fp = "zab2-2ccf-kzfa-fsms-q7ws"
        XCTAssertEqual(FingerprintFormat.grouped(fp, form: .full),
                       "zab2 2ccf\u{00A0}· kzfa fsms\u{00A0}· q7ws")
    }

    func testFingerprintWithoutDashesIsCutInFours() {
        XCTAssertEqual(FingerprintFormat.grouped("zab22ccfkzfafsms", form: .full), "zab2 2ccf\u{00A0}· kzfa fsms")
        XCTAssertEqual(FingerprintFormat.grouped("ZAB2 2ccf · kzfa", form: .full), "zab2 2ccf\u{00A0}· kzfa")
    }

    /// Too short for four groups: shown as it is, never padded.
    func testShortFingerprintStaysAsIs() {
        XCTAssertEqual(FingerprintFormat.grouped("zab2-2ccf", form: .short), "zab2-2ccf")
        XCTAssertEqual(FingerprintFormat.grouped("", form: .full), "")
    }

    /// VoiceOver reads one group at a time, character by character.
    func testFingerprintSpokenGroupByGroup() {
        XCTAssertEqual(FingerprintFormat.spoken("zab2-2ccf-kzfa-fsms-q7ws", form: .short),
                       "z a b 2, 2 c c f, k z f a, f s m s")
    }

    /// The models that showed a short fingerprint keep the same text.
    func testModelsUseTheSharedFormat() {
        let fp = "zab2-2ccf-kzfa-fsms-q7ws"
        XCTAssertEqual(FingerprintFormat.grouped(fp, form: .short).replacingOccurrences(of: "\u{00A0}", with: " "),
                       "zab2 2ccf · kzfa fsms")
    }

    // MARK: Buttons

    func testDisabledButtonsAreNeverATranslucentPurple() {
        for kind in [ButtonKind.primary, .secondary, .danger] {
            let t = ButtonTokens.of(kind, .disabled)
            XCTAssertEqual(t.fill, "fillDisabled", "\(kind)")
            XCTAssertEqual(t.label, "fgDisabled", "\(kind)")
            XCTAssertEqual(t.border, "borderDisabled", "\(kind)")
        }
    }

    func testEveryButtonStateIsReadable() {
        for style in [UIUserInterfaceStyle.light, .dark] {
            for kind in [ButtonKind.primary, .secondary, .danger] {
                for state in [ButtonState.enabled, .disabled, .loading] {
                    let t = ButtonTokens.of(kind, state)
                    let label = t.label == "white" ? UIColor.white : color(t.label, style)
                    // An unfilled button sits on a card or the ground: check both.
                    for ground in t.fill.map({ [$0] }) ?? ["surface", "surfaceCard"] {
                        let r = DesignSystemTests.ratio(label, color(ground, style))
                        XCTAssertGreaterThanOrEqual(r, 4.5, "\(kind) \(state) \(t.label) on \(ground) \(style.rawValue): \(r)")
                    }
                }
            }
        }
    }

    func testButtonStateFromFlags() {
        XCTAssertEqual(ButtonState(enabled: true, isLoading: false), .enabled)
        XCTAssertEqual(ButtonState(enabled: false, isLoading: false), .disabled)
        // Loading wins: the action already runs.
        XCTAssertEqual(ButtonState(enabled: true, isLoading: true), .loading)
        XCTAssertEqual(ButtonState(enabled: false, isLoading: true), .loading)
        XCTAssertTrue(ButtonState.enabled.isInteractive)
        XCTAssertFalse(ButtonState.disabled.isInteractive)
        XCTAssertFalse(ButtonState.loading.isInteractive)
    }

    func testDangerButtonIsOutlinedInDanger() {
        let t = ButtonTokens.of(.danger, .enabled)
        XCTAssertNil(t.fill)
        XCTAssertEqual(t.label, "danger")
        XCTAssertEqual(t.border, "danger")
    }

    // MARK: Status and tags

    /// Status is a glyph plus a word: each state has its own glyph or
    /// colour, and offline is amber, never red.
    func testStatusDotGlyphsAndColours() {
        XCTAssertEqual(StatusDot.State.ok.glyph, "●")
        XCTAssertEqual(StatusDot.State.ok.token, "ok")
        XCTAssertEqual(StatusDot.State.waiting.glyph, "○")
        XCTAssertEqual(StatusDot.State.waiting.token, "warnFg")
        XCTAssertEqual(StatusDot.State.checking.glyph, "○")
        XCTAssertEqual(StatusDot.State.checking.token, "fgSoft")
        XCTAssertEqual(StatusDot.State.down.glyph, "✗")
        XCTAssertEqual(StatusDot.State.down.token, "danger")
    }

    func testTagsAreReadable() {
        for style in [UIUserInterfaceStyle.light, .dark] {
            for s in [Tag.Style.accent, .neutral, .ok, .danger] {
                let r = DesignSystemTests.ratio(color(s.tokens.text, style), color(s.tokens.fill, style))
                XCTAssertGreaterThanOrEqual(r, 4.5, "tag \(s) \(style.rawValue): \(r)")
            }
        }
    }

    // MARK: Navigation bar

    func testNavigationTitlesUseFiraCode() throws {
        BarkingNavigationAppearance.apply()
        let a = UINavigationBar.appearance().standardAppearance
        let large = try XCTUnwrap(a.largeTitleTextAttributes[.font] as? UIFont)
        let inline = try XCTUnwrap(a.titleTextAttributes[.font] as? UIFont)
        XCTAssertEqual(large.fontName, "FiraCode-SemiBold")
        XCTAssertEqual(inline.fontName, "FiraCode-SemiBold")
        XCTAssertGreaterThanOrEqual(large.pointSize, 30 * 0.8)
        XCTAssertLessThan(inline.pointSize, large.pointSize)
        XCTAssertEqual(a.largeTitleTextAttributes[.kern] as? CGFloat, -0.5)
        XCTAssertEqual((UINavigationBar.appearance().compactAppearance?.titleTextAttributes[.font] as? UIFont)?.fontName,
                       "FiraCode-SemiBold")
    }

    // MARK: Motion

    func testMotionIsNilUnderReduceMotion() {
        XCTAssertNil(Motion.gated(Motion.feedback, reduceMotion: true))
        XCTAssertNotNil(Motion.gated(Motion.enter, reduceMotion: false))
    }
}
