import SwiftUI
import UIKit
import XCTest
@testable import Barking

/// Forms and fields of the UI review (B2): the states the views draw with,
/// read from the same tables.
@MainActor
final class FormComponentTests: XCTestCase {
    private func color(_ name: String, _ style: UIUserInterfaceStyle) -> UIColor {
        let traits = UITraitCollection(userInterfaceStyle: style)
        guard let c = UIColor(named: name, in: Bundle.main, compatibleWith: traits) else {
            XCTFail("missing color \(name)")
            return .clear
        }
        return c.resolvedColor(with: traits)
    }

    // MARK: Text field

    /// A slot on `field`; focus draws a 1.5 pt ring, an error a `danger`
    /// one (an error wins over focus), never colour alone (the error line
    /// says it in words).
    func testFieldStates() {
        XCTAssertEqual(FieldTokens.of(.idle), FieldTokens(fill: "field", text: "fg", prompt: "fgSoft", border: nil, borderWidth: 0))
        XCTAssertEqual(FieldTokens.of(.focused).border, "focusRing")
        XCTAssertEqual(FieldTokens.of(.focused).borderWidth, 1.5)
        XCTAssertEqual(FieldTokens.of(.error).border, "danger")
        XCTAssertEqual(FieldState(focused: true, hasError: true), .error)
        XCTAssertEqual(FieldState(focused: true, hasError: false), .focused)
        XCTAssertEqual(FieldState(focused: false, hasError: false), .idle)
    }

    func testFieldTextIsReadable() {
        for style in [UIUserInterfaceStyle.light, .dark] {
            for state in [FieldState.idle, .focused, .error] {
                let t = FieldTokens.of(state)
                for text in [t.text, t.prompt] {
                    let r = DesignSystemTests.ratio(color(text, style), color(t.fill, style))
                    XCTAssertGreaterThanOrEqual(r, 4.5, "\(text) on \(t.fill) \(style.rawValue): \(r)")
                }
                if let b = t.border {
                    XCTAssertGreaterThanOrEqual(DesignSystemTests.ratio(color(b, style), color("surface", style)), 3,
                                                "\(b) ring on surface")
                }
            }
        }
    }

    // MARK: Rows and segmented control

    func testFormRowHeights() {
        XCTAssertEqual(FormRowMetrics.minHeight(hasSubtitle: false), 44)
        XCTAssertEqual(FormRowMetrics.minHeight(hasSubtitle: true), 56)
        XCTAssertEqual(FormRowMetrics.inset, 16)
    }

    /// Labels never truncate: at accessibility sizes the segments become a
    /// menu.
    func testSegmentedFallsBackToAMenuAtAccessibilitySizes() {
        XCTAssertFalse(SegmentedMetrics.usesMenu(.large))
        XCTAssertFalse(SegmentedMetrics.usesMenu(.xxxLarge))
        XCTAssertTrue(SegmentedMetrics.usesMenu(.accessibility1))
        XCTAssertTrue(SegmentedMetrics.usesMenu(.accessibility3))
    }

    // MARK: Tags

    /// A tag longer than the row wraps inside the width it is given
    /// instead of overflowing the layout.
    func testLongTagStaysInsideItsFlowLayout() {
        let view = FlowLayout {
            Tag(verbatim: "envoyé 12:01 · accusé de réception 12:02 · lu 12:03 par Sam", style: .neutral)
            Tag(verbatim: "admin")
        }
        .environment(\.dynamicTypeSize, .accessibility3)
        let size = UIHostingController(rootView: view).sizeThatFits(in: CGSize(width: 200, height: 2000))
        XCTAssertLessThanOrEqual(size.width, 200.5, "tag overflows: \(size)")
    }

    // MARK: PDF password

    /// The meter follows the gate: whatever the gate refuses reads "too
    /// weak" (1 or 2 bars), only what it accepts reads "strong" (3 bars).
    func testStrengthVerdictFollowsTheGate() {
        XCTAssertEqual(PhraseExport.verdict(""), .empty)
        XCTAssertEqual(PhraseExport.verdict("abc"), .tooWeak(bars: 1))
        // 2 on the rough estimate, refused by the gate: "fair" used to show.
        XCTAssertEqual(PhraseExport.strength("password1234"), 2)
        XCTAssertEqual(PhraseExport.verdict("password1234"), .tooWeak(bars: 2))
        // Strong characters, but shorter than the gate's 12.
        XCTAssertEqual(PhraseExport.verdict("aB3$eF6&hI9"), .tooWeak(bars: 2))
        let suggested = PhraseExport.suggestedPassword(from: ["alpha", "bravo", "cobalt", "delta", "ember", "fjord", "gamma"])
        XCTAssertEqual(PhraseExport.verdict(suggested), .strong)
        for p in ["", "abc", "password1234", "aB3$eF6&hI9", suggested] {
            XCTAssertEqual(PhraseExport.verdict(p) == .strong, PhraseExport.problem(p, p) == nil, p)
        }
    }

    /// A copied password stays on this iPhone (no Universal Clipboard) and
    /// leaves the pasteboard after two minutes.
    func testCopiedSecretIsLocalAndExpires() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let o = SecretPasteboard.options(now: now)
        XCTAssertEqual(o[.localOnly] as? Bool, true)
        XCTAssertEqual(try XCTUnwrap(o[.expirationDate] as? Date), now.addingTimeInterval(120))
    }
}
