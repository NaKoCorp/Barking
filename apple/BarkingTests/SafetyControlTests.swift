import SwiftUI
import UIKit
import XCTest
@testable import Barking

/// Safety-critical controls of the UI review (B3): the hold to erase, the
/// danger zones, the lock-screen tile and the haptic map.
@MainActor
final class SafetyControlTests: XCTestCase {
    private func hex(_ name: String, _ style: UIUserInterfaceStyle) -> String {
        let traits = UITraitCollection(userInterfaceStyle: style)
        guard let c = UIColor(named: name, in: Bundle.main, compatibleWith: traits)?.resolvedColor(with: traits) else {
            XCTFail("missing color \(name)")
            return ""
        }
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        c.getRed(&r, green: &g, blue: &b, alpha: &a)
        return String(format: "#%02X%02X%02X", Int((r * 255).rounded()), Int((g * 255).rounded()), Int((b * 255).rounded()))
    }

    // MARK: Hold to confirm

    /// The sweep follows the finger; under Reduce Motion a counter says the
    /// seconds left ("2… 1…") and nothing moves.
    func testHoldIndicator() {
        XCTAssertEqual(HoldIndicator.of(elapsed: nil, duration: 2, reduceMotion: false), .idle)
        XCTAssertEqual(HoldIndicator.of(elapsed: nil, duration: 2, reduceMotion: true), .idle)
        XCTAssertEqual(HoldIndicator.of(elapsed: 0, duration: 2, reduceMotion: false), .sweep(0))
        XCTAssertEqual(HoldIndicator.of(elapsed: 0.5, duration: 2, reduceMotion: false), .sweep(0.25))
        XCTAssertEqual(HoldIndicator.of(elapsed: 3, duration: 2, reduceMotion: false), .sweep(1))
        XCTAssertEqual(HoldIndicator.of(elapsed: 0, duration: 2, reduceMotion: true), .counter(2))
        XCTAssertEqual(HoldIndicator.of(elapsed: 0.9, duration: 2, reduceMotion: true), .counter(2))
        XCTAssertEqual(HoldIndicator.of(elapsed: 1.2, duration: 2, reduceMotion: true), .counter(1))
        XCTAssertEqual(HoldIndicator.of(elapsed: 2.5, duration: 2, reduceMotion: true), .counter(1))
    }

    /// Where the sweep has passed the label swaps to `surface` on solid
    /// `danger`: the pair stays at 4.5:1 in both themes.
    func testHoldSweepKeepsTheLabelReadable() {
        XCTAssertEqual(HoldMetrics.sweepFill, "danger")
        XCTAssertEqual(HoldMetrics.labelOnSweep, "surface")
        for style in [UIUserInterfaceStyle.light, .dark] {
            let traits = UITraitCollection(userInterfaceStyle: style)
            let fill = UIColor(named: HoldMetrics.sweepFill, in: Bundle.main, compatibleWith: traits)!.resolvedColor(with: traits)
            let label = UIColor(named: HoldMetrics.labelOnSweep, in: Bundle.main, compatibleWith: traits)!.resolvedColor(with: traits)
            let r = DesignSystemTests.ratio(label, fill)
            XCTAssertGreaterThanOrEqual(r, 4.5, "label on the sweep \(style.rawValue): \(r)")
        }
    }

    /// VoiceOver cannot hold for 2 s: a double-tap (the default action) and
    /// a named custom action open the same confirmation as the hold.
    func testHoldToConfirmHasVoiceOverActions() throws {
        var confirmed = 0
        let button = HoldToConfirmButton("Erase Barking", hint: "Press and hold for 2 seconds",
                                         identifier: "probe") { confirmed += 1 }
        let node = try XCTUnwrap(AccessibilityProbe.element(labelled: "Erase Barking", in: button))
        XCTAssertTrue(node.accessibilityTraits.contains(.button))
        let actions = node.accessibilityCustomActions ?? []
        XCTAssertEqual(actions.map(\.name), ["Erase Barking"])
        XCTAssertTrue(AccessibilityProbe.perform(try XCTUnwrap(actions.first)))
        XCTAssertEqual(confirmed, 1)
        XCTAssertTrue(node.accessibilityActivate())
        XCTAssertEqual(confirmed, 2)
    }

    /// Not an assertion: the held states as pictures (sweep half way, then
    /// the Reduce Motion counter), in Paper and Ink, for the review shots.
    func testHoldStatesPictures() {
        let states: [(String, HoldIndicator)] = [("idle", .idle), ("sweep-50", .sweep(0.5)),
                                                 ("reduce-motion-2", .counter(2)), ("reduce-motion-1", .counter(1))]
        for scheme in [ColorScheme.light, .dark] {
            for (name, indicator) in states {
                let view = VStack(spacing: Space.s2) {
                    HoldFace(title: "Erase Barking", indicator: indicator)
                    HoldCaption(hint: "Press and hold for 2 seconds", indicator: indicator)
                }
                .padding(Space.gutter)
                .frame(width: 390)
                .background(Color.surface)
                .environment(\.colorScheme, scheme)
                let renderer = ImageRenderer(content: view)
                renderer.scale = 3
                guard let image = renderer.uiImage else { XCTFail("no image for \(name)"); continue }
                let shot = XCTAttachment(image: image)
                shot.name = "hold-\(name)-\(scheme == .light ? "light" : "dark")"
                shot.lifetime = .keepAlways
                add(shot)
            }
        }
    }

    // MARK: Danger zone

    /// A danger zone sits 32 pt below the rest of the screen.
    func testDangerZoneGap() {
        XCTAssertEqual(Space.section + DangerZoneMetrics.extraTop, 32)
        XCTAssertEqual(Space.danger, 32)
    }

    // MARK: Lock screen

    /// The samoyed's 96 pt tile uses the logo tile gradient in both themes.
    func testLockTileGradient() {
        for style in [UIUserInterfaceStyle.light, .dark] {
            XCTAssertEqual(hex("logoTileTop", style), "#7C55C9")
            XCTAssertEqual(hex("logoTileBottom", style), "#4E3189")
        }
        XCTAssertEqual(LockTileMetrics.size, 96)
        XCTAssertEqual(LockTileMetrics.radius, Radius.card)
    }

    // MARK: Haptics

    /// Review B3 #1: Return on the password field buzzes only for a password
    /// the gate refuses, never for a strong one whose copy is still empty;
    /// on the confirmation, any problem buzzes.
    func testPDFSubmitRefusal() {
        let strong = "correct horse battery staple"
        XCTAssertFalse(PhraseExport.refusesOnSubmit(.password, password: strong, confirm: ""))
        XCTAssertFalse(PhraseExport.refusesOnSubmit(.password, password: strong, confirm: "corr"))
        XCTAssertTrue(PhraseExport.refusesOnSubmit(.password, password: "short", confirm: ""))
        XCTAssertTrue(PhraseExport.refusesOnSubmit(.password, password: "password1234", confirm: ""))
        XCTAssertFalse(PhraseExport.refusesOnSubmit(.password, password: "", confirm: ""))
        XCTAssertTrue(PhraseExport.refusesOnSubmit(.confirm, password: strong, confirm: "corr"))
        XCTAssertTrue(PhraseExport.refusesOnSubmit(.confirm, password: "short", confirm: "short"))
        XCTAssertFalse(PhraseExport.refusesOnSubmit(.confirm, password: strong, confirm: strong))
        XCTAssertFalse(PhraseExport.refusesOnSubmit(.confirm, password: "", confirm: ""))
    }

    /// Review B3 #5: a weak password is refused with these words (the line
    /// is a VoiceOver hint now, which UI tests cannot read).
    func testWeakPasswordWording() {
        XCTAssertEqual(PhraseExport.problem("password1234", "password1234"), .tooWeak)
        XCTAssertEqual(PhrasePDFSheet.text(for: .tooWeak),
                       LocalizedStringKey("Too easy to guess: use the suggestion or several random words."))
    }

    /// Review B3 #4: a completed wrong set buzzes each time (not only on the
    /// first change); success is Confirm's, so the picks never say it.
    /// UI review U-24: the verdict, and its haptic, come with Confirm: an
    /// error for each wrong set confirmed, success when right.
    func testQuizConfirmFeedback() {
        XCTAssertEqual(PhraseConfirmView.confirmFeedback(passed: false), .error)
        XCTAssertEqual(PhraseConfirmView.confirmFeedback(passed: true), .success)
    }

    /// B4 carry: a transient `.inactive` (Control Center, a banner) keeps
    /// the hold; only `.background` resets it.
    func testHoldResetsOnlyInTheBackground() {
        XCTAssertFalse(HoldMetrics.resetsHold(on: .active))
        XCTAssertFalse(HoldMetrics.resetsHold(on: .inactive))
        XCTAssertTrue(HoldMetrics.resetsHold(on: .background))
    }

    /// Review B3 #7: a pressed outlined danger button never tints under its
    /// `danger` label (4.2:1 on Paper); its outline thickens instead.
    func testPressedDangerKeepsItsContrast() {
        XCTAssertEqual(ButtonTokens.pressed(.danger), .thickerOutline(2))
        XCTAssertEqual(ButtonTokens.pressed(.primary), .darken)
    }

    /// U-25: one feedback per kind of moment.
    func testHapticMap() {
        XCTAssertEqual(Haptic.success.feedback, .success)
        XCTAssertEqual(Haptic.error.feedback, .error)
        XCTAssertEqual(Haptic.send.feedback, .impact(weight: .light))
        XCTAssertEqual(Haptic.holdCompleted.feedback, .warning)
    }
}

/// Reads SwiftUI's accessibility tree in a unit test: the tree is only
/// built while accessibility is on, which `libAccessibility` switches on
/// for this process (as XCTest does for UI tests).
@MainActor
enum AccessibilityProbe {
    private static var enabled = false

    private static func enable() {
        guard !enabled, let lib = dlopen("/usr/lib/libAccessibility.dylib", RTLD_NOW),
              let f = dlsym(lib, "_AXSApplicationAccessibilitySetEnabled") else { return }
        typealias SetEnabled = @convention(c) (Bool) -> Void
        unsafeBitCast(f, to: SetEnabled.self)(true)
        enabled = true
    }

    static func element(labelled label: String, in view: some View) -> NSObject? {
        enable()
        let host = UIHostingController(rootView: view)
        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 390, height: 844))
        window.rootViewController = host
        window.makeKeyAndVisible()
        host.view.layoutIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
        return find(label, in: host.view)
    }

    private static func find(_ label: String, in o: NSObject) -> NSObject? {
        if o.isAccessibilityElement, o.accessibilityLabel == label { return o }
        let count = o.accessibilityElementCount()
        if count != NSNotFound {
            for i in 0..<count {
                if let child = o.accessibilityElement(at: i) as? NSObject, let hit = find(label, in: child) { return hit }
            }
        }
        if let v = o as? UIView {
            for s in v.subviews { if let hit = find(label, in: s) { return hit } }
        }
        return nil
    }

    /// Runs a custom action the way VoiceOver does.
    static func perform(_ action: UIAccessibilityCustomAction) -> Bool {
        if let handler = action.actionHandler { return handler(action) }
        if let target = action.target as? NSObject {
            _ = target.perform(action.selector, with: action)
            return true
        }
        return false
    }
}
