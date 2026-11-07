import SwiftUI
import UIKit
import XCTest
@testable import Barking
@testable import BarkingKit

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

    // MARK: Symbols

    /// A glyph inside a fixed or capped container stops growing at
    /// `maximum`, so it never overflows its tile at AX sizes.
    func testSymbolSizeClampsAtAccessibilitySizes() {
        let ax5 = UITraitCollection(preferredContentSizeCategory: .accessibilityExtraExtraExtraLarge)
        let large = UITraitCollection(preferredContentSizeCategory: .large)
        XCTAssertEqual(BarkingFont.scaledSize(15, relativeTo: .body, maximum: 24, traits: ax5), 24)
        XCTAssertEqual(BarkingFont.scaledSize(15, relativeTo: .body, maximum: 24, traits: large), 15)
        XCTAssertGreaterThan(BarkingFont.scaledSize(15, relativeTo: .body, maximum: nil, traits: ax5), 24)
    }

    // MARK: Motion

    func testMotionIsNilUnderReduceMotion() {
        XCTAssertNil(Motion.gated(Motion.feedback, reduceMotion: true))
        XCTAssertNotNil(Motion.gated(Motion.enter, reduceMotion: false))
    }

    // MARK: Delivery (spec Lot M §6.1, §6.2, §7.1)

    private func hex(_ c: UIColor) -> String {
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        c.getRed(&r, green: &g, blue: &b, alpha: &a)
        return String(format: "#%02X%02X%02X", Int((r * 255).rounded()), Int((g * 255).rounded()), Int((b * 255).rounded()))
    }

    private func lang(_ code: String) throws -> (bundle: Bundle, locale: Locale) {
        let path = try XCTUnwrap(Bundle.main.path(forResource: code, ofType: "lproj"))
        return (try XCTUnwrap(Bundle(path: path)), Locale(identifier: code))
    }

    private func delivery(_ state: DeliveryState, sealed: UInt64 = 0, deposited: UInt64? = nil, received: UInt64? = nil,
                          expired: UInt64? = nil, devices: UInt32 = 1, got: UInt32 = 0) -> Delivery {
        Delivery(state: state, sealedAt: sealed, depositedAt: deposited, receivedAt: received, expiredAt: expired,
                 devices: devices, devicesReceived: got, devicesLeft: 0, devicesPending: 0)
    }

    /// §6.2: the table of symbols and tints.
    func testSymbolsAndTints() {
        XCTAssertEqual(DeliveryState.allCases, [.pending, .onNetwork, .received, .notDelivered])
        XCTAssertEqual(DeliveryState.allCases.map(\.symbol),
                       ["clock", "checkmark", "checkmark.double", "exclamationmark.triangle.fill"])
        XCTAssertEqual(DeliveryState.allCases.map(\.isCustomSymbol), [false, false, true, false])
        XCTAssertEqual(DeliveryState.allCases.map(\.tintToken), ["fgSoft", "fgSoft", "accent", "warnFg"])
        XCTAssertEqual(DeliveryState.allCases.map(\.tint), [.fgSoft, .fgSoft, .accent, .warnFg])
        // Never red for a network problem.
        XCTAssertFalse(DeliveryState.allCases.map(\.tintToken).contains("danger"))
    }

    func testCustomSymbolLoads() throws {
        let custom = try XCTUnwrap(UIImage(named: "checkmark.double"), "custom symbol missing from the asset catalog")
        XCTAssertTrue(custom.isSymbolImage)
        // Same height as checkmark: the width carries the meaning.
        let cfg = UIImage.SymbolConfiguration(pointSize: 17, weight: .semibold)
        let check = try XCTUnwrap(UIImage(systemName: "checkmark", withConfiguration: cfg))
        let double = try XCTUnwrap(UIImage(named: "checkmark.double", in: .main, with: cfg))
        XCTAssertEqual(double.size.height, check.size.height, accuracy: 1.0)
        XCTAssertGreaterThan(double.size.width, check.size.width * 1.2)
    }

    /// The custom symbol follows the weights the components use: the ink
    /// grows with the weight (a symbol with one weight draws the same everywhere).
    func testCustomSymbolFollowsWeights() throws {
        func ink(_ weight: UIImage.SymbolWeight) throws -> Double {
            let cfg = UIImage.SymbolConfiguration(pointSize: 60, weight: weight)
            let image = try XCTUnwrap(UIImage(named: "checkmark.double", in: .main, with: cfg))
                .withTintColor(.black, renderingMode: .alwaysOriginal)
            let size = CGSize(width: 160, height: 160)
            let format = UIGraphicsImageRendererFormat(); format.scale = 1
            let cg = try XCTUnwrap(UIGraphicsImageRenderer(size: size, format: format).image { _ in
                image.draw(at: CGPoint(x: (size.width - image.size.width) / 2, y: (size.height - image.size.height) / 2))
            }.cgImage)
            let data = try XCTUnwrap(cg.dataProvider?.data as Data?)
            return stride(from: 3, to: data.count, by: 4).reduce(0.0) { $0 + Double(data[$1]) } / 255
        }
        let weights: [UIImage.SymbolWeight] = [.ultraLight, .regular, .semibold, .black]
        let inks = try weights.map(ink)
        XCTAssertGreaterThan(inks[0], 50, "drawn")
        for (a, b) in zip(inks, inks.dropFirst()) { XCTAssertGreaterThan(b, a * 1.05, "ink by weight: \(inks)") }
    }

    func testSpokenPhrases() throws {
        let en = try lang("en"), fr = try lang("fr")
        let utc = try XCTUnwrap(TimeZone(identifier: "UTC"))
        let t0: UInt64 = 1_794_060_120 // 2026-11-07 14:02:00 UTC
        func at(_ d: UInt64, _ l: (bundle: Bundle, locale: Locale)) -> String {
            Date(timeIntervalSince1970: TimeInterval(d)).formatted(
                Date.FormatStyle(date: .omitted, time: .shortened, locale: l.locale, timeZone: utc))
        }
        func spoken(_ d: Delivery, _ l: (bundle: Bundle, locale: Locale)) -> String {
            d.state.spoken(d, bundle: l.bundle, locale: l.locale, timeZone: utc)
        }
        XCTAssertEqual(fr.locale.identifier, "fr")
        XCTAssertEqual(at(t0, fr), "14:02")

        let pending = delivery(.pending, sealed: t0)
        XCTAssertEqual(spoken(pending, en), "Pending since \(at(t0, en))")
        XCTAssertEqual(spoken(pending, fr), "En attente depuis 14:02")

        let onNet = delivery(.onNetwork, sealed: t0 - 60, deposited: t0)
        XCTAssertEqual(spoken(onNet, en), "On the network since \(at(t0, en))")
        XCTAssertEqual(spoken(onNet, fr), "Sur le réseau depuis 14:02")

        let got = delivery(.received, sealed: t0 - 60, deposited: t0, received: t0 + 180, devices: 1, got: 1)
        XCTAssertEqual(spoken(got, en), "Received at \(at(t0 + 180, en))")
        XCTAssertEqual(spoken(got, fr), "Reçu à 14:05")

        // Plural: on 1 of 2 devices, on 2 of 3 devices; all of them, no count.
        let part = delivery(.received, sealed: t0, deposited: t0, received: t0 + 180, devices: 2, got: 1)
        XCTAssertEqual(spoken(part, en), "Received at \(at(t0 + 180, en)), on 1 of 2 devices")
        XCTAssertEqual(spoken(part, fr), "Reçu à 14:05, sur 1 de ses 2 appareils")
        let part3 = delivery(.received, sealed: t0, deposited: t0, received: t0 + 180, devices: 3, got: 2)
        XCTAssertEqual(spoken(part3, en), "Received at \(at(t0 + 180, en)), on 2 of 3 devices")
        XCTAssertEqual(spoken(part3, fr), "Reçu à 14:05, sur 2 de ses 3 appareils")
        let all = delivery(.received, sealed: t0, deposited: t0, received: t0 + 180, devices: 2, got: 2)
        XCTAssertEqual(spoken(all, fr), "Reçu à 14:05")

        let lost = delivery(.notDelivered, sealed: t0 - 86_400, expired: t0)
        XCTAssertEqual(spoken(lost, en), "Not delivered. Expired at \(at(t0, en)).")
        XCTAssertEqual(spoken(lost, fr), "Non distribué. Expiré à 14:02.")
        XCTAssertEqual(spoken(delivery(.notDelivered), fr), "Non distribué.")
    }

    func testWordsInBothLanguages() throws {
        let en = try lang("en"), fr = try lang("fr")
        XCTAssertEqual(DeliveryState.allCases.map { $0.wordString(bundle: en.bundle, locale: en.locale) },
                       ["Pending", "On the network", "Received", "Not delivered"])
        XCTAssertEqual(DeliveryState.allCases.map { $0.wordString(bundle: fr.bundle, locale: fr.locale) },
                       ["En attente", "Sur le réseau", "Reçu", "Non distribué"])
    }

    func testLegendShowsNotDeliveredOnlyWhenCurrent() {
        let normal: [DeliveryState] = [.pending, .onNetwork, .received]
        for shown in [DeliveryState.pending, .onNetwork, .received] {
            XCTAssertEqual(DeliveryLegend.states(current: shown), normal, "\(shown)")
        }
        XCTAssertEqual(DeliveryLegend.states(current: .notDelivered), normal + [.notDelivered])
    }

    /// §6.2: under the bubble, on `surface`, every tint passes in both themes.
    func testUnderBubbleContrast() {
        for style in [UIUserInterfaceStyle.light, .dark] {
            for token in ["fgSoft", "accent", "warnFg"] {
                let r = DesignSystemTests.ratio(color(token, style), color("surface", style))
                XCTAssertGreaterThanOrEqual(r, 4.5, "\(token) on surface, \(style == .dark ? "dark" : "light"): \(r)")
            }
        }
        // The retry word and the glyph share warnFg; the highlighted chip is warnFg on warnBg.
        for style in [UIUserInterfaceStyle.light, .dark] {
            XCTAssertGreaterThanOrEqual(DesignSystemTests.ratio(color("warnFg", style), color("warnBg", style)), 4.5)
            XCTAssertGreaterThanOrEqual(DesignSystemTests.ratio(color("accent", style), color("wash", style)), 4.5)
        }
        // On the network and Received differ by shape, not by tint alone.
        XCTAssertNotEqual(DeliveryState.onNetwork.symbol, DeliveryState.received.symbol)
    }

    func testPathColorsetsMatchTokens() {
        for (name, value) in [("pathSender", "#6640AF"), ("pathRecipient", "#1F7F55"), ("pathOwnDevices", "#4E3189")] {
            for style in [UIUserInterfaceStyle.light, .dark] {
                XCTAssertEqual(hex(color(name, style)), value, "\(name) \(style == .dark ? "dark" : "light")")
                // White glyphs read on the discs.
                XCTAssertGreaterThanOrEqual(DesignSystemTests.ratio(.white, color(name, style)), 4.5, name)
            }
        }
        // The relay's disc is the internet transport color, not the amber.
        XCTAssertEqual(PathStopColor.relay, "transportNet")
    }

    // MARK: Timeline and rows

    func testTimelineConnectorsAreSolidBetweenDoneSteps() {
        typealias Step = DeliveryTimeline.Step
        func step(_ id: String, _ phase: DeliveryTimeline.Phase) -> Step {
            Step(id: id, glyph: nil, title: Text(verbatim: id), at: nil, detail: nil, phase: phase)
        }
        let lines = DeliveryTimeline.connectors(of: [step("a", .done), step("b", .done), step("c", .ahead), step("d", .ahead)])
        XCTAssertEqual(lines, [.solid, .dashed, .dashed])
        // A message that stopped: nothing is drawn after the stop.
        XCTAssertEqual(DeliveryTimeline.connectors(of: [step("a", .done), step("b", .stopped)]), [.dashed])
        XCTAssertEqual(DeliveryTimeline.connectors(of: [step("a", .done)]), [])
        XCTAssertEqual(DeliveryTimeline.connectors(of: []), [])
    }

    func testTimelineTimes() throws {
        let utc = try XCTUnwrap(TimeZone(identifier: "UTC"))
        var cal = Calendar(identifier: .gregorian); cal.timeZone = utc
        let now = Date(timeIntervalSince1970: 1_794_060_120 + 3600) // 2026-11-07 15:02 UTC, a Saturday
        let today = Date(timeIntervalSince1970: 1_794_060_127) // 14:02:07
        let thursday = Date(timeIntervalSince1970: 1_793_869_923) // 2026-11-05 09:12:03
        let fr = Locale(identifier: "fr")
        XCTAssertEqual(DeliveryTimeline.timeText(today, now: now, calendar: cal, locale: fr), "14:02:07")
        XCTAssertEqual(DeliveryTimeline.timeText(thursday, now: now, calendar: cal, locale: fr), "jeu. 09:12:03")
        XCTAssertEqual(DeliveryTimeline.timeText(thursday, now: now, calendar: cal, locale: Locale(identifier: "en")), "Thu 09:12:03")
    }

    func testRowExcerptIsOneLine() {
        XCTAssertEqual(DeliveryRow.oneLine("See you\nat the market\r\n\nat 6"), "See you at the market at 6")
        XCTAssertEqual(DeliveryRow.oneLine("plain"), "plain")
    }
}
