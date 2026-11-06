import SwiftUI
import UIKit
import XCTest
@testable import Barking
import BarkingKit

/// UI review B5: the welcome galaxy (placement, mask, colours, pause), the
/// link sheet's countdown, the recover paste and the copy polish.
@MainActor
final class WelcomeTests: XCTestCase {
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

    // MARK: Galaxy

    /// Screens from an SE to a Pro Max, at a normal and a large text size
    /// (where the text starts high and the band is thin or empty).
    private let layouts: [GalaxyLayout] = [
        GalaxyLayout(size: CGSize(width: 393, height: 790), top: 62, bottom: 440),
        GalaxyLayout(size: CGSize(width: 320, height: 548), top: 52, bottom: 250),
        GalaxyLayout(size: CGSize(width: 440, height: 880), top: 64, bottom: 500),
        GalaxyLayout(size: CGSize(width: 393, height: 1400), top: 120, bottom: 150),
        GalaxyLayout(size: CGSize(width: 393, height: 1400), top: 120, bottom: 100),
    ]

    /// U-32: no dot ever shows over the text. Every orbiter, at every moment
    /// of two minutes, is drawn with the mask's alpha at each of its pixel
    /// rows; any row inside the text rectangle (or the header) has alpha 0.
    func testNoDotReachesTheText() {
        for layout in layouts {
            for step in 0..<240 {
                let t = Double(step) * 0.5
                for o in Galaxy.orbiters {
                    let p = layout.point(Galaxy.position(o, at: t))
                    let r = Galaxy.dotRadius * layout.scale
                    for y in stride(from: p.y - r, through: p.y + r, by: 0.5)
                    where y >= layout.bottom || y <= layout.top {
                        XCTAssertEqual(layout.alpha(atY: y), 0, "dot row \(y) visible, text from \(layout.bottom)")
                    }
                }
            }
            // The mask is clear over the whole text and header.
            for y in stride(from: layout.bottom, through: layout.size.height, by: 1) {
                XCTAssertEqual(layout.alpha(atY: y), 0)
            }
            for y in stride(from: 0, through: layout.top, by: 1) {
                XCTAssertEqual(layout.alpha(atY: y), 0)
            }
        }
    }

    /// The gradient the view draws says the same as `alpha(atY:)`.
    func testMaskStopsMatchTheAlpha() {
        for layout in layouts {
            let stops = layout.maskStops
            XCTAssertEqual(stops.map(\.location), stops.map(\.location).sorted(), "stops out of order")
            XCTAssertEqual(stops.first?.opacity, 0)
            XCTAssertEqual(stops.last?.opacity, 0)
            for s in stops {
                XCTAssertEqual(layout.alpha(atY: s.location * layout.size.height), s.opacity, accuracy: 0.001)
            }
            XCTAssertLessThanOrEqual(stops.last?.location ?? 1, layout.bottom / layout.size.height + 0.0001)
        }
    }

    /// U-32: the centre sits at about (62 %, 26 %), inside the band, and on
    /// a normal screen the dots are seen most of the time.
    func testGalaxyIsCentredAboveTheText() {
        let l = layouts[0]
        XCTAssertEqual(l.centre.x, 0.62 * 393, accuracy: 0.5)
        XCTAssertEqual(l.centre.y, 0.26 * 790, accuracy: 0.5)
        var seen = 0
        for step in 0..<120 {
            for o in Galaxy.orbiters where l.alpha(atY: l.point(Galaxy.position(o, at: Double(step))).y) > 0.5 {
                seen += 1
            }
        }
        XCTAssertGreaterThan(seen, 120, "the dots are almost never visible")
        // A band thinner than the centre's place: the centre is clamped into it.
        let thin = layouts[3]
        XCTAssertGreaterThanOrEqual(thin.centre.y, thin.top)
        XCTAssertLessThanOrEqual(thin.centre.y, thin.bottom)
        // ...and a band that thin shows nothing (no slivers of rings).
        XCTAssertFalse(thin.isShown)
        XCTAssertEqual(thin.alpha(atY: 135), 0)
        XCTAssertTrue(l.isShown)
    }

    /// B5 (user): every coloured dot rides one of the drawn rings, exactly,
    /// at every moment and on every layout (the rings and the dots share one
    /// centre and one scale, so text size cannot move one without the other).
    func testDotsSitOnTheirRings() {
        let radii = Galaxy.rings.map(\.radius)
        for o in Galaxy.orbiters {
            XCTAssertTrue(radii.contains(o.radius), "orbit \(o.radius) is not a drawn ring \(radii)")
        }
        for layout in layouts {
            for step in 0..<240 {
                for o in Galaxy.orbiters {
                    let p = layout.point(Galaxy.position(o, at: Double(step) * 0.5))
                    let d = hypot(p.x - layout.centre.x, p.y - layout.centre.y)
                    XCTAssertEqual(d, o.radius * layout.scale, accuracy: 0.001)
                }
            }
        }
    }

    /// U-32: the dots use the transport tokens, light and dark.
    func testDotsUseTransportTokens() {
        XCTAssertEqual(Galaxy.orbiters.map(\.token), ["transportBle", "transportLora", "transportWifi", "transportNet"])
        let expected: [String: (String, String)] = [
            "transportBle": ("#5AB0FF", "#5AB0FF"),
            "transportLora": ("#D9A920", "#F2C94C"),
            "transportWifi": ("#3DBB85", "#3DDC97"),
            "transportNet": ("#9B6BE0", "#C59BFF"),
        ]
        for (name, (light, dark)) in expected {
            XCTAssertEqual(hex(name, .light), light, name)
            XCTAssertEqual(hex(name, .dark), dark, name)
        }
    }

    /// U-32: the galaxy stops after 60 s and while the scene is not active;
    /// under Reduce Motion it never starts (time 0, paused).
    func testGalaxyClock() {
        XCTAssertEqual(GalaxyClock.time(elapsed: 12, reduceMotion: false), 12)
        XCTAssertEqual(GalaxyClock.time(elapsed: 95, reduceMotion: false), 60)
        XCTAssertEqual(GalaxyClock.time(elapsed: 12, reduceMotion: true), 0)
        XCTAssertFalse(GalaxyClock.paused(elapsed: 12, reduceMotion: false, active: true))
        XCTAssertTrue(GalaxyClock.paused(elapsed: 12, reduceMotion: false, active: false))
        XCTAssertTrue(GalaxyClock.paused(elapsed: 60, reduceMotion: false, active: true))
        XCTAssertTrue(GalaxyClock.paused(elapsed: 0, reduceMotion: true, active: true))
    }

    // MARK: Link a new device (U-28)

    /// The offer's own expiry: postcard (root 32, secret 32, varint seconds).
    func testOfferExpiryIsReadFromTheOffer() {
        let seconds: UInt64 = 1_799_999_999
        var bytes = Data(repeating: 0xAB, count: 64)
        var v = seconds
        repeat {
            var b = UInt8(v & 0x7F)
            v >>= 7
            if v != 0 { b |= 0x80 }
            bytes.append(b)
        } while v != 0
        XCTAssertEqual(LinkOfferExpiry.date(of: bytes), Date(timeIntervalSince1970: TimeInterval(seconds)))
        XCTAssertNil(LinkOfferExpiry.date(of: Data(repeating: 0, count: 64)), "no date")
        XCTAssertNil(LinkOfferExpiry.date(of: bytes + Data([1])), "trailing byte")
        XCTAssertNil(LinkOfferExpiry.date(of: Data(repeating: 0xFF, count: 80)), "unterminated varint")
    }

    func testCountdown() {
        let expiry = Date(timeIntervalSince1970: 10_000)
        XCTAssertEqual(LinkCountdown.of(now: expiry.addingTimeInterval(-582), expiry: expiry, reduceMotion: false), .live("09:42"))
        XCTAssertEqual(LinkCountdown.of(now: expiry.addingTimeInterval(-0.4), expiry: expiry, reduceMotion: false), .live("00:01"))
        XCTAssertEqual(LinkCountdown.of(now: expiry, expiry: expiry, reduceMotion: false), .expired)
        // Reduce Motion: a fixed time, not a ticking clock; still expires.
        XCTAssertEqual(LinkCountdown.of(now: expiry.addingTimeInterval(-582), expiry: expiry, reduceMotion: true), .until(expiry))
        XCTAssertEqual(LinkCountdown.of(now: expiry.addingTimeInterval(1), expiry: expiry, reduceMotion: true), .expired)
    }

    // MARK: Recover paste (carry 5)

    /// A clipboard that counts its reads and can change behind our back.
    private final class FakeClipboard: PhraseClipboard {
        var text: String?
        var changeCount = 1
        var reads = 0
        var changesOnRead = false
        var cleared = false
        init(_ text: String?) { self.text = text }
        var string: String? {
            reads += 1
            if changesOnRead { changeCount += 1 }
            return text
        }
        func clear() { cleared = true; text = nil; changeCount += 1 }
    }

    private var words: [String] { Array(bip39Words().prefix(24)) }
    private func freshDefaults() -> UserDefaults { UserDefaults(suiteName: "test.\(UUID())")! }

    /// The clipboard is read once (one paste prompt on a device), and
    /// cleared when nothing else was copied meanwhile.
    func testPasteReadsOnceThenClears() {
        let board = FakeClipboard(words.joined(separator: " "))
        let m = OnboardingModel(defaults: freshDefaults())
        XCTAssertEqual(RecoverPaste.take(from: board, into: m), .init(result: .filled, cleared: true))
        XCTAssertEqual(board.reads, 1)
        XCTAssertTrue(board.cleared)
        XCTAssertEqual(RecoverPaste.message(for: .init(result: .filled, cleared: true)), "Pasted. The clipboard was cleared.")
    }

    /// Something new was copied after the read: it is not ours to clear,
    /// and the line does not say "cleared".
    func testPasteLeavesAChangedClipboard() {
        let board = FakeClipboard(words.prefix(20).joined(separator: " "))
        board.changesOnRead = true
        let m = OnboardingModel(defaults: freshDefaults())
        let outcome = RecoverPaste.take(from: board, into: m)
        XCTAssertEqual(outcome, .init(result: .wrongCount(20), cleared: false))
        XCTAssertFalse(board.cleared)
        XCTAssertEqual(board.reads, 1)
        XCTAssertEqual(RecoverPaste.message(for: outcome), "Found 20 words; 24 are needed.")
        XCTAssertEqual(RecoverPaste.message(for: .init(result: .filled, cleared: false)), "Pasted.")
        XCTAssertEqual(RecoverPaste.message(for: .init(result: .wrongCount(1), cleared: true)),
                       "Found 1 word; 24 are needed. The clipboard was cleared.")
    }

    /// Digits or blanks hold no word: nothing is cleared, and the line says
    /// "no words", not "no text".
    func testPasteOfNoWords() {
        let m = OnboardingModel(defaults: freshDefaults())
        for text in ["  \n ", "1234 5678", nil] as [String?] {
            let board = FakeClipboard(text)
            let outcome = RecoverPaste.take(from: board, into: m)
            XCTAssertEqual(outcome, .init(result: .empty, cleared: false), "\(text ?? "nil")")
            XCTAssertFalse(board.cleared)
            XCTAssertEqual(RecoverPaste.message(for: outcome), "The clipboard holds no words.")
        }
    }

    /// Carry 4: the count of words left is a plural.
    func testWordsLeftIsAPlural() {
        XCTAssertEqual(RecoverView.wordsLeft(1), "1 word left to fill in.")
        XCTAssertEqual(RecoverView.wordsLeft(7), "7 words left to fill in.")
    }
}
