import UIKit
import XCTest
@testable import Barking

final class DesignSystemTests: XCTestCase {
    private let styles: [UIUserInterfaceStyle] = [.light, .dark]

    private func color(_ name: String, _ style: UIUserInterfaceStyle) -> UIColor {
        let traits = UITraitCollection(userInterfaceStyle: style)
        guard let c = UIColor(named: name, in: Bundle.main, compatibleWith: traits) else {
            XCTFail("missing color \(name)")
            return .clear
        }
        return c.resolvedColor(with: traits)
    }

    /// WCAG relative luminance contrast ratio.
    static func ratio(_ a: UIColor, _ b: UIColor) -> Double {
        func lum(_ c: UIColor) -> Double {
            var r: CGFloat = 0, g: CGFloat = 0, bl: CGFloat = 0, al: CGFloat = 0
            c.getRed(&r, green: &g, blue: &bl, alpha: &al)
            func ch(_ v: CGFloat) -> Double {
                let v = Double(v)
                return v <= 0.03928 ? v / 12.92 : pow((v + 0.055) / 1.055, 2.4)
            }
            return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(bl)
        }
        let (l1, l2) = (lum(a), lum(b))
        return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)
    }

    func testEveryTextPairPassesContrast() {
        var pairs: [(String, String)] = []
        for text in ["fg", "fgMuted", "fgSoft", "accent"] {
            for ground in ["surface", "surfaceCard", "surfaceAlt"] { pairs.append((text, ground)) }
        }
        pairs += [("fgMuted", "field"), ("fg", "segment"), ("bannerFg", "bannerBg"), ("warnFg", "warnBg"), ("ok", "okBg"), ("danger", "surfaceCard")]
        for style in styles {
            for (t, g) in pairs {
                let r = Self.ratio(color(t, style), color(g, style))
                XCTAssertGreaterThanOrEqual(r, 4.5, "\(t) on \(g) in \(style == .dark ? "dark" : "light"): \(r)")
            }
            let white = Self.ratio(.white, color("accentFill", style))
            XCTAssertGreaterThanOrEqual(white, 4.5, "white on accentFill")
        }
    }

    /// Pairs added by the UI review (B1): the third text tier on every
    /// ground, the disabled state, status words, tags and the terminal block.
    func testUIReviewPairsPassContrast() {
        let pairs: [(String, String)] = [
            ("fgSoft", "field"), ("fgDisabled", "fillDisabled"),
            ("terminalFg", "terminalBg"), ("accent", "wash"), ("fgMuted", "field"),
            ("ok", "surface"), ("ok", "surfaceCard"), ("warnFg", "surface"), ("warnFg", "surfaceCard"),
            ("danger", "surface"), ("danger", "surfaceCard"), ("fgSoft", "surface"), ("fgSoft", "surfaceCard"),
        ]
        for style in styles {
            for (t, g) in pairs {
                let r = Self.ratio(color(t, style), color(g, style))
                XCTAssertGreaterThanOrEqual(r, 4.5, "\(t) on \(g) in \(style == .dark ? "dark" : "light"): \(r)")
            }
            // The switch knob is white on the tint (never the light purple).
            XCTAssertGreaterThanOrEqual(Self.ratio(.white, color("toggleOn", style)), 4.5, "white on toggleOn")
            // Non-text: the focus ring stands out from the grounds (3:1).
            for g in ["surface", "surfaceCard", "field"] {
                XCTAssertGreaterThanOrEqual(Self.ratio(color("focusRing", style), color(g, style)), 3, "focusRing on \(g)")
            }
        }
    }

    /// §6 token values: the dark third tier, and a segmented thumb that is
    /// no longer purple (purple stays for actions).
    func testUIReviewTokenValues() {
        func hex(_ c: UIColor) -> String {
            var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
            c.getRed(&r, green: &g, blue: &b, alpha: &a)
            return String(format: "#%02X%02X%02X", Int((r * 255).rounded()), Int((g * 255).rounded()), Int((b * 255).rounded()))
        }
        XCTAssertEqual(hex(color("fgSoft", .dark)), "#9A90B2")
        XCTAssertEqual(hex(color("segment", .dark)), "#1B1524")
        XCTAssertEqual(hex(color("fillDisabled", .light)), hex(color("field", .light)))
        XCTAssertEqual(hex(color("fillDisabled", .dark)), hex(color("field", .dark)))
        XCTAssertEqual(hex(color("toggleOn", .dark)), "#6640AF")
        XCTAssertEqual(hex(color("terminalBg", .light)), "#0B0910")
    }

    func testFiraCodeIsRegistered() {
        for name in ["FiraCode-Regular", "FiraCode-Medium", "FiraCode-SemiBold"] {
            XCTAssertNotNil(UIFont(name: name, size: 15), name)
        }
    }

    func testAvatarPaletteIsStableAndReadable() {
        let fp = "zab2-2ccf-kzfa-fsms"
        XCTAssertEqual(AvatarPalette.index(for: fp), AvatarPalette.index(for: fp))
        for style in styles {
            for pair in AvatarPalette.pairs {
                let r = Self.ratio(color(pair.text, style), color(pair.fill, style))
                XCTAssertGreaterThanOrEqual(r, 4.5, "\(pair.text) on \(pair.fill)")
            }
        }
    }
}

final class RoosterTests: XCTestCase {
    /// Commands are glued to their first number in the mockup's paths.
    func testPathParsesGluedCommands() {
        let p = Rooster.path("M38 33 C38 20 46 9 57 6 L45 35 Z")
        XCTAssertEqual(p.boundingRect.minX, 38, accuracy: 0.5)
        XCTAssertEqual(p.boundingRect.maxX, 57, accuracy: 0.5)
        XCTAssertEqual(p.boundingRect.minY, 6, accuracy: 0.5)
    }
}
