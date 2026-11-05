import SwiftUI

/// NakoCorp design system colors (spec iOS messaging §7.1): one colorset per
/// token in Colors.xcassets, light (Paper) and dark (Ink).
extension Color {
    static let surface = Color("surface")
    static let surfaceWelcome = Color("surfaceWelcome")
    static let surfaceCard = Color("surfaceCard")
    static let surfaceAlt = Color("surfaceAlt")
    static let border = Color("border")
    static let borderStrong = Color("borderStrong")
    static let fg = Color("fg")
    static let fgMuted = Color("fgMuted")
    static let fgSoft = Color("fgSoft")
    static let accent = Color("accent")
    static let accentFill = Color("accentFill")
    static let wash = Color("wash")
    static let ok = Color("ok")
    static let okBg = Color("okBg")
    static let bannerBg = Color("bannerBg")
    static let bannerFg = Color("bannerFg")
    static let warnBg = Color("warnBg")
    static let warnBorder = Color("warnBorder")
    static let warnFg = Color("warnFg")
    static let danger = Color("danger")
    static let switchOff = Color("switchOff")
    static let transportNet = Color("transportNet")
}

/// Corner radii of the design system.
enum Radius {
    static let tag: CGFloat = 4
    static let button: CGFloat = 6
    static let tile: CGFloat = 8
    static let chip: CGFloat = 10
    static let card: CGFloat = 12
    static let panel: CGFloat = 16
}

/// Contact avatar colors: fixed pairs that pass 4.5:1 in both themes, chosen
/// from the fingerprint so a contact keeps its color everywhere.
enum AvatarPalette {
    struct Pair { let fill: String; let text: String }

    static let pairs: [Pair] = (1...6).map { Pair(fill: "avatar\($0)Fill", text: "avatar\($0)Text") }

    static func index(for fingerprint: String) -> Int {
        // FNV-1a: stable across launches, unlike `hashValue`.
        var h: UInt64 = 0xcbf2_9ce4_8422_2325
        for b in fingerprint.utf8 { h = (h ^ UInt64(b)) &* 0x100_0000_01b3 }
        return Int(h % UInt64(pairs.count))
    }

    static func colors(for fingerprint: String) -> (fill: Color, text: Color) {
        let p = pairs[index(for: fingerprint)]
        return (Color(p.fill), Color(p.text))
    }
}
