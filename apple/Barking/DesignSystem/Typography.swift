import SwiftUI
import UIKit

/// Fira Code (headings, buttons, eyebrows, times, chips, tab labels) and the
/// system font (reading). Every size follows Dynamic Type.
enum BarkingFont {
    static func mono(_ style: Font.TextStyle, size: CGFloat, weight: Font.Weight = .regular) -> Font {
        let name = switch weight {
        case .semibold, .bold, .heavy, .black: "FiraCode-SemiBold"
        case .medium: "FiraCode-Medium"
        default: "FiraCode-Regular"
        }
        return .custom(name, size: size, relativeTo: style)
    }

    /// The system font at the mockup's size, scaled for the text style. Views
    /// re-render when the size category changes, so the scale is read then.
    static func sans(_ style: Font.TextStyle, size: CGFloat, weight: Font.Weight = .regular) -> Font {
        // At the style's own size, the text style scales by itself, even in
        // views that do not re-render on a size change.
        if UIFont.preferredFont(forTextStyle: style.uiKit, compatibleWith: .init(preferredContentSizeCategory: .large))
            .pointSize == size {
            return .system(style, weight: weight)
        }
        return .system(size: UIFontMetrics(forTextStyle: style.uiKit).scaledValue(for: size), weight: weight)
    }

    /// `size` scaled for `style` at the current (or given) text size, capped
    /// at `maximum` when there is one.
    static func scaledSize(_ size: CGFloat, relativeTo style: Font.TextStyle, maximum: CGFloat?,
                           traits: UITraitCollection? = nil) -> CGFloat {
        let scaled = UIFontMetrics(forTextStyle: style.uiKit).scaledValue(for: size, compatibleWith: traits)
        return maximum.map { min(scaled, $0) } ?? scaled
    }
}

/// Type roles of the iOS screens (UI review §6). Fira Code names, labels,
/// commands and states; the system font is for what a person reads. Every
/// role follows Dynamic Type. Feature code uses these, never a fixed
/// `.system(size:)`. Computed, so a sans role is scaled when it is read.
extension Font {
    /// Screen title: Fira 600, 30 (apply `.tracking(-0.5)` with it).
    static var bTitle: Font { BarkingFont.mono(.largeTitle, size: 30, weight: .semibold) }
    /// Inline navigation title: Fira 600, 17.
    static var bNavTitle: Font { BarkingFont.mono(.headline, size: 17, weight: .semibold) }
    /// In-page section label: Fira 500, 13, sentence case, in `fgMuted`.
    static var bSectionLabel: Font { BarkingFont.mono(.footnote, size: 13, weight: .medium) }
    /// Card and row body: sans 15.
    static var bBody: Font { BarkingFont.sans(.subheadline, size: 15) }
    /// Chat bubbles, inputs and onboarding leads: sans 17.
    static var bBodyLarge: Font { BarkingFont.sans(.body, size: 17) }
    /// Secondary lines, previews, banners: sans 14.
    static var bBodySmall: Font { BarkingFont.sans(.subheadline, size: 14) }
    /// Times, sizes, hints: Fira 12.
    static var bMeta: Font { BarkingFont.mono(.caption, size: 12) }
    /// Tags: Fira 600, 11.
    static var bTag: Font { BarkingFont.mono(.caption2, size: 11, weight: .semibold) }
    /// Buttons: Fira 600, 15.
    static var bButton: Font { BarkingFont.mono(.body, size: 15, weight: .semibold) }

    /// SF Symbols and the ✓ glyph (Fira Code draws ✓ like a √), scaled
    /// with `style`.
    /// Pass `maximum` when the glyph sits in a container that does not grow
    /// as much (a 44 pt button, a capped tile).
    static func bSymbol(_ size: CGFloat, relativeTo style: Font.TextStyle = .body,
                        weight: Font.Weight = .regular, maximum: CGFloat? = nil) -> Font {
        guard maximum != nil else { return BarkingFont.sans(style, size: size, weight: weight) }
        return .system(size: BarkingFont.scaledSize(size, relativeTo: style, maximum: maximum), weight: weight)
    }
}

private extension Font.TextStyle {
    var uiKit: UIFont.TextStyle {
        switch self {
        case .largeTitle: .largeTitle
        case .title: .title1
        case .title2: .title2
        case .title3: .title3
        case .headline: .headline
        case .subheadline: .subheadline
        case .callout: .callout
        case .footnote: .footnote
        case .caption: .caption1
        case .caption2: .caption2
        default: .body
        }
    }
}
