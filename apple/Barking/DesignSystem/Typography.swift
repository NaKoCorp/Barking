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
        .system(size: UIFontMetrics(forTextStyle: style.uiKit).scaledValue(for: size), weight: weight)
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
