import SwiftUI

/// Section kicker written as a code comment: `// …`, in `accent`.
struct Eyebrow: View {
    let text: LocalizedStringKey
    init(_ text: LocalizedStringKey) { self.text = text }

    var body: some View {
        (Text(verbatim: "// ") + Text(text))
            .font(BarkingFont.mono(.footnote, size: 13))
            .foregroundStyle(Color.accent)
            .accessibilityAddTraits(.isHeader)
    }
}

/// Screen title in Fira Code 600.
struct ScreenTitle: View {
    private let text: Text
    var size: CGFloat = 30
    init(_ text: LocalizedStringKey, size: CGFloat = 30) {
        self.text = Text(text)
        self.size = size
    }

    /// Text from data (a contact's name): never a localization key.
    init(verbatim: String, size: CGFloat = 30) {
        self.text = Text(verbatim: verbatim)
        self.size = size
    }

    var body: some View {
        text
            .font(BarkingFont.mono(.largeTitle, size: size, weight: .semibold))
            .tracking(-0.5)
            .foregroundStyle(Color.fg)
            .accessibilityAddTraits(.isHeader)
    }
}
