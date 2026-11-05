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
    let text: LocalizedStringKey
    var size: CGFloat = 30
    init(_ text: LocalizedStringKey, size: CGFloat = 30) {
        self.text = text
        self.size = size
    }

    var body: some View {
        Text(text)
            .font(BarkingFont.mono(.largeTitle, size: size, weight: .semibold))
            .tracking(-0.5)
            .foregroundStyle(Color.fg)
            .accessibilityAddTraits(.isHeader)
    }
}
