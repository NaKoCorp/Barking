import SwiftUI

/// Flat card: radius 12, 1 px `border`, no shadow.
struct Card<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
            .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
    }
}

/// Information, warning or danger banner (radius 10). The kind is also said
/// in words to VoiceOver: color is never the only signal.
struct Banner: View {
    enum Kind { case info, warning, danger }
    let kind: Kind
    let title: LocalizedStringKey
    var message: LocalizedStringKey?

    private var colors: (bg: Color, fg: Color, border: Color) {
        switch kind {
        case .info: (.bannerBg, .bannerFg, .bannerBg)
        case .warning: (.warnBg, .warnFg, .warnBorder)
        case .danger: (.surfaceCard, .danger, .danger)
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: kind == .info ? "info.circle" : "exclamationmark.triangle")
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).fontWeight(.semibold)
                if let message { Text(message) }
            }
            Spacer(minLength: 0)
        }
        .font(BarkingFont.sans(.subheadline, size: 14))
        .foregroundStyle(colors.fg)
        .padding(12)
        .background(colors.bg, in: .rect(cornerRadius: Radius.chip))
        .overlay(RoundedRectangle(cornerRadius: Radius.chip).stroke(colors.border, lineWidth: 1))
        .accessibilityElement(children: .combine)
    }
}
