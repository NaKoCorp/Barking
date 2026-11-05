import SwiftUI

/// Message status, shown as a glyph and read by VoiceOver as a word.
enum MessageStatusKind: Equatable {
    case queued, sent, delivered, failed, received

    init(status: String, failed: Bool, outgoing: Bool) {
        if !outgoing { self = .received; return }
        if failed { self = .failed; return }
        switch status {
        case "delivered": self = .delivered
        case "sent": self = .sent
        default: self = .queued
        }
    }
}

struct StatusGlyph: View {
    let status: MessageStatusKind

    var body: some View {
        switch status {
        case .queued: Text(verbatim: "⏳").accessibilityLabel(Text("queued"))
        case .sent: Text(verbatim: "✓").accessibilityLabel(Text("sent"))
        case .delivered: Text(verbatim: "✓✓").accessibilityLabel(Text("delivered"))
        case .failed: Text(verbatim: "⚠︎").foregroundStyle(Color.danger).accessibilityLabel(Text("not sent"))
        case .received: EmptyView()
        }
    }
}

/// Chat bubble: received on the card color with a border, sent in purple.
struct Bubble<Footer: View>: View {
    let text: String
    let outgoing: Bool
    @ViewBuilder let footer: Footer

    var body: some View {
        let shape = UnevenRoundedRectangle(
            topLeadingRadius: Radius.panel,
            bottomLeadingRadius: outgoing ? Radius.panel : 5,
            bottomTrailingRadius: outgoing ? 5 : Radius.panel,
            topTrailingRadius: Radius.panel)
        VStack(alignment: .leading, spacing: 4) {
            Text(text).font(BarkingFont.sans(.body, size: 15))
            footer.font(BarkingFont.mono(.caption2, size: 11))
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .foregroundStyle(outgoing ? Color.white : Color.fg)
        .background(outgoing ? Color.accentFill : Color.surfaceCard, in: shape)
        .overlay(shape.stroke(outgoing ? Color.clear : Color.border, lineWidth: 1))
        .containerRelativeFrame(.horizontal, alignment: outgoing ? .trailing : .leading) { w, _ in w * 0.8 }
        .frame(maxWidth: .infinity, alignment: outgoing ? .trailing : .leading)
    }
}

/// Initial on a stable color.
struct Avatar: View {
    let name: String
    let fingerprint: String
    var size: CGFloat = 48

    var body: some View {
        let c = AvatarPalette.colors(for: fingerprint)
        Text(String(name.first ?? "?").uppercased())
            .font(.system(size: size * 0.38, weight: .bold))
            .foregroundStyle(c.text)
            .frame(width: size, height: size)
            .background(c.fill, in: .circle)
            .accessibilityHidden(true)
    }
}

/// Safety code: 12 groups of 5 digits, 4 rows of 3.
struct CodeGrid: View {
    let groups: [String]

    var body: some View {
        Grid(horizontalSpacing: 12, verticalSpacing: 10) {
            ForEach(0..<4, id: \.self) { row in
                GridRow {
                    ForEach(0..<3, id: \.self) { col in
                        let i = row * 3 + col
                        Text(i < groups.count ? groups[i] : "")
                            .font(BarkingFont.mono(.title3, size: 17, weight: .medium))
                            .tracking(1)
                            .foregroundStyle(Color.fg)
                    }
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity)
        .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.panel))
        .overlay(RoundedRectangle(cornerRadius: Radius.panel).stroke(Color.border, lineWidth: 1))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(groups.joined(separator: ", ")))
    }
}
