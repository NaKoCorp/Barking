import BarkingKit
import SwiftUI
import UIKit

extension Message {
    /// A sent message that was not delivered: it can be sent again.
    var failed: Bool { delivery?.state == .notDelivered }

    /// The state shown under an outgoing bubble; nil for a received message.
    /// A sent message without a delivery record (sent from another of my
    /// devices) shows its time only.
    var shownState: DeliveryState? { outgoing ? delivery?.state : nil }
}

/// Whether a contact's safety code was compared (UI review U-20): a glyph
/// and a word, never colour alone.
enum Trust: Equatable {
    case verified, notVerified

    init(verified: Bool) { self = verified ? .verified : .notVerified }

    var glyph: String { self == .verified ? "✓" : "○" }
    /// Asset name of the glyph and the word.
    var token: String { self == .verified ? "ok" : "fgMuted" }
    var word: LocalizedStringKey { self == .verified ? "verified" : "not verified" }
}

/// "✓ verified" or "○ not verified" in Fira 12, with an optional "›" when
/// it opens the safety code. One element for VoiceOver: the word.
struct TrustLine: View {
    let trust: Trust
    var chevron = false

    var body: some View {
        HStack(spacing: 4) {
            // The system font: Fira Code draws ✓ like a √.
            Text(verbatim: trust.glyph).font(.bSymbol(11, relativeTo: .caption, weight: .bold))
                .accessibilityHidden(true)
            Text(trust.word).font(.bMeta)
            if chevron { Text(verbatim: "›").font(.bMeta).accessibilityHidden(true) }
        }
        .foregroundStyle(Color(trust.token))
        .lineLimit(1)
        .accessibilityElement(children: .combine)
    }
}

/// The conversation's title in the navigation bar: avatar, name, trust
/// line. A bar has a fixed height and the bar's content does not take a
/// SwiftUI Dynamic Type cap, so the sizes here are scaled by hand and
/// capped (name 20, line 14) and the avatar goes at accessibility sizes:
/// at AX3 it no longer runs under the back and path buttons. The bar's
/// item shows the large content viewer on a long press instead.
struct ChatTitle: View {
    let name: String
    let fingerprint: String
    let trust: Trust
    /// Read so the title re-renders when the text size changes.
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    static let nameMaximum: CGFloat = 20
    static let lineMaximum: CGFloat = 14

    /// The app's text size, from UIKit: the bar's content may not get the
    /// scene's SwiftUI environment.
    static var accessibilitySize: Bool { UIApplication.shared.preferredContentSizeCategory.isAccessibilityCategory }

    var body: some View {
        let line = BarkingFont.scaledSize(12, relativeTo: .caption, maximum: Self.lineMaximum)
        HStack(spacing: 8) {
            if !Self.accessibilitySize && !dynamicTypeSize.isAccessibilitySize {
                Avatar(name: name, fingerprint: fingerprint, size: 32)
            }
            VStack(alignment: .leading, spacing: 0) {
                Text(verbatim: name)
                    .font(.system(size: BarkingFont.scaledSize(16, relativeTo: .headline, maximum: Self.nameMaximum),
                                  weight: .semibold))
                    .foregroundStyle(Color.fg).lineLimit(1)
                HStack(spacing: 4) {
                    Text(verbatim: trust.glyph).font(.system(size: line - 1, weight: .bold)).accessibilityHidden(true)
                    Text(trust.word).font(.custom("FiraCode-Regular", fixedSize: line))
                    Text(verbatim: "›").font(.custom("FiraCode-Regular", fixedSize: line)).accessibilityHidden(true)
                }
                .foregroundStyle(Color(trust.token))
                .lineLimit(1)
            }
        }
        .frame(minHeight: 44)
    }
}

/// Chat bubble: received on the card color with a border, sent in purple.
/// The text alone (spec Lot M §6.3): time and state go under it
/// (`BubbleMeta`). Place it in its row with `bubbleRow(outgoing:)`, after
/// the modifiers that should see the bubble only (context menu preview).
struct Bubble: View {
    let text: String
    let outgoing: Bool

    static func shape(outgoing: Bool) -> UnevenRoundedRectangle {
        UnevenRoundedRectangle(
            topLeadingRadius: Radius.panel,
            bottomLeadingRadius: outgoing ? Radius.panel : 5,
            bottomTrailingRadius: outgoing ? 5 : Radius.panel,
            topTrailingRadius: Radius.panel)
    }

    var body: some View {
        let shape = Self.shape(outgoing: outgoing)
        Text(text).font(BarkingFont.sans(.body, size: 15))
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .foregroundStyle(outgoing ? Color.white : Color.fg)
            .background(outgoing ? Color.accentFill : Color.surfaceCard, in: shape)
            .overlay(shape.stroke(outgoing ? Color.clear : Color.border, lineWidth: 1))
            .contentShape(.contextMenuPreview, shape)
    }
}

extension View {
    /// A bubble on its side of the conversation, 80 % of the width at most.
    func bubbleRow(outgoing: Bool) -> some View {
        containerRelativeFrame(.horizontal, alignment: outgoing ? .trailing : .leading) { w, _ in w * 0.8 }
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

/// Safety code: 12 groups of 5 digits, 4 rows of 3. A group never wraps
/// inside itself (review final #1: "9045" over "0" is read as other
/// digits): at large text sizes the rows hold 2 groups, then 1.
struct CodeGrid: View {
    let groups: [String]

    var body: some View {
        // The first layout whose one-line groups fit the width.
        ViewThatFits(in: .horizontal) {
            grid(columns: 3)
            grid(columns: 2)
            grid(columns: 1)
        }
        .padding(16)
        .frame(maxWidth: .infinity)
        .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.panel))
        .overlay(RoundedRectangle(cornerRadius: Radius.panel).stroke(Color.border, lineWidth: 1))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(groups.joined(separator: ", ")))
        .accessibilityIdentifier("contact.safetyCode")
    }

    private func grid(columns: Int) -> some View {
        Grid(horizontalSpacing: 12, verticalSpacing: 10) {
            ForEach(0..<(12 / columns), id: \.self) { row in
                GridRow {
                    ForEach(0..<columns, id: \.self) { col in
                        let i = row * columns + col
                        Text(i < groups.count ? groups[i] : "")
                            .font(BarkingFont.mono(.title3, size: 17, weight: .medium))
                            .tracking(1)
                            .foregroundStyle(Color.fg)
                            .lineLimit(1)
                            .fixedSize()
                    }
                }
            }
        }
    }
}
