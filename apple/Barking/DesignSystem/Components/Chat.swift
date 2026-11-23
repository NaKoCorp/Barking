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

/// What a reply's quote shows above its text (spec reply and reactions
/// §5.6): who wrote the original and the start of it, or that it is gone.
struct QuoteLine: Equatable {
    let quote: Quote
    /// "You" or the contact's name, already in the language shown.
    let author: String

    /// The original is among the rows: its text can be shown and tapped.
    var available: Bool { quote.id != nil && quote.excerpt != nil }
    var excerpt: String { quote.excerpt ?? "" }

    /// What VoiceOver says: "Reply to Sam: see you at six".
    func spoken(bundle: Bundle = .main, locale: Locale = .current) -> String {
        available
            ? String(localized: "Reply to \(author): \(excerpt)", bundle: bundle, locale: locale)
            : String(localized: "Original message unavailable", bundle: bundle, locale: locale)
    }
}

extension ReactionChip {
    /// The chip for VoiceOver: "👍, 2 reactions, including yours".
    func label(bundle: Bundle = .main, locale: Locale = .current) -> String {
        let n = Int(count)
        return mine
            ? String(localized: "\(emoji), \(n) reactions, including yours", bundle: bundle, locale: locale)
            : String(localized: "\(emoji), \(n) reactions", bundle: bundle, locale: locale)
    }

    /// The same, with the send state of my reaction after it ("…, reaction
    /// pending"); other people's chips and an untracked one say no state.
    func label(state: DeliveryState?, bundle: Bundle = .main, locale: Locale = .current) -> String {
        let base = label(bundle: bundle, locale: locale)
        guard mine, let state else { return base }
        let word: String = switch state {
        case .pending: String(localized: "reaction pending", bundle: bundle, locale: locale)
        case .onNetwork: String(localized: "reaction on the network", bundle: bundle, locale: locale)
        case .received: String(localized: "reaction received", bundle: bundle, locale: locale)
        case .notDelivered: String(localized: "reaction not delivered", bundle: bundle, locale: locale)
        }
        return "\(base), \(word)"
    }
}

/// The quote inside a bubble: a 3 pt bar, the author, two lines of the
/// original. An unavailable original is one italic line, not tappable.
/// One VoiceOver element: "Reply to Sam: …".
struct QuoteView: View {
    let line: QuoteLine
    let outgoing: Bool
    @Environment(\.locale) private var locale

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            // Accent on the card; white on the purple bubble, where it would vanish.
            RoundedRectangle(cornerRadius: 1.5).fill(outgoing ? Color.white : Color.accentFill).frame(width: 3)
            VStack(alignment: .leading, spacing: 2) {
                if line.available {
                    Text(verbatim: line.author).font(BarkingFont.sans(.footnote, size: 12, weight: .semibold))
                        .foregroundStyle(outgoing ? Color.white : Color.accent)
                    Text(verbatim: line.excerpt).font(BarkingFont.sans(.footnote, size: 13))
                        .foregroundStyle(outgoing ? Color.white : Color.fgMuted)
                        .lineLimit(2)
                } else {
                    Text("Original message unavailable").font(BarkingFont.sans(.footnote, size: 13)).italic()
                        .foregroundStyle(outgoing ? Color.white : Color.fgMuted)
                }
            }
            .multilineTextAlignment(.leading)
        }
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: line.spoken(bundle: .strings(for: locale), locale: locale)))
    }
}

/// Chat bubble: received on the card color with a border, sent in purple.
/// The text alone (spec Lot M §6.3): time and state go under it
/// (`BubbleMeta`). Place it in its row with `bubbleRow(outgoing:)`, after
/// the modifiers that should see the bubble only (context menu preview).
/// A reply carries its quote above the text; a tap on an available quote
/// calls `onQuote`.
struct Bubble: View {
    let text: String
    let outgoing: Bool
    var quote: QuoteLine?
    /// A placeholder for something this version cannot read: italic.
    var placeholder = false
    /// Lit after a quote jumped here: an accent outline that fades out.
    var highlighted = false
    var onQuote: () -> Void = {}
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    static func shape(outgoing: Bool) -> UnevenRoundedRectangle {
        UnevenRoundedRectangle(
            topLeadingRadius: Radius.panel,
            bottomLeadingRadius: outgoing ? Radius.panel : 5,
            bottomTrailingRadius: outgoing ? 5 : Radius.panel,
            topTrailingRadius: Radius.panel)
    }

    /// The outline's fade: 1.5 s out, at once in; none under Reduce Motion.
    static let highlightFade: Animation = .easeOut(duration: 1.5)

    var body: some View {
        let shape = Self.shape(outgoing: outgoing)
        VStack(alignment: .leading, spacing: 8) {
            if let quote {
                if quote.available {
                    QuoteView(line: quote, outgoing: outgoing).onTapGesture(perform: onQuote)
                } else {
                    QuoteView(line: quote, outgoing: outgoing)
                }
            }
            Text(text).font(BarkingFont.sans(.body, size: 15)).italic(placeholder)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .foregroundStyle(outgoing ? Color.white : Color.fg)
        .background(outgoing ? Color.accentFill : Color.surfaceCard, in: shape)
        .overlay(shape.stroke(outgoing ? Color.clear : Color.border, lineWidth: 1))
        .overlay {
            shape.stroke(outgoing ? Color.fg : Color.accent, lineWidth: 3).opacity(highlighted ? 1 : 0)
                .animation(highlighted ? nil : Motion.gated(Self.highlightFade, reduceMotion: reduceMotion),
                           value: highlighted)
                .allowsHitTesting(false)
        }
        .contentShape(.contextMenuPreview, shape)
    }
}

/// What is left of an ephemeral, rounded up (spec deletion/ephemeral §5.5):
/// "<1 min" under a minute, then minutes ("4 min"), hours ("2 h") under a
/// day, days ("3 d", « 3 j ») beyond.
func remainingLabel(seconds: Int, bundle: Bundle = .main, locale: Locale = .current) -> String {
    func up(_ unit: Int) -> Int { (seconds + unit - 1) / unit }
    switch seconds {
    case ..<60: return String(localized: "<1 min", bundle: bundle, locale: locale)
    case ..<3_600: return String(localized: "\(up(60)) min", bundle: bundle, locale: locale)
    case ..<86_400: return String(localized: "\(up(3_600)) h", bundle: bundle, locale: locale)
    default: return String(localized: "\(up(86_400)) d", bundle: bundle, locale: locale)
    }
}

/// `remainingLabel` for VoiceOver (spec §5.5): the same rounding, the
/// units spelled out ("4 minutes", "2 days").
func spokenRemainingLabel(seconds: Int, bundle: Bundle = .main, locale: Locale = .current) -> String {
    func up(_ unit: Int) -> Int { (seconds + unit - 1) / unit }
    switch seconds {
    case ..<60: return String(localized: "less than a minute", bundle: bundle, locale: locale)
    case ..<3_600: return String(localized: "\(up(60)) minutes", bundle: bundle, locale: locale)
    case ..<86_400: return String(localized: "\(up(3_600)) hours", bundle: bundle, locale: locale)
    default: return String(localized: "\(up(86_400)) days", bundle: bundle, locale: locale)
    }
}

/// Under an ephemeral bubble: an hourglass and the time left, read again
/// each minute. VoiceOver reads it in the bubble's value instead.
struct EphemeralCountdown: View {
    /// The seconds left at a date (`ConversationModel.Item.remaining`).
    let remaining: (Date) -> Int
    let alignment: HorizontalAlignment
    @Environment(\.locale) private var locale

    var body: some View {
        TimelineView(.everyMinute) { context in
            HStack(spacing: Space.s1) {
                Image(systemName: "hourglass").font(.bSymbol(11, relativeTo: .caption, weight: .semibold))
                Text(verbatim: remainingLabel(seconds: remaining(context.date), bundle: .strings(for: locale),
                                              locale: locale))
                    .font(.bMeta)
            }
            .foregroundStyle(Color.fgSoft)
            .frame(maxWidth: .infinity, alignment: Alignment(horizontal: alignment, vertical: .center))
        }
        .accessibilityHidden(true)
    }
}

/// How a chip is drawn: the stroke, its dash, the fill and the width, plus
/// a ⚠︎ after the count. Only my chips carry the send state of my reaction;
/// the shape says it as much as the colour (dashed, solid, ⚠︎).
struct ReactionChipLook: Equatable {
    let stroke: Color
    let dashed: Bool
    let fill: Color
    let lineWidth: CGFloat
    let warning: Bool

    static func of(mine: Bool, state: DeliveryState?) -> ReactionChipLook {
        guard mine else {
            return ReactionChipLook(stroke: .border, dashed: false, fill: .surfaceCard, lineWidth: 1, warning: false)
        }
        switch state {
        case .pending?:
            return ReactionChipLook(stroke: .borderStrong, dashed: true, fill: .surfaceAlt, lineWidth: 1, warning: false)
        case .received?:
            return ReactionChipLook(stroke: .accentFill, dashed: false, fill: Color.accentFill.opacity(0.12),
                                    lineWidth: 1.5, warning: false)
        case .notDelivered?:
            return ReactionChipLook(stroke: .warnBorder, dashed: false, fill: .warnBg, lineWidth: 1, warning: true)
        case .onNetwork?, nil:
            return ReactionChipLook(stroke: .accent, dashed: false, fill: .surfaceCard, lineWidth: 1, warning: false)
        }
    }
}

/// The emoji under a bubble: `emoji count` in a capsule; mine are outlined
/// by the send state of my latest reaction (`myState`); a tap toggles mine.
/// Each chip is one VoiceOver element.
struct ReactionChips: View {
    let chips: [ReactionChip]
    let outgoing: Bool
    var myState: DeliveryState?
    let toggle: (String) -> Void
    @Environment(\.locale) private var locale

    var body: some View {
        FlowLayout(spacing: 4) {
            ForEach(chips, id: \.emoji) { chip in
                let look = ReactionChipLook.of(mine: chip.mine, state: myState)
                Button { toggle(chip.emoji) } label: {
                    HStack(spacing: 4) {
                        Text(verbatim: "\(chip.emoji) \(chip.count)")
                        if look.warning {
                            Text(verbatim: "\u{26A0}\u{FE0E}").foregroundStyle(Color.warnFg)
                        }
                    }
                    .font(BarkingFont.sans(.footnote, size: 13))
                    .foregroundStyle(Color.fg)
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .frame(minHeight: 28)
                    .background(look.fill, in: .capsule)
                    .overlay(Capsule().stroke(look.stroke, style: StrokeStyle(lineWidth: look.lineWidth,
                                                                              dash: look.dashed ? [3, 2] : [])))
                    .contentShape(.capsule)
                }
                .buttonStyle(.plain)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text(verbatim: chip.label(state: myState, bundle: .strings(for: locale),
                                                              locale: locale)))
                .accessibilityAddTraits(chip.mine ? .isSelected : [])
            }
        }
        .frame(maxWidth: .infinity, alignment: outgoing ? .trailing : .leading)
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
