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

/// The only in-page section header: Fira Code 13/500 `fgMuted`, sentence
/// case, never uppercase-tracked. `Eyebrow` stays the only kicker.
struct SectionLabel: View {
    private let text: Text
    init(_ text: LocalizedStringKey) { self.text = Text(text) }
    /// Text from data (a day's title): never a localization key.
    init(verbatim: String) { self.text = Text(verbatim: verbatim) }

    var body: some View {
        text
            .font(.bSectionLabel)
            .foregroundStyle(Color.fgMuted)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityAddTraits(.isHeader)
    }
}

/// A small label on a row: "this device", "admin", "sent 12:01".
/// Fira Code 600 11, radius 4; wraps inside a `FlowLayout`, never inside
/// itself.
struct Tag: View {
    enum Style {
        case accent, neutral, ok, danger

        /// Asset names of the text and its ground.
        var tokens: (text: String, fill: String) {
            switch self {
            case .accent: ("accent", "wash")
            case .neutral: ("fgMuted", "field")
            case .ok: ("ok", "okBg")
            case .danger: ("danger", "surfaceCard")
            }
        }
    }

    private let text: Text
    let style: Style

    init(_ text: LocalizedStringKey, style: Style = .neutral) {
        self.text = Text(text)
        self.style = style
    }

    init(verbatim: String, style: Style = .neutral) {
        self.text = Text(verbatim: verbatim)
        self.style = style
    }

    var body: some View {
        let t = style.tokens
        let shape = RoundedRectangle(cornerRadius: Radius.tag)
        text
            .font(.bTag)
            .lineLimit(1)
            .fixedSize()
            .foregroundStyle(Color(t.text))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(Color(t.fill), in: shape)
            .overlay { if style == .danger { shape.strokeBorder(Color.danger, lineWidth: 1) } }
    }
}

/// Lays its children out in rows, wrapping to the next row when the width
/// runs out (tags, chips).
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews)
        let width = rows.map(\.width).max() ?? 0
        let height = rows.map(\.height).reduce(0, +) + spacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(width: bounds.width, subviews) {
            var x = bounds.minX
            for i in row.items {
                let size = subviews[i].sizeThatFits(.unspecified)
                subviews[i].place(at: CGPoint(x: x, y: y + (row.height - size.height) / 2),
                                  proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += row.height + spacing
        }
    }

    private struct Row { var items: [Int] = []; var width: CGFloat = 0; var height: CGFloat = 0 }

    private func arrange(width: CGFloat, _ subviews: Subviews) -> [Row] {
        var rows: [Row] = [Row()]
        for i in subviews.indices {
            let size = subviews[i].sizeThatFits(.unspecified)
            let extra = rows[rows.count - 1].items.isEmpty ? size.width : rows[rows.count - 1].width + spacing + size.width
            if extra > width, !rows[rows.count - 1].items.isEmpty {
                rows.append(Row())
            }
            var row = rows[rows.count - 1]
            row.width = row.items.isEmpty ? size.width : row.width + spacing + size.width
            row.height = max(row.height, size.height)
            row.items.append(i)
            rows[rows.count - 1] = row
        }
        return rows.filter { !$0.items.isEmpty }
    }
}

/// A status as a glyph plus a word, never colour alone: reachable or
/// verified ● `ok`; waiting or offline ○ `warnFg` (nothing is lost, so not
/// red); checking ○ `fgSoft`; a threat or a wrong answer ✗ `danger`.
struct StatusDot: View {
    enum State {
        case ok, waiting, down, checking

        var glyph: String {
            switch self {
            case .ok: "●"
            case .waiting, .checking: "○"
            case .down: "✗"
            }
        }

        var token: String {
            switch self {
            case .ok: "ok"
            case .waiting: "warnFg"
            case .down: "danger"
            case .checking: "fgSoft"
            }
        }
    }

    let state: State
    let label: LocalizedStringKey

    init(_ state: State, label: LocalizedStringKey) {
        self.state = state
        self.label = label
    }

    var body: some View {
        HStack(spacing: 6) {
            // The system font: Fira Code draws ✗ and ● at another weight.
            Text(verbatim: state.glyph).font(.bSymbol(11, relativeTo: .caption, weight: .bold))
                .accessibilityHidden(true)
            Text(label).font(.bMeta)
        }
        .foregroundStyle(Color(state.token))
        .accessibilityElement(children: .combine)
    }
}

#if DEBUG
#Preview("Text") {
    PreviewMatrix {
        Eyebrow("how your messages travel")
        SectionLabel("Appearance")
        FlowLayout {
            Tag("this device", style: .accent)
            Tag(verbatim: "admin")
            Tag("verified", style: .ok)
            Tag("Remove", style: .danger)
        }
        StatusDot(.ok, label: "Reachable")
        StatusDot(.waiting, label: "Unreachable")
        StatusDot(.checking, label: "Not synced yet")
        StatusDot(.down, label: "Do not trust this contact until you meet")
    }
}
#endif
