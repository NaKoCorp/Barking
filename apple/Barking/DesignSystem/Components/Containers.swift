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

    /// A trailing action (UI review U-23): "Check now ›", 44 pt, with a hint
    /// that says where it goes.
    struct Action {
        let label: LocalizedStringKey
        let hint: LocalizedStringKey
        let perform: () -> Void
    }

    let kind: Kind
    let title: Text
    var message: LocalizedStringKey?
    var action: Action?

    init(kind: Kind, title: LocalizedStringKey, message: LocalizedStringKey? = nil, action: Action? = nil) {
        self.init(kind: kind, title: Text(title), message: message, action: action)
    }

    /// A title already localized (a sentence built with its arguments).
    init(kind: Kind, verbatim title: String, message: LocalizedStringKey? = nil, action: Action? = nil) {
        self.init(kind: kind, title: Text(verbatim: title), message: message, action: action)
    }

    private init(kind: Kind, title: Text, message: LocalizedStringKey?, action: Action?) {
        self.kind = kind
        self.title = title
        self.message = message
        self.action = action
    }

    private var colors: (bg: Color, fg: Color, border: Color) {
        switch kind {
        case .info: (.bannerBg, .bannerFg, .bannerBg)
        case .warning: (.warnBg, .warnFg, .warnBorder)
        case .danger: (.surfaceCard, .danger, .danger)
        }
    }

    var body: some View {
        let content = VStack(alignment: .leading, spacing: Space.s1) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: kind == .info ? "info.circle" : "exclamationmark.triangle")
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    title.fontWeight(.semibold)
                    if let message { Text(message) }
                }
                Spacer(minLength: 0)
            }
            if let action {
                // The banner's own colour: `warnFg` is 4.5:1 or more on its ground,
                // where `accent` is not on every banner.
                Button(action: action.perform) {
                    HStack(spacing: Space.s1) {
                        Text(action.label)
                        Text(verbatim: "›").accessibilityHidden(true)
                    }
                    .font(BarkingFont.mono(.footnote, size: 13, weight: .semibold))
                    .frame(minHeight: 44)
                    .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .accessibilityHint(Text(action.hint))
                .frame(maxWidth: .infinity, alignment: .trailing)
            }
        }
        .font(.bBodySmall)
        .foregroundStyle(colors.fg)
        .padding(.horizontal, 12)
        .padding(.top, 12)
        .padding(.bottom, action == nil ? 12 : 0)
        .background(colors.bg, in: .rect(cornerRadius: Radius.chip))
        .overlay(RoundedRectangle(cornerRadius: Radius.chip).stroke(colors.border, lineWidth: 1))
        if action == nil {
            content.accessibilityElement(children: .combine)
        } else {
            // The text and the action stay two elements: a combined banner
            // would hide its button.
            content.accessibilityElement(children: .contain)
        }
    }
}

/// A group of rows on a flat card (UI review §4): `surfaceCard`, radius 12,
/// 1 px `border`, and a 1 px `border` divider between rows. Brand screens
/// use it in place of `Form`, whose iOS 26 rows turn into capsules.
struct FormCard<Content: View>: View {
    @ViewBuilder let content: Content

    init(@ViewBuilder content: () -> Content) { self.content = content() }

    var body: some View {
        VStack(spacing: 0) {
            Group(subviews: content) { rows in
                ForEach(rows) { row in
                    if row.id != rows.first?.id { Rectangle().fill(Color.border).frame(height: 1) }
                    row
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
        .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
    }
}

/// Sizes of a `FormRow`.
enum FormRowMetrics {
    /// Row inset inside a card.
    static let inset: CGFloat = 16

    static func minHeight(hasSubtitle: Bool) -> CGFloat { hasSubtitle ? 56 : 44 }
}

/// One row of a `FormCard`: an optional icon tile, a title (sans 15
/// semibold) and subtitle (sans 13 `fgMuted`) that wrap leading, and an
/// accessory (a chevron, a switch, a menu, a value).
struct FormRow<Accessory: View>: View {
    private let title: Text
    private let subtitle: Text?
    private let icon: String?
    private let accessory: Accessory
    /// The icon tile grows with the text, up to 48 pt.
    @ScaledMetric(relativeTo: .subheadline) private var tile: CGFloat = 32

    init(_ title: LocalizedStringKey, subtitle: LocalizedStringKey? = nil, icon: String? = nil,
         @ViewBuilder accessory: () -> Accessory) {
        self.init(title: Text(title), subtitle: subtitle.map { Text($0) }, icon: icon, accessory: accessory)
    }

    /// Title or subtitle from data or with a custom look (a device name, a
    /// fingerprint).
    init(title: Text, subtitle: Text? = nil, icon: String? = nil, @ViewBuilder accessory: () -> Accessory) {
        self.title = title
        self.subtitle = subtitle
        self.icon = icon
        self.accessory = accessory()
    }

    var body: some View {
        HStack(spacing: Space.s3) {
            if let icon {
                Image(systemName: icon).font(.bSymbol(15, relativeTo: .subheadline, maximum: 22))
                    .foregroundStyle(Color.accent)
                    .frame(width: min(tile, 48), height: min(tile, 48))
                    .background(Color.wash, in: .rect(cornerRadius: Radius.tile))
                    .accessibilityHidden(true)
            }
            // Leading, also when a long French subtitle wraps (U-10).
            VStack(alignment: .leading, spacing: 2) {
                title.font(.bBody.weight(.semibold)).foregroundStyle(Color.fg)
                subtitle?.font(BarkingFont.sans(.footnote, size: 13)).foregroundStyle(Color.fgMuted)
            }
            .multilineTextAlignment(.leading)
            .frame(maxWidth: .infinity, alignment: .leading)
            accessory
        }
        .padding(.horizontal, FormRowMetrics.inset)
        .padding(.vertical, Space.s2)
        .frame(minHeight: FormRowMetrics.minHeight(hasSubtitle: subtitle != nil))
        .contentShape(.rect)
    }
}

extension FormRow where Accessory == EmptyView {
    init(_ title: LocalizedStringKey, subtitle: LocalizedStringKey? = nil, icon: String? = nil) {
        self.init(title, subtitle: subtitle, icon: icon) { EmptyView() }
    }
}

/// The trailing glyph of a row that opens something: a chevron, or an
/// arrow for a row that leaves the app. Not read by VoiceOver.
struct RowGlyph: View {
    var symbol = "chevron.right"

    var body: some View {
        Image(systemName: symbol).font(.bSymbol(13, relativeTo: .footnote, weight: .semibold, maximum: 20))
            .foregroundStyle(Color.fgMuted)
            .accessibilityHidden(true)
    }
}

enum DangerZoneMetrics {
    /// Added to the screen's 24 pt section gap: 32 pt above the zone.
    static let extraTop: CGFloat = Space.danger - Space.section
}

/// The destructive actions of a screen, at the bottom, 32 pt below the rest
/// and on no shared card (UI review U-2). Placed in a `barkingScreen` stack.
struct DangerZone<Content: View>: View {
    let label: LocalizedStringKey?
    @ViewBuilder let content: Content

    init(_ label: LocalizedStringKey? = nil, @ViewBuilder content: () -> Content) {
        self.label = label
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            if let label { SectionLabel(label) }
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, DangerZoneMetrics.extraTop)
    }
}

extension View {
    /// A brand screen (UI review §4): `surface` ground, 20 pt gutter, 24 pt
    /// between sections, and room for the floating tab bar on a tab root.
    func barkingScreen(tabRoot: Bool = false) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.section) { self }
                .padding(.horizontal, Space.gutter)
                .padding(.top, Space.s2)
                .padding(.bottom, Space.section)
        }
        .scrollDismissesKeyboard(.interactively)
        .contentMargins(.bottom, tabRoot ? 96 : 0, for: .scrollContent)
        .background(Color.surface)
    }

    /// The screen's call to action, pinned above the keyboard and the home
    /// indicator, never in a list row (U-4): 20 pt gutter, 12 pt top,
    /// `surface` ground and a 1 px `border` on top.
    func ctaBar<Bar: View>(@ViewBuilder _ bar: () -> Bar) -> some View {
        safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: Space.s2, content: bar)
                .padding(.horizontal, Space.gutter)
                .padding(.top, Space.s3)
                .padding(.bottom, Space.s2)
                .frame(maxWidth: .infinity)
                .background(Color.surface)
                .overlay(alignment: .top) { Rectangle().fill(Color.border).frame(height: 1) }
        }
    }
}

#if DEBUG
#Preview("Form card") {
    PreviewMatrix {
        FormCard {
            FormRow("Linked devices", subtitle: "receive, write, send", icon: "laptopcomputer.and.iphone") { RowGlyph() }
            FormRow("Security", subtitle: "Lock and erase", icon: "lock") { RowGlyph() }
            FormRow("Lock Barking") { Toggle(isOn: .constant(true)) { EmptyView() }.labelsHidden().tint(Color.toggleOn) }
        }
    }
}
#endif
