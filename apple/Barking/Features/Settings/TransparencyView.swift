import BarkingKit
import SwiftUI

/// Settings › Transparency (spec block 2b §5): the journal of what the core
/// did, and where my data is.
struct TransparencyView: View {
    /// Icon tiles grow with the text, up to 48 pt.
    @ScaledMetric(relativeTo: .subheadline) private var tile: CGFloat = 32
    @State private var model: TransparencyModel
    /// Entries the user opened to read in full.
    @State private var expanded: Set<Int64> = []
    @Environment(\.dynamicTypeSize) private var size

    init(core: CoreService) {
        _model = State(initialValue: TransparencyModel(core: core))
    }

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Space.s2) {
                heading("Where my data is")
                VStack(spacing: 0) {
                    ForEach(Array(model.dataRows.enumerated()), id: \.element.id) { i, row in
                        if i > 0 { Rectangle().fill(Color.border).frame(height: 1) }
                        dataRow(row)
                    }
                }
                .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
                .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
                .accessibilityIdentifier("transparency.data")

                wakeUps

                heading("Journal")
                BarkingSegmented("Journal filter",
                                 selection: Binding(get: { model.filter }, set: { f in Task { await model.setFilter(f) } }),
                                 options: [(JournalFilter.everything, LocalizedStringKey("Everything")),
                                           (.keysAndDevices, LocalizedStringKey("Keys and devices"))],
                                 identifier: "transparency.filter")
                Text("Keys and devices: key changes, devices added or removed, unreadable messages. These are the events to watch first.")
                    .font(BarkingFont.sans(.caption, size: 12.5)).foregroundStyle(Color.fgMuted)
                if model.isEmpty, !model.loading {
                    Text("Nothing yet").font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fgMuted)
                        .padding(.top, 6)
                }
                ForEach(model.days) { day in
                    SectionLabel(verbatim: model.title(of: day)).padding(.top, Space.section - Space.s2)
                    VStack(spacing: 0) {
                        ForEach(Array(day.rows.enumerated()), id: \.element.id) { i, row in
                            if i > 0 { Rectangle().fill(Color.border).frame(height: 1) }
                            logRow(row).onAppear {
                                if row.id == model.oldestID { Task { await model.loadMore() } }
                            }
                        }
                    }
                    .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
                    .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
                }
            }
            .padding(.horizontal, Space.gutter)
            .padding(.bottom, Space.section)
        }
        .background(Color.surface)
        .navigationTitle(Text("Transparency"))
        .navigationBarTitleDisplayMode(.inline)
        .task { await model.load() }
    }

    /// "Wake-ups" (spec §5.7): the state and why, the nodes holding a
    /// subscription, who sees what, and the last wake handled.
    @ViewBuilder private var wakeUps: some View {
        heading("Wake-ups")
        card(id: "transparency.wake.state") {
            dataRow(DataRow(id: "state", icon: "bolt", title: String(localized: "State"), detail: stateText))
        }

        SectionLabel("Subscribed nodes").padding(.top, Space.section - Space.s2)
        if model.wakeRows.isEmpty {
            Text("None").font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fgMuted)
                .accessibilityIdentifier("transparency.wake.none")
        } else {
            card(id: "transparency.wake.nodes") {
                ForEach(Array(model.wakeRows.enumerated()), id: \.element.id) { i, row in
                    if i > 0 { Rectangle().fill(Color.border).frame(height: 1) }
                    dataRow(DataRow(id: row.id, icon: "point.3.connected.trianglepath.dotted",
                                    title: row.title, detail: row.detail))
                }
            }
        }

        SectionLabel("Who sees what").padding(.top, Space.section - Space.s2)
        card(id: "transparency.wake.who") {
            dataRow(DataRow(id: "node", icon: "point.3.connected.trianglepath.dotted", title: String(localized: "Node"),
                            detail: String(localized: "A mailbox, an opaque sealed token and the relay's address.")))
            Rectangle().fill(Color.border).frame(height: 1)
            dataRow(DataRow(id: "relay", icon: "arrow.left.arrow.right", title: String(localized: "Relay"),
                            detail: String(localized: "That a node asks to wake a token.")))
            Rectangle().fill(Color.border).frame(height: 1)
            dataRow(DataRow(id: "apple", icon: "apple.logo", title: String(localized: "Apple"),
                            detail: String(localized: "That an iPhone receives a Barking push.")))
        }
        Text("None of them sees the sender or the content.")
            .font(BarkingFont.sans(.caption, size: 12.5)).foregroundStyle(Color.fgMuted)
        Text("Limit: a node that cooperates with the relay or with Apple can link a mailbox to this iPhone. Turning instant notifications off prevents it.")
            .font(BarkingFont.sans(.caption, size: 12.5)).foregroundStyle(Color.fgMuted)

        card(id: "transparency.wake.last") {
            dataRow(DataRow(id: "last", icon: "clock", title: String(localized: "Last wake handled"), detail: lastWakeText))
        }
        .padding(.top, Space.s2)
    }

    private var stateText: String {
        if model.waitingForToken { return String(localized: "Waiting for Apple's token") }
        switch model.wakeState {
        case .on: return String(localized: "On")
        case .off: return String(localized: "Off: instant notifications are turned off")
        case .notAsked, .denied: return String(localized: "Off: notifications are not allowed on this iPhone")
        case .noRelay: return String(localized: "Off: no wake-up relay in this build")
        }
    }

    private var lastWakeText: String {
        guard let at = model.lastWake else { return String(localized: "Never") }
        return at.formatted(.relative(presentation: .named))
    }

    private func card<Content: View>(id: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(spacing: 0, content: content)
            .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
            .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
            .accessibilityIdentifier(id)
    }

    /// 24 pt above a section label, 8 below (U-14); the stack gives the 8.
    private func heading(_ title: LocalizedStringKey) -> some View {
        SectionLabel(title).padding(.top, Space.section - Space.s2)
    }

    private func dataRow(_ row: DataRow) -> some View {
        HStack(alignment: .top, spacing: 12) {
            icon(row.icon, accent: true)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: row.title).font(BarkingFont.sans(.subheadline, size: 15, weight: .semibold)).foregroundStyle(Color.fg)
                Text(verbatim: row.detail).font(BarkingFont.sans(.caption, size: 12.5)).foregroundStyle(Color.fgMuted)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .accessibilityElement(children: .combine)
    }

    /// A journal row (U-30): the title (one line), a Fira meta line led by
    /// the direction glyph, then the explanation in two lines; a tap shows
    /// it whole. No icon tile: the glyph says which way it went.
    private func logRow(_ row: LogRow) -> some View {
        JournalRowView(row: row, open: expanded.contains(row.id), titleLines: size.isAccessibilitySize ? 3 : 1) {
            if expanded.contains(row.id) { expanded.remove(row.id) } else { expanded.insert(row.id) }
        }
    }

    private func icon(_ name: String, accent: Bool) -> some View {
        Image(systemName: name).font(.bSymbol(14, relativeTo: .subheadline, maximum: 21))
            .foregroundStyle(accent ? Color.accent : Color.fgMuted)
            .frame(width: min(tile, 48), height: min(tile, 48))
            .background(accent ? Color.wash : Color.field, in: .rect(cornerRadius: Radius.tile))
            .accessibilityHidden(true)
    }
}

/// Whether two lines cut a journal text: its full height against its
/// two-line height, both measured at the row's width (review B4 #6).
enum JournalText {
    static func isCut(full: CGFloat, clamped: CGFloat) -> Bool { full > clamped + 1 }
}

/// One journal row. The disclosure (⌄ / ⌃) and the VoiceOver hint show only
/// when two lines really cut the text, at this width, size and language.
private struct JournalRowView: View {
    let row: LogRow
    let open: Bool
    let titleLines: Int
    let toggle: () -> Void
    @State private var fullHeight: CGFloat = 0
    @State private var clampedHeight: CGFloat = 0

    private var cut: Bool { JournalText.isCut(full: fullHeight, clamped: clampedHeight) }

    var body: some View {
        Button(action: toggle) {
            VStack(alignment: .leading, spacing: 4) {
                Text(verbatim: row.title)
                    .font(BarkingFont.sans(.subheadline, size: 15, weight: .semibold)).foregroundStyle(Color.fg)
                    .lineLimit(titleLines)
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(verbatim: row.glyph.symbol)
                        .font(row.glyph.usesSystemFont ? .bSymbol(12, relativeTo: .caption, weight: .bold) : .bMeta)
                        .foregroundStyle(Color(row.glyph.token))
                        .accessibilityHidden(true)
                    Text(verbatim: row.meta).font(.bMeta).foregroundStyle(Color.fgSoft)
                        .multilineTextAlignment(.leading)
                }
                text(lines: open ? nil : 2)
                    .background(alignment: .topLeading) { measures }
                if cut {
                    Text(verbatim: open ? "⌃" : "⌄").font(.bMeta).foregroundStyle(Color.fgSoft)
                        .frame(maxWidth: .infinity, alignment: .trailing)
                        .accessibilityHidden(true)
                }
            }
            .padding(.horizontal, FormRowMetrics.inset)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityHint(cut && !open ? String(localized: "Tap to show the whole text") : "")
    }

    private func text(lines: Int?) -> some View {
        Text(verbatim: row.text).font(.bBodySmall).foregroundStyle(Color.fgMuted)
            .lineLimit(lines).multilineTextAlignment(.leading)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// Two hidden copies at the same width: the whole text and two lines.
    private var measures: some View {
        ZStack(alignment: .topLeading) {
            text(lines: nil)
                .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { fullHeight = $0 }
            text(lines: 2)
                .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { clampedHeight = $0 }
        }
        .hidden()
        .accessibilityHidden(true)
    }
}
