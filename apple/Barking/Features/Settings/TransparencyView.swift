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

    init(core: CoreService) {
        _model = State(initialValue: TransparencyModel(core: core))
    }

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 10) {
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

                heading("Journal").padding(.top, 14)
                BarkingSegmented("Journal filter",
                                 selection: Binding(get: { model.filter }, set: { f in Task { await model.setFilter(f) } }),
                                 options: [(JournalFilter.everything, LocalizedStringKey("Everything")),
                                           (.keysAndDevices, LocalizedStringKey("Keys and devices"))],
                                 identifier: "transparency.filter")
                Text("Keys and devices: key changes, devices added or removed, unreadable messages — the events to watch first.")
                    .font(BarkingFont.sans(.caption, size: 12.5)).foregroundStyle(Color.fgMuted)
                if model.isEmpty, !model.loading {
                    Text("Nothing yet").font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fgMuted)
                        .padding(.top, 6)
                }
                ForEach(model.days) { day in
                    SectionLabel(verbatim: model.title(of: day)).padding(.top, 10)
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
            .padding(.horizontal, 20)
            .padding(.bottom, 16)
        }
        .background(Color.surface)
        .navigationTitle(Text("Transparency"))
        .navigationBarTitleDisplayMode(.inline)
        .task { await model.load() }
    }

    private func heading(_ title: LocalizedStringKey) -> some View {
        SectionLabel(title).padding(.top, 8)
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

    private func logRow(_ row: LogRow) -> some View {
        let open = expanded.contains(row.id)
        return Button {
            if open { expanded.remove(row.id) } else { expanded.insert(row.id) }
        } label: {
            HStack(alignment: .top, spacing: 12) {
                icon(row.icon, accent: row.security)
                VStack(alignment: .leading, spacing: 3) {
                    // Long entries (a packet's lesson on what relays see) show 3
                    // lines until tapped; VoiceOver reads the whole text.
                    Text(verbatim: row.text).font(BarkingFont.sans(.subheadline, size: 14)).foregroundStyle(Color.fg)
                        .lineLimit(open ? nil : 3).multilineTextAlignment(.leading)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(row.at, format: .dateTime.hour().minute())
                        .font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgSoft)
                }
                Spacer(minLength: 0)
            }
            .padding(12)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityHint(open ? "" : String(localized: "Tap to show the whole text"))
    }

    private func icon(_ name: String, accent: Bool) -> some View {
        Image(systemName: name).font(.bSymbol(14, relativeTo: .subheadline, maximum: 21))
            .foregroundStyle(accent ? Color.accent : Color.fgMuted)
            .frame(width: min(tile, 48), height: min(tile, 48))
            .background(accent ? Color.wash : Color.field, in: .rect(cornerRadius: Radius.tile))
            .accessibilityHidden(true)
    }
}
