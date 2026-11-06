import BarkingKit
import SwiftUI

/// Settings › Transparency (spec block 2b §5): the journal of what the core
/// did, and where my data is.
struct TransparencyView: View {
    @State private var model: TransparencyModel

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
                Toggle("Security only", isOn: Binding(get: { model.securityOnly },
                                                       set: { on in Task { await model.setSecurityOnly(on) } }))
                    .font(.system(size: 15)).tint(Color.accent)
                    .accessibilityIdentifier("transparency.securityOnly")
                if model.isEmpty, !model.loading {
                    Text("Nothing yet").font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fgMuted)
                        .padding(.top, 6)
                }
                ForEach(model.days) { day in
                    Text(model.title(of: day)).textCase(.uppercase)
                        .font(BarkingFont.sans(.caption, size: 12, weight: .semibold)).tracking(0.6)
                        .foregroundStyle(Color.fgSoft).padding(.top, 10)
                        .accessibilityAddTraits(.isHeader)
                    VStack(spacing: 0) {
                        ForEach(Array(day.rows.enumerated()), id: \.element.id) { i, row in
                            if i > 0 { Rectangle().fill(Color.border).frame(height: 1) }
                            logRow(row).onAppear {
                                if row.id == model.days.last?.rows.last?.id { Task { await model.loadMore() } }
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
        Text(title).textCase(.uppercase)
            .font(.system(size: 12, weight: .semibold)).tracking(0.6)
            .foregroundStyle(Color.fgMuted).padding(.top, 8)
            .accessibilityAddTraits(.isHeader)
    }

    private func dataRow(_ row: DataRow) -> some View {
        HStack(alignment: .top, spacing: 12) {
            icon(row.icon, accent: true)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: row.title).font(.system(size: 15, weight: .semibold)).foregroundStyle(Color.fg)
                Text(verbatim: row.detail).font(.system(size: 12.5)).foregroundStyle(Color.fgMuted)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .accessibilityElement(children: .combine)
    }

    private func logRow(_ row: LogRow) -> some View {
        HStack(alignment: .top, spacing: 12) {
            icon(row.icon, accent: row.security)
            VStack(alignment: .leading, spacing: 3) {
                Text(verbatim: row.text).font(.system(size: 14)).foregroundStyle(Color.fg)
                    .fixedSize(horizontal: false, vertical: true)
                Text(row.at, format: .dateTime.hour().minute())
                    .font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgSoft)
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .accessibilityElement(children: .combine)
    }

    private func icon(_ name: String, accent: Bool) -> some View {
        Image(systemName: name).font(.system(size: 14))
            .foregroundStyle(accent ? Color.accent : Color.fgMuted)
            .frame(width: 32, height: 32)
            .background(accent ? Color.wash : Color.field, in: .rect(cornerRadius: Radius.tile))
            .accessibilityHidden(true)
    }
}
