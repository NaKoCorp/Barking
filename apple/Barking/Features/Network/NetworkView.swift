import BarkingKit
import SwiftUI

/// Screen 7 of the mockup, Internet only.
struct NetworkView: View {
    let core: CoreService
    @State private var model: NetworkModel
    @State private var adding = false
    @State private var relayId = ""
    @State private var relayAddr = ""

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: NetworkModel(core: core))
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Eyebrow("how your messages travel")
                    ScreenTitle("Network")
                    internetCard
                    Card {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("\(model.pending) packets pending")
                                .font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold)).foregroundStyle(Color.fg)
                            PrimaryButton("Sync now", enabled: !model.syncing) { Task { await model.syncNow() } }
                            if !model.terminal.isEmpty {
                                VStack(alignment: .leading, spacing: 2) {
                                    ForEach(model.terminal, id: \.self) { Text(verbatim: $0) }
                                }
                                .font(BarkingFont.mono(.caption, size: 12))
                                .foregroundStyle(Color(red: 0.85, green: 0.82, blue: 0.91))
                                .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color(red: 0.043, green: 0.035, blue: 0.063), in: .rect(cornerRadius: Radius.card))
                            }
                        }
                    }
                    Text("Internet relays").font(BarkingFont.mono(.footnote, size: 12, weight: .semibold))
                        .foregroundStyle(Color.fgSoft)
                    Card {
                        VStack(alignment: .leading, spacing: 12) {
                            if model.relays.isEmpty {
                                Text("No relay yet. Until public relays exist, add one by hand.")
                                    .foregroundStyle(Color.fgMuted)
                            }
                            ForEach(model.relays, id: \.id) { r in relayRow(r) }
                            Button("+ Add a relay") { adding = true }
                                .font(BarkingFont.mono(.subheadline, size: 14)).foregroundStyle(Color.accent)
                                .frame(minHeight: 44)
                        }
                    }
                }
                .padding(20)
            }
            .background(Color.surface)
            .refreshable { await model.syncNow() }
            .sheet(isPresented: $adding) { addSheet }
        }
        .task {
            await model.load()
            for await change in await core.changes where change == .network { await model.load() }
        }
    }

    private var internetCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Circle().fill(Color.transportNet).frame(width: 8, height: 8).accessibilityHidden(true)
                Text(verbatim: "Internet").font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold))
                    .foregroundStyle(Color.fg)
            }
            switch model.internetReachable {
            case true?: Text("Reachable").foregroundStyle(Color.ok)
            case false?: Text("Unreachable").foregroundStyle(Color.danger)
            case nil: Text("Not synced yet").foregroundStyle(Color.fgSoft)
            }
            if let at = model.lastSync {
                Text("last sync \(at.formatted(date: .omitted, time: .shortened))")
                    .font(BarkingFont.mono(.caption, size: 12)).foregroundStyle(Color.fgSoft)
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
        .overlay(alignment: .top) { Rectangle().fill(Color.transportNet).frame(height: 3) }
        .clipShape(.rect(cornerRadius: Radius.card))
        .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
    }

    private func relayRow(_ r: NodeInfo) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: String(r.id.prefix(12))).font(BarkingFont.mono(.footnote, size: 13)).foregroundStyle(Color.fg)
                Text(verbatim: r.addr).font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgSoft)
                if r.manual { Text("added by hand").font(.caption2).foregroundStyle(Color.fgSoft) }
                else if r.fromCard { Text("from a contact's card").font(.caption2).foregroundStyle(Color.fgSoft) }
            }
            Spacer()
            Text(verbatim: "\(Int(r.score * 100))%").font(BarkingFont.mono(.caption, size: 12)).foregroundStyle(Color.fgMuted)
            ZStack(alignment: .leading) {
                Capsule().fill(Color.surfaceAlt).frame(width: 64, height: 4)
                Capsule().fill(Color.transportNet).frame(width: 64 * CGFloat(r.score), height: 4)
            }
            .accessibilityHidden(true)
        }
    }

    private var addSheet: some View {
        NavigationStack {
            Form {
                TextField("Identifier", text: $relayId).textInputAutocapitalization(.characters).autocorrectionDisabled()
                TextField("ip:port", text: $relayAddr).keyboardType(.numbersAndPunctuation).autocorrectionDisabled()
                Button("Paste a relay link") {
                    if let s = UIPasteboard.general.string, let r = NetworkModel.parseRelay(link: s) {
                        relayId = r.id; relayAddr = r.addr
                    }
                }
                if let e = model.addError { Text(LocalizedStringKey(e)).foregroundStyle(Color.danger) }
            }
            .navigationTitle(Text("Add a relay"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { adding = false } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") { Task { if await model.addRelay(id: relayId, addr: relayAddr) { adding = false } } }
                }
            }
        }
    }
}
