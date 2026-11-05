import BarkingKit
import SwiftUI

/// Screen 4 of the mockup, without route chips nor the "Send from" chooser.
struct ConversationView: View {
    let core: CoreService
    @State private var model: ConversationModel
    @Environment(\.scenePhase) private var phase

    init(core: CoreService, contact: String) {
        self.core = core
        _model = State(initialValue: ConversationModel(contact: contact, core: core))
    }

    var body: some View {
        VStack(spacing: 0) {
            if model.keyChanged {
                Banner(kind: .danger, title: "\(model.name)'s key changed.",
                       message: "Compare your safety code again.")
                    .padding(.horizontal, 16).padding(.top, 8)
            }
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(groupedByDay, id: \.day) { group in
                            Text(group.day, format: .dateTime.weekday(.wide).day().month())
                                .font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgSoft)
                                .padding(.top, 8)
                            ForEach(group.items) { item in bubble(item).id(item.id) }
                        }
                    }
                    .padding(16)
                }
                .onChange(of: model.items.last?.id) { _, id in if let id { proxy.scrollTo(id, anchor: .bottom) } }
            }
            if let e = model.sendError {
                Text(e).font(.footnote).foregroundStyle(Color.danger).padding(.horizontal, 16)
            }
            ComposerView(model: model)
        }
        .background(Color.surface)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                NavigationLink {
                    SafetyCodeView(core: core, contact: model.contact)
                } label: {
                    HStack(spacing: 8) {
                        Avatar(name: model.name, fingerprint: model.contact, size: 38)
                        VStack(alignment: .leading, spacing: 0) {
                            Text(verbatim: model.name).font(BarkingFont.sans(.headline, size: 16, weight: .semibold))
                                .foregroundStyle(Color.fg)
                            Text(model.verified ? "✓ verified · safety code matched" : "not verified")
                                .font(BarkingFont.mono(.caption2, size: 11))
                                .foregroundStyle(model.verified ? Color.ok : Color.fgSoft)
                        }
                    }
                }
            }
        }
        .onDisappear { model.onDisappear() }
        .task {
            await model.onAppear()
            for await change in await core.changes {
                switch change {
                case .messages, .contacts, .network: await model.reload()
                default: break
                }
            }
        }
    }

    private struct DayGroup { let day: Date; let items: [ConversationModel.Item] }

    private var groupedByDay: [DayGroup] {
        let cal = Calendar.current
        let groups = Dictionary(grouping: model.items) { cal.startOfDay(for: $0.at) }
        return groups.keys.sorted().map { DayGroup(day: $0, items: groups[$0] ?? []) }
    }

    @ViewBuilder private func bubble(_ item: ConversationModel.Item) -> some View {
        Bubble(text: item.text, outgoing: item.outgoing) {
            HStack(spacing: 4) {
                Text(item.at, format: .dateTime.hour().minute())
                if item.status == .failed {
                    Button { Task { await model.retry(item.id) } } label: {
                        Text("⚠︎ not sent — tap to retry")
                    }
                    .foregroundStyle(item.outgoing ? Color.white : Color.danger)
                } else if item.status == .queued {
                    StatusGlyph(status: .queued)
                    Text("queued")
                } else {
                    StatusGlyph(status: item.status)
                }
            }
            .opacity(0.85)
        }
    }
}

/// Text field, byte counter, send button.
struct ComposerView: View {
    @Bindable var model: ConversationModel

    var body: some View {
        VStack(alignment: .trailing, spacing: 4) {
            if model.showsCounter {
                Text(verbatim: "\(model.byteCount) / \(ConversationModel.maxBytes)")
                    .font(BarkingFont.mono(.caption2, size: 11))
                    .foregroundStyle(model.byteCount > ConversationModel.maxBytes ? Color.danger : Color.fgSoft)
            }
            HStack(spacing: 8) {
                TextField("Message", text: $model.draft, axis: .vertical)
                    .lineLimit(1...5)
                    .padding(.horizontal, 14).padding(.vertical, 10)
                    .background(Color.surfaceAlt, in: .capsule)
                Button { Task { await model.send() } } label: {
                    Image(systemName: "arrow.up").font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(.white).frame(width: 40, height: 40)
                        .background(Color.accentFill.opacity(model.canSend ? 1 : 0.4), in: .circle)
                }
                .disabled(!model.canSend)
                .accessibilityLabel(Text("Send"))
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background(Color.surfaceCard)
        .overlay(alignment: .top) { Rectangle().fill(Color.border).frame(height: 1) }
    }
}
