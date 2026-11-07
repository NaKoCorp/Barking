import BarkingKit
import SwiftUI

/// Screen 4 of the mockup, without the "Send from" chooser. The path icon
/// in the header and a bubble's route badge open the path screen.
struct ConversationView: View {
    let core: CoreService
    @State private var model: ConversationModel
    @Environment(\.scenePhase) private var phase
    /// The message whose path is shown.
    @State private var pathOf: Int64?

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
                            Text(verbatim: DayLabel.text(for: group.day))
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
                Text(LocalizedStringKey(e)).font(.footnote).foregroundStyle(Color.danger).padding(.horizontal, 16)
            }
            ComposerView(model: model)
        }
        .background(Color.surface)
        .navigationBarTitleDisplayMode(.inline)
        .navigationDestination(item: $pathOf) { id in
            PathView(core: core, messageId: id, contact: model.contact, contactName: model.name)
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    pathOf = model.lastMessageId
                } label: {
                    Image(systemName: "point.topleft.down.to.point.bottomright.curvepath")
                }
                .disabled(model.lastMessageId == nil)
                .accessibilityLabel(Text("Message path"))
                .accessibilityIdentifier("conversation.path")
            }
            ToolbarItem(placement: .principal) {
                ChatHeader(core: core, model: model)
            }
        }
        .toolbar(.hidden, for: .tabBar)
        .onDisappear { model.onDisappear() }
        .task {
            await model.onAppear()
            for await change in await core.changes {
                switch change {
                case .messages, .contacts, .network: await model.reload()
                // States only; the rows are patched in place later (Lot M).
                case .delivery(let contact, _) where contact == model.contact: await model.reload()
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
                        Text("⚠︎ not sent, tap to retry")
                    }
                    .foregroundStyle(item.outgoing ? Color.white : Color.danger)
                } else if item.status == .queued {
                    StatusGlyph(status: .queued)
                    Text("queued")
                } else {
                    StatusGlyph(status: item.status)
                }
                if let route = RouteBadge.text(for: item.route) {
                    Button { pathOf = item.id } label: { RouteChip(text: route, outgoing: item.outgoing) }
                        .buttonStyle(.plain)
                        .accessibilityHint(Text("Message path"))
                }
            }
            .opacity(0.85)
        }
    }
}

/// The conversation's title (U-20): one 44 pt button to the safety code,
/// the name over "○ not verified ›" or "✓ verified ›". `ChatTitle` keeps it
/// inside the bar at AX3; a long press shows it larger, as system bars do.
private struct ChatHeader: View {
    let core: CoreService
    let model: ConversationModel

    var body: some View {
        NavigationLink {
            SafetyCodeView(core: core, contact: model.contact)
        } label: {
            ChatTitle(name: model.name, fingerprint: model.contact, trust: model.trust)
                .contentShape(.rect)
        }
        .accessibilityShowsLargeContentViewer {
            Text(verbatim: model.name)
        }
        .accessibilityElement(children: .combine)
        .accessibilityHint(Text("Opens the safety code."))
        .accessibilityIdentifier("conversation.header")
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
                Button {
                    Haptic.send.play()
                    Task { await model.send() }
                } label: {
                    // Disabled is a slot, never a translucent purple (U-3).
                    Image(systemName: "arrow.up").font(.bSymbol(17, weight: .semibold, maximum: 26))
                        .foregroundStyle(model.canSend ? Color.white : Color.fgDisabled)
                        .frame(width: 44, height: 44)
                        .background(model.canSend ? Color.accentFill : Color.fillDisabled, in: .circle)
                        .overlay { if !model.canSend { Circle().strokeBorder(Color.borderDisabled, lineWidth: 1) } }
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

/// "Today", "Yesterday", then the date, above each day of messages.
enum DayLabel {
    static func text(for day: Date, now: Date = .now) -> String {
        let cal = Calendar.current
        if cal.isDate(day, inSameDayAs: now) { return String(localized: "Today") }
        if let y = cal.date(byAdding: .day, value: -1, to: now), cal.isDate(day, inSameDayAs: y) {
            return String(localized: "Yesterday")
        }
        return day.formatted(.dateTime.weekday(.wide).day().month())
    }
}
