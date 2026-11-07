import BarkingKit
import SwiftUI

/// Screen 4 of the mockup, without the "Send from" chooser. Each bubble
/// has its time and state line under it (spec Lot M §6.3); a bubble opens
/// the message sheet (§6.4). The header button opens "Deliveries" (§6.5).
struct ConversationView: View {
    let core: CoreService
    @State private var model: ConversationModel
    @Environment(\.scenePhase) private var phase
    /// Told while this conversation is on screen: syncs every 15 s.
    @Environment(\.syncLoop) private var syncLoop
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// The message whose sheet is open.
    @State private var sheetOf: SheetTarget?
    /// The message the delete confirmation is open for, as it was then.
    @State private var confirming: ConversationModel.Item?
    /// The confirmation adds "Your other devices keep their copy." (§7.4).
    @State private var confirmingKeeps = false

    /// A message to bring into view once the conversation is loaded.
    let focus: Int64?
    @State private var scrollTarget: Int64?

    private struct SheetTarget: Identifiable { let id: Int64 }

    init(core: CoreService, contact: String, focus: Int64? = nil) {
        self.core = core
        self.focus = focus
        _model = State(initialValue: ConversationModel(contact: contact, core: core))
    }

    var body: some View {
        VStack(spacing: 0) {
            if model.keyChanged {
                Banner(kind: .danger, title: "\(model.name)'s key changed.",
                       message: "Compare your safety code again.")
                    .padding(.horizontal, 16).padding(.top, 8)
            }
            if let notice = model.notice {
                noticeBanner(notice).padding(.horizontal, 16).padding(.top, 8)
            }
            ScrollViewReader { proxy in
                ScrollView {
                    let shown = ConversationModel.metaShown(model.items,
                                                            accessibilitySize: dynamicTypeSize.isAccessibilitySize)
                    LazyVStack(spacing: 8) {
                        ForEach(groupedByDay, id: \.day) { group in
                            Text(verbatim: DayLabel.text(for: group.day))
                                .font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgSoft)
                                .padding(.top, 8)
                            ForEach(group.items) { item in
                                row(item, showsMeta: shown.contains(item.id))
                                    .id(item.id)
                                    // A cancelled message leaves (§6.3); at once under Reduce Motion.
                                    .transition(.asymmetric(insertion: .identity,
                                                            removal: .opacity.combined(with: .scale(scale: 0.98, anchor: .trailing))))
                            }
                        }
                    }
                    .padding(16)
                    .animation(Motion.gated(Motion.enter, reduceMotion: reduceMotion), value: model.items.map(\.id))
                }
                .onChange(of: model.items.last?.id) { _, id in
                    if let id, scrollTarget == nil { proxy.scrollTo(id, anchor: .bottom) }
                }
                .onChange(of: scrollTarget) { _, id in
                    guard let id else { return }
                    proxy.scrollTo(id, anchor: .center)
                    // Done: new messages scroll into view again.
                    scrollTarget = nil
                }
            }
            if let e = model.sendError {
                Text(LocalizedStringKey(e)).font(.footnote).foregroundStyle(Color.danger).padding(.horizontal, 16)
            }
            ComposerView(model: model)
        }
        .background(Color.surface)
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $sheetOf) { target in
            MessageSheet(core: core, messageId: target.id, contact: model.contact, contactName: model.name) {
                model.showDeleted($0)
            }
        }
        .confirmationDialog(confirmation?.title ?? "", isPresented: confirmingShown,
                            titleVisibility: .visible, presenting: confirming) { item in
            Button(DeleteConfirmation(outgoing: item.outgoing, delivery: item.delivery).button, role: .destructive) {
                Task { await model.delete(item.id, shown: item.delivery) }
            }
            Button("Keep", role: .cancel) {}
        } message: { item in
            Text(verbatim: DeleteConfirmation(outgoing: item.outgoing, delivery: item.delivery)
                .message(name: model.name, keepsOwnCopies: confirmingKeeps))
        }
        // The message went meanwhile (deleted elsewhere): nothing to confirm (§9).
        .onChange(of: model.items.map(\.id)) { _, ids in
            if let c = confirming, !ids.contains(c.id) { confirming = nil }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                // "Deliveries" (§6.5): disabled until a message was sent. A
                // link, like the header's: a `navigationDestination(isPresented:)`
                // in the chats' path-bound stack looped SwiftUI's layout at
                // 100 % CPU on the push.
                NavigationLink {
                    DeliveriesView(core: core, contact: model.contact, contactName: model.name)
                } label: {
                    Image(systemName: "checklist")
                }
                .disabled(!model.hasSentMessage)
                .accessibilityLabel(Text("Deliveries"))
                .accessibilityIdentifier("conversation.deliveries")
            }
            ToolbarItem(placement: .principal) {
                ChatHeader(core: core, model: model)
            }
        }
        .toolbar(.hidden, for: .tabBar)
        .onAppear { syncLoop?.conversationOpen = true }
        .onDisappear {
            model.onDisappear()
            syncLoop?.conversationOpen = false
        }
        .task {
            await model.onAppear()
            // The first not delivered message, if it is still there.
            if let focus, model.items.contains(where: { $0.id == focus }) { scrollTarget = focus }
            for await change in await core.changes { await model.handle(change) }
        }
    }

    private var confirmation: DeleteConfirmation? {
        confirming.map { DeleteConfirmation(outgoing: $0.outgoing, delivery: $0.delivery) }
    }

    private var confirmingShown: Binding<Bool> {
        Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } })
    }

    @ViewBuilder private func noticeBanner(_ notice: ConversationModel.Notice) -> some View {
        switch notice {
        case .deleted(let message): Banner(kind: .info, title: message.key)
        case .deleteFailed, .noReachableDevice:
            Banner(kind: .warning, verbatim: notice.text())
        }
    }

    private struct DayGroup { let day: Date; let items: [ConversationModel.Item] }

    private var groupedByDay: [DayGroup] {
        let cal = Calendar.current
        let groups = Dictionary(grouping: model.items) { cal.startOfDay(for: $0.at) }
        return groups.keys.sorted().map { DayGroup(day: $0, items: groups[$0] ?? []) }
    }

    /// A bubble and, 4 pt under it, its time and state on the background.
    /// While its deletion runs: dimmed, a spinner in place of the line (§9).
    @ViewBuilder private func row(_ item: ConversationModel.Item, showsMeta: Bool) -> some View {
        let deleting = model.deleting.contains(item.id)
        let side: HorizontalAlignment = item.outgoing ? .trailing : .leading
        VStack(alignment: side, spacing: 4) {
            bubble(item)
            if deleting {
                ProgressView().controlSize(.mini)
                    .frame(maxWidth: .infinity, alignment: Alignment(horizontal: side, vertical: .center))
            } else if showsMeta {
                BubbleMeta(state: item.state, at: item.at, alignment: side,
                           retry: item.state == .notDelivered ? { retry(item.id) } : nil)
            }
        }
        .opacity(deleting ? 0.5 : 1)
        .onAppear { model.bubbleAppeared(item.id) }
        .onDisappear { model.bubbleDisappeared(item.id) }
    }

    /// One VoiceOver element (§8): the text, the state as its value, the
    /// actions by name. A tap opens the message; a long press its menu.
    private func bubble(_ item: ConversationModel.Item) -> some View {
        let failed = item.state == .notDelivered
        return Bubble(text: item.text, outgoing: item.outgoing)
            .onTapGesture { sheetOf = SheetTarget(id: item.id) }
            .contextMenu {
                if failed {
                    Button { retry(item.id) } label: { Label("Retry", systemImage: "arrow.clockwise") }
                }
                Button { copy(item.text) } label: { Label("Copy", systemImage: "doc.on.doc") }
                Button { sheetOf = SheetTarget(id: item.id) } label: { Label("Details", systemImage: "info.circle") }
                Divider()
                Button(role: .destructive) { confirm(item) } label: { Label("Delete", systemImage: "trash") }
            }
            .accessibilityElement(children: .combine)
            .accessibilityValue(Text(verbatim: Self.spoken(item)))
            .accessibilityHint(Text("Opens the message details."))
            .accessibilityActions {
                if failed { Button("Retry") { retry(item.id) } }
                Button("Copy") { copy(item.text) }
                Button("Details") { sheetOf = SheetTarget(id: item.id) }
                Button("Delete") { confirm(item) }
            }
            .bubbleRow(outgoing: item.outgoing)
    }

    /// The bubble's VoiceOver value (§7.1): the state sentence of a sent
    /// message, "Sent from another of your devices" without a record, the
    /// time of a received one.
    static func spoken(_ item: ConversationModel.Item) -> String {
        if item.outgoing {
            guard let d = item.delivery else { return BubbleMeta.sentElsewhere() }
            return d.state.spoken(d)
        }
        return item.at.formatted(date: .omitted, time: .shortened)
    }

    /// Opens the delete confirmation once its own-copies line is known.
    private func confirm(_ item: ConversationModel.Item) {
        Task {
            confirmingKeeps = await model.keepsOwnCopies(item)
            confirming = item
        }
    }

    private func retry(_ id: Int64) {
        // The send haptic: a retry sends (§8); no new haptic.
        Haptic.send.play()
        Task { await model.retry(id) }
    }

    /// On this iPhone only: never to the Universal Clipboard.
    private func copy(_ text: String) {
        UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: text]], options: [.localOnly: true])
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
