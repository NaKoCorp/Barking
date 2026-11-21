import BarkingKit
import SwiftUI

/// Screen 4 of the mockup, without the "Send from" chooser. Each bubble
/// has its time and state line under it (spec Lot M §6.3); a bubble opens
/// the message sheet (§6.4), which tells each message's delivery.
struct ConversationView: View {
    let core: CoreService
    @State private var model: ConversationModel
    @Environment(\.scenePhase) private var phase
    /// Its cover hides the conversation: nothing is seen under it (nil in
    /// previews and renders).
    @Environment(LockController.self) private var lock: LockController?
    /// Told while this conversation is on screen: syncs every 15 s.
    @Environment(\.syncLoop) private var syncLoop
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// The app's language: notices and quotes follow it, not only the device's.
    @Environment(\.locale) private var locale
    /// Saves the draft once typing stops for 2 s; restarted by each change.
    @State private var draftSave: Task<Void, Never>?
    /// The message whose sheet is open.
    @State private var sheetOf: SheetTarget?
    /// The message the emoji picker is open for.
    @State private var reactingTo: SheetTarget?
    /// The message the delete confirmation is open for, as it was then.
    @State private var confirming: ConversationModel.Item?
    /// My linked devices when the confirmation opened: its title says "all your devices".
    @State private var confirmingDevices = 0
    /// The unverified banner's safety code, in a sheet: a
    /// `navigationDestination(isPresented:)` in the chats' path-bound stack
    /// looped SwiftUI's layout at 100 % CPU on the push.
    @State private var verifying = false

    /// A message to bring into view once the conversation is loaded.
    let focus: Int64?
    @State private var scrollTarget: Int64?
    /// The last message is in view (within `bottomSlack`).
    @State private var atBottom = true
    private static let bottomSlack: CGFloat = 24

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
            } else if model.showsUnverified {
                Banner(kind: .warning, title: "\(model.name) is not verified.",
                       message: "Compare your safety code before sending anything sensitive.",
                       action: .init(label: "Verify now", hint: "Opens the safety code.") { verifying = true })
                    .padding(.horizontal, 16).padding(.top, 8)
                    .accessibilityIdentifier("conversation.unverified")
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
                // Held at the bottom: it opens there, and the keyboard or a
                // new bubble keeps the last message in view without a jump.
                .defaultScrollAnchor(.bottom)
                .onScrollGeometryChange(for: Bool.self) { g in
                    g.visibleRect.maxY >= g.contentSize.height - Self.bottomSlack
                } action: { _, bottom in
                    atBottom = bottom
                }
                // A message I send while reading higher up: brought into
                // view. At the bottom the anchor already shows it, and a
                // received message never moves what I am reading.
                .onChange(of: model.items.last?.id) { _, id in
                    guard let id, scrollTarget == nil, !atBottom,
                          model.items.last?.outgoing == true else { return }
                    withAnimation(Motion.gated(Motion.enter, reduceMotion: reduceMotion)) {
                        proxy.scrollTo(id, anchor: .bottom)
                    }
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
        .sheet(isPresented: $verifying) {
            NavigationStack {
                SafetyCodeView(core: core, contact: model.contact)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) { Button("Close") { verifying = false } }
                    }
            }
            .presentationBackground(Color.surface)
        }
        .sheet(item: $sheetOf) { target in
            MessageSheet(core: core, messageId: target.id, contact: model.contact, contactName: model.name) {
                model.showDeleted($0)
            }
        }
        .sheet(item: $reactingTo) { target in
            EmojiPicker { emoji in react(emoji, on: target.id) }
        }
        .confirmationDialog(Text(verbatim: confirmation?.title(otherDevices: confirmingDevices) ?? ""),
                            isPresented: confirmingShown,
                            titleVisibility: .visible, presenting: confirming) { item in
            Button(DeleteConfirmation(outgoing: item.outgoing, delivery: item.delivery).button, role: .destructive) {
                Task { await model.delete(item.id, shown: item.delivery) }
            }
            Button("Keep", role: .cancel) {}
        } message: { item in
            Text(verbatim: DeleteConfirmation(outgoing: item.outgoing, delivery: item.delivery)
                .message(name: model.name))
        }
        // The message went meanwhile (deleted elsewhere): nothing to confirm (§9).
        .onChange(of: model.items.map(\.id)) { _, ids in
            if let c = confirming, !ids.contains(c.id) { confirming = nil }
        }
        .toolbar {
            ToolbarItem(placement: .principal) {
                ChatHeader(core: core, model: model)
            }
        }
        .toolbar(.hidden, for: .tabBar)
        .onChange(of: locale, initial: true) { _, new in model.language = (Bundle.strings(for: new), new) }
        .onAppear { syncLoop?.conversationOpen = true }
        .onDisappear {
            model.onDisappear()
            syncLoop?.conversationOpen = false
            draftSave?.cancel()
            Task { await model.saveDraft() }
        }
        .onChange(of: phase) { _, new in
            if new == .background { Task { await model.saveDraft() } }
        }
        // Ephemerals: erased when due and seen only while active and unlocked.
        .onChange(of: phase, initial: true) { _, new in
            Task { await model.phaseChanged(active: new == .active) }
        }
        .onChange(of: lock?.covered ?? false, initial: true) { _, covered in model.covered = covered }
        .onChange(of: model.draft) {
            draftSave?.cancel()
            draftSave = Task {
                try? await Task.sleep(for: .seconds(2))
                guard !Task.isCancelled else { return }
                await model.saveDraft()
            }
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
        case .deleteFailed, .noReachableDevice, .reactionTooMany, .reactionFailed, .reactionResendFailed,
             .contactRemoved:
            Banner(kind: .warning, verbatim: notice.text(bundle: .strings(for: locale), locale: locale))
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
            if !item.reactions.isEmpty {
                ReactionChips(chips: item.reactions, outgoing: item.outgoing, myState: item.myReactionState) { react($0, on: item.id) }
                    .disabled(deleting)
                    .bubbleRow(outgoing: item.outgoing)
            }
            if deleting {
                ProgressView().controlSize(.mini)
                    .frame(maxWidth: .infinity, alignment: Alignment(horizontal: side, vertical: .center))
            } else if showsMeta {
                BubbleMeta(state: item.state, at: item.at, alignment: side,
                           retry: item.state == .notDelivered ? { retry(item.id) } : nil)
            }
            // Not grouped with the time: each ephemeral says how long it has left.
            if !deleting, item.ttl != nil {
                EphemeralCountdown(remaining: { item.remaining(at: $0) ?? 0 }, alignment: side)
            }
        }
        .opacity(deleting ? 0.5 : 1)
        .onAppear { model.bubbleAppeared(item.id) }
        .onDisappear { model.bubbleDisappeared(item.id) }
    }

    /// One VoiceOver element (§8): the text, the state as its value, the
    /// actions by name. A tap opens the message; a long press its menu; a
    /// swipe to the right answers it.
    private func bubble(_ item: ConversationModel.Item) -> some View {
        let failed = item.state == .notDelivered
        // My latest reaction did not leave: offered even without a chip (a removal).
        let resendable = item.myReactionState == .notDelivered
        // Still being sent: the core has no row to open or delete yet.
        let saved = !item.local
        // Not for a local row (not in the core yet) or a placeholder (§5.6).
        let acts = item.canReplyOrReact
        let strings = Bundle.strings(for: locale)
        return Bubble(text: item.needsUpdate
                        ? String(localized: "This message needs a newer version of Barking.", bundle: strings, locale: locale)
                        : item.text,
                      outgoing: item.outgoing,
                      quote: model.quoteLine(for: item, bundle: strings, locale: locale),
                      placeholder: item.needsUpdate,
                      highlighted: model.highlighted == item.id) {
            if let quote = item.quote { scrollTarget = model.jump(to: quote) }
        }
            .onTapGesture { if saved { sheetOf = SheetTarget(id: item.id) } }
            .swipeToReply(enabled: acts, outgoing: item.outgoing) { model.startReply(item.id) }
            .contextMenu {
                if acts {
                    emojiRow(item)
                    Button { model.startReply(item.id) } label: {
                        Label("Reply", systemImage: "arrowshape.turn.up.left")
                    }
                }
                if resendable {
                    Button { retryReaction(item.id) } label: {
                        Label("Resend reaction", systemImage: "arrow.clockwise")
                    }
                }
                if failed {
                    Button { retry(item.id) } label: { Label("Retry", systemImage: "arrow.clockwise") }
                }
                if item.canCopy {
                    Button { copy(item.text) } label: { Label("Copy", systemImage: "doc.on.doc") }
                }
                if saved {
                    Button { sheetOf = SheetTarget(id: item.id) } label: { Label("Details", systemImage: "info.circle") }
                    Divider()
                    Button(role: .destructive) { confirm(item) } label: { Label("Delete", systemImage: "trash") }
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityValue(Text(verbatim: Self.spoken(item, now: .now, bundle: strings, locale: locale)))
            .accessibilityHint(saved ? Text("Opens the message details.") : Text(verbatim: ""))
            .accessibilityActions {
                if acts {
                    Button("Reply") { model.startReply(item.id) }
                    Button("React") { reactingTo = SheetTarget(id: item.id) }
                }
                if let quote = item.quote, quote.id != nil, quote.excerpt != nil {
                    Button("Show original") { scrollTarget = model.jump(to: quote) }
                }
                if resendable { Button("Resend reaction") { retryReaction(item.id) } }
                if failed { Button("Retry") { retry(item.id) } }
                if item.canCopy { Button("Copy") { copy(item.text) } }
                if saved {
                    Button("Details") { sheetOf = SheetTarget(id: item.id) }
                    Button("Delete") { confirm(item) }
                }
            }
            // Seen once more than half of it is in the visible part of the list.
            .onScrollVisibilityChange(threshold: 0.5) { model.bubbleVisibility(item.id, shown: $0) }
            .bubbleRow(outgoing: item.outgoing)
    }

    /// The row above the menu: the six frequent emoji and "+" (§5.6). One of
    /// mine shows selected; at 20 of mine, the others and "+" are off.
    @ViewBuilder private func emojiRow(_ item: ConversationModel.Item) -> some View {
        let mine = Set(item.reactions.filter(\.mine).map(\.emoji))
        let full = !model.canAdd(on: item.id)
        ControlGroup {
            ForEach(ConversationModel.frequentEmoji, id: \.self) { emoji in
                let chosen = mine.contains(emoji)
                Toggle(isOn: Binding(get: { chosen }, set: { _ in react(emoji, on: item.id) })) {
                    Text(verbatim: emoji)
                }
                .menuActionDismissBehavior(.enabled)
                .disabled(full && !chosen)
                .accessibilityHint(full && !chosen ? Text("20 reactions at most on a message.") : Text(verbatim: ""))
            }
            Button { reactingTo = SheetTarget(id: item.id) } label: {
                Label("More emoji", systemImage: "plus")
            }
            .disabled(full)
            .accessibilityHint(full ? Text("20 reactions at most on a message.") : Text(verbatim: ""))
        }
        .controlGroupStyle(.palette)
    }

    private func react(_ emoji: String, on id: Int64) {
        Task { await model.toggle(emoji, on: id) }
    }

    /// The bubble's VoiceOver value (§7.1): the state sentence of a sent
    /// message, "Sent from another of your devices" without a record, the
    /// time of a received one. An ephemeral adds how long it has left.
    static func spoken(_ item: ConversationModel.Item, now: Date = .now, bundle: Bundle = .main,
                       locale: Locale = .current) -> String {
        let base: String
        if item.outgoing {
            if let d = item.delivery {
                base = d.state.spoken(d, bundle: bundle, locale: locale)
            } else {
                base = BubbleMeta.sentElsewhere(bundle: bundle, locale: locale)
            }
        } else {
            base = item.at.formatted(date: .omitted, time: .shortened)
        }
        guard let left = item.remaining(at: now) else { return base }
        let label = spokenRemainingLabel(seconds: left, bundle: bundle, locale: locale)
        return base + String(localized: ", disappearing message, disappears in \(label)", bundle: bundle, locale: locale)
    }

    /// Opens the delete confirmation once my linked devices are counted.
    private func confirm(_ item: ConversationModel.Item) {
        Task {
            confirmingDevices = await model.otherDevices()
            confirming = item
        }
    }

    private func retryReaction(_ id: Int64) {
        Haptic.send.play()
        Task { await model.retryReaction(id) }
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
    @Environment(\.locale) private var locale

    var body: some View {
        VStack(alignment: .trailing, spacing: 4) {
            if let banner = model.replyBanner(bundle: .strings(for: locale), locale: locale) {
                replyBanner(banner)
            }
            if let warning = model.ephemeralBanner(bundle: .strings(for: locale), locale: locale) {
                ephemeralBanner(warning)
            }
            if model.showsCounter {
                Text(verbatim: "\(model.byteCount) / \(ConversationModel.maxBytes)")
                    .font(BarkingFont.mono(.caption2, size: 11))
                    .foregroundStyle(model.byteCount > ConversationModel.maxBytes ? Color.danger : Color.fgSoft)
            }
            HStack(spacing: 8) {
                EphemeralMenu(model: model)
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

extension ComposerView {
    /// When a delay is set: when the message erases for you and for the
    /// contact, and that a screenshot stays possible (§5.5).
    fileprivate func ephemeralBanner(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "hourglass").font(.bSymbol(13, weight: .semibold, maximum: 20))
                .foregroundStyle(Color.accent)
            Text(verbatim: text).font(BarkingFont.sans(.footnote, size: 13))
                .foregroundStyle(Color.fgMuted)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("composer.delayBanner")
    }

    /// "Replying to Sam", the start of the original, and an ✕ (§5.6). Not
    /// part of the draft.
    fileprivate func replyBanner(_ banner: (name: String, excerpt: String)) -> some View {
        HStack(spacing: 8) {
            RoundedRectangle(cornerRadius: 1.5).fill(Color.accentFill).frame(width: 3)
            VStack(alignment: .leading, spacing: 2) {
                Text("Replying to \(banner.name)").font(BarkingFont.sans(.footnote, size: 12, weight: .semibold))
                    .foregroundStyle(Color.accent)
                Text(verbatim: banner.excerpt).font(BarkingFont.sans(.footnote, size: 13))
                    .foregroundStyle(Color.fgMuted).lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Button { model.cancelReply() } label: {
                Image(systemName: "xmark").font(.bSymbol(14, weight: .semibold, maximum: 22))
                    .foregroundStyle(Color.fgMuted)
                    .frame(width: 44, height: 44)
                    .contentShape(.rect)
            }
            .accessibilityLabel(Text("Cancel reply"))
            .accessibilityIdentifier("composer.cancelReply")
        }
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
    }
}

/// A swipe to the right on a bubble answers it (§5.6): the bubble follows the
/// finger (up to 60 pt, less on a sent bubble, which sits at the edge and
/// would be clipped) and a drag past 60 pt, mostly sideways, starts the
/// reply. A drag that starts within 20 pt of the left edge is the system's
/// back gesture. Not under VoiceOver, where the "Reply" action does it.
/// The shift is a `GestureState`: it resets by itself if the drag is cancelled.
private struct SwipeToReply: ViewModifier {
    let enabled: Bool
    let outgoing: Bool
    let reply: () -> Void
    @GestureState private var shift: CGFloat = 0
    @Environment(\.accessibilityVoiceOverEnabled) private var voiceOver
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    static let reach: CGFloat = 60
    static let edge: CGFloat = 20
    /// How far a sent bubble moves: the screen's gutter.
    static let outgoingShift: CGFloat = 12

    private func counts(_ drag: DragGesture.Value) -> Bool {
        enabled && !voiceOver && drag.startLocation.x > Self.edge
    }

    func body(content: Content) -> some View {
        content
            .offset(x: shift)
            .animation(Motion.gated(Motion.feedback, reduceMotion: reduceMotion), value: shift)
            .simultaneousGesture(DragGesture(minimumDistance: 20, coordinateSpace: .global)
                .updating($shift) { drag, state, _ in
                    guard counts(drag), abs(drag.translation.width) > abs(drag.translation.height) else { return }
                    state = min(max(drag.translation.width, 0), outgoing ? Self.outgoingShift : Self.reach)
                }
                .onEnded { drag in
                    if counts(drag), drag.translation.width > Self.reach, abs(drag.translation.height) < 30 { reply() }
                })
    }
}

extension View {
    fileprivate func swipeToReply(enabled: Bool, outgoing: Bool, reply: @escaping () -> Void) -> some View {
        modifier(SwipeToReply(enabled: enabled, outgoing: outgoing, reply: reply))
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
