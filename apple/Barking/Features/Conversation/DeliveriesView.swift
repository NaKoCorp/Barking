import BarkingKit
import SwiftUI

/// "Deliveries" (spec Lot M §6.5): the messages sent to a contact, grouped by
/// state, newest first. A row opens the message sheet; "Retry all" ends the
/// "Not delivered" group. Rows move between groups as the core reports it.
struct DeliveriesView: View {
    let core: CoreService
    @State private var model: DeliveriesModel
    /// The message whose sheet is open.
    @State private var sheetOf: SheetTarget?

    private struct SheetTarget: Identifiable { let id: Int64 }

    init(core: CoreService, contact: String, contactName: String) {
        self.core = core
        _model = State(initialValue: DeliveriesModel(core: core, contact: contact, contactName: contactName))
    }

    var body: some View {
        DeliveriesContent(model: model) { sheetOf = SheetTarget(id: $0) }
            .background(Color.surface)
            .navigationTitle(Text("Deliveries"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar(.hidden, for: .tabBar)
            .sheet(item: $sheetOf) { target in
                MessageSheet(core: core, messageId: target.id, contact: model.contact,
                             contactName: model.contactName) { model.showDeleted($0) }
            }
            .task {
                // Subscribe before reading: a change during the load is not lost.
                let changes = await core.changes
                await model.load()
                for await change in changes { await model.apply(change) }
            }
    }
}

/// The list itself, without the screen around it (previews and renders).
struct DeliveriesContent: View {
    let model: DeliveriesModel
    /// False inside another scroll view (previews and renders).
    var scrolls = true
    let open: (Int64) -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.locale) private var locale
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Namespace private var moving
    /// VoiceOver stays on the message that moved (§6.5).
    @AccessibilityFocusState private var focused: Int64?
    @State private var focusMemory: DeliveriesModel.FocusMemory?

    var body: some View {
        if scrolls {
            ScrollView { list }.modifier(FocusFollowsRow(model: model, focused: $focused, memory: $focusMemory))
        } else {
            list.modifier(FocusFollowsRow(model: model, focused: $focused, memory: $focusMemory))
        }
    }

    private var list: some View {
        LazyVStack(alignment: .leading, spacing: 0) {
            if let notice = model.notice { noticeBanner(notice).padding(.bottom, Space.s3) }
            if model.readFailed || model.phase == .failed {
                Banner(kind: .warning, title: "Couldn’t read the list. Your messages are unchanged.",
                       action: .init(label: "Retry", hint: "Reads the list again.") { Task { await model.load() } })
                    .padding(.bottom, Space.s3)
            }
            switch model.phase {
            case .loading:
                ProgressView().frame(maxWidth: .infinity).padding(.top, Space.danger)
            case .failed:
                EmptyView()
            case .loaded:
                if model.isEmpty { emptyState } else { groups }
            }
        }
        .padding(.horizontal, Space.s4)
        .padding(.vertical, Space.s3)
        .animation(Motion.gated(Motion.enter, reduceMotion: reduceMotion), value: model.groups)
    }

    // MARK: Groups

    @ViewBuilder private var groups: some View {
        ForEach(model.groups) { group in
            VStack(alignment: .leading, spacing: 0) {
                title(of: group)
                    .padding(.bottom, Space.s1)
                ForEach(group.rows) { row in
                    rowView(row, in: group)
                    if row.id != group.rows.last?.id || group.state == .notDelivered {
                        Rectangle().fill(Color.border).frame(height: 1)
                    }
                }
                if group.hasMore {
                    // Reads the next page as the end of the group shows, also
                    // when a move left too few rows to scroll to it.
                    Color.clear.frame(height: 1)
                        .task(id: "\(group.state)-\(group.rows.count)-\(group.count)") {
                            await model.loadMore(group.state)
                        }
                }
                if group.state == .notDelivered {
                    TextLink("Retry all", tint: .warnFg) {
                        // The send haptic: a retry sends (§8); no new haptic.
                        Haptic.send.play()
                        Task { await model.retryAll() }
                    }
                }
            }
            .padding(.top, group.id == model.groups.first?.id ? 0 : Space.section)
        }
    }

    /// The group's title with its number (a plural in the stringsdict).
    @ViewBuilder private func title(of group: DeliveriesModel.Group) -> some View {
        switch group.state {
        case .notDelivered: SectionLabel("Not delivered · \(group.count)")
        case .pending: SectionLabel("Pending · \(group.count)")
        case .onNetwork: SectionLabel("On the network · \(group.count)")
        case .received: SectionLabel("Received · \(group.count)")
        }
    }

    private func rowView(_ row: DeliveriesModel.Row, in group: DeliveriesModel.Group) -> some View {
        Button { open(row.id) } label: {
            DeliveryRow(state: group.state, title: nil, excerpt: row.text,
                        meta: Text(verbatim: DeliveriesModel.timeText(row.at, locale: locale)))
                .chevron()
                // Taller than 56 pt at accessibility sizes: air above the rule.
                .padding(.vertical, dynamicTypeSize.isAccessibilitySize ? Space.s2 : 0)
                .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .matchedGeometryEffect(id: row.id, in: moving)
        // One element: the message, its state spoken as the value (§8).
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: DeliveryRow.oneLine(row.text)))
        .accessibilityValue(Text(verbatim: group.state.spoken(row.delivery)))
        .accessibilityHint(Text("Opens the message details."))
        .accessibilityAddTraits(.isButton)
        .accessibilityFocused($focused, equals: row.id)
        .onAppear {
            // As the end of a group comes near, the next 50 load.
            if group.hasMore, group.rows.suffix(5).contains(where: { $0.id == row.id }) {
                Task { await model.loadMore(group.state) }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: Space.s3) {
            Image(systemName: "checklist").font(.bSymbol(28, weight: .regular, maximum: 48)).foregroundStyle(Color.fgSoft)
                .accessibilityHidden(true)
            Text("No messages sent yet. Their delivery will show here.")
                .font(.bBodySmall).foregroundStyle(Color.fgMuted).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, Space.danger)
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private func noticeBanner(_ notice: ConversationModel.Notice) -> some View {
        switch notice {
        case .deleted(let message): Banner(kind: .info, title: message.key)
        case .deleteFailed, .noReachableDevice:
            Banner(kind: .warning, verbatim: notice.text())
        }
    }
}

/// VoiceOver goes back to a message that itself moved group (its row is
/// another view after the move). What it was on is remembered; focus that
/// settles on anything else (a title, another row) forgets it.
private struct FocusFollowsRow: ViewModifier {
    let model: DeliveriesModel
    var focused: AccessibilityFocusState<Int64?>.Binding
    @Binding var memory: DeliveriesModel.FocusMemory?
    @State private var forget: Task<Void, Never>?

    func body(content: Content) -> some View {
        content
            .onChange(of: focused.wrappedValue) { _, now in
                forget?.cancel()
                if let now, let state = model.state(of: now) {
                    memory = .init(id: now, state: state)
                } else if memory != nil {
                    // Nil is also what a moving row leaves behind: forget it
                    // only once the groups had their say.
                    forget = Task {
                        try? await Task.sleep(for: .seconds(1))
                        if !Task.isCancelled { memory = nil }
                    }
                }
            }
            .onChange(of: model.groups) {
                guard let id = DeliveriesModel.focusRestore(memory, in: model.groups) else { return }
                memory = nil
                forget?.cancel()
                Task { focused.wrappedValue = id }
            }
    }
}

#if DEBUG
enum DeliveriesSamples {
    private static let t0 = MessageSheetSamples.t0

    /// All four groups; Received is longer than the rows loaded.
    @MainActor static func populated() -> DeliveriesModel {
        let model = makeModel()
        func row(_ id: Int64, _ text: String, _ state: DeliveryState, _ ago: UInt64) -> DeliveriesModel.Row {
            .init(id: id, text: text, at: Date(timeIntervalSince1970: TimeInterval(t0 - ago)),
                  delivery: MessageSheetSamples.delivery(state))
        }
        model.preload([
            .notDelivered: [row(9, "On se voit au marché à 18 h,\ndevant la fontaine.", .notDelivered, 7_200)],
            .pending: [row(8, "J’arrive dans dix minutes", .pending, 120), row(7, "Tu as reçu mon message ?", .pending, 900)],
            .onNetwork: [row(6, "Merci pour hier soir, c’était parfait", .onNetwork, 5_400)],
            .received: [row(5, "D’accord", .received, 90_000), row(4, "Bonne nuit", .received, 100_000),
                        row(3, "À demain", .received, 700_000)],
        ], counts: [.received: 12])
        return model
    }

    @MainActor static func empty() -> DeliveriesModel {
        let model = makeModel()
        model.preload([:])
        return model
    }

    @MainActor static func failed() -> DeliveriesModel {
        let model = makeModel()
        model.preloadFailed()
        return model
    }

    @MainActor private static func makeModel() -> DeliveriesModel {
        DeliveriesModel(core: CoreService(device: PreviewSheetDevice(), runner: PreviewSheetRunner()),
                        contact: "alice", contactName: "Alice")
    }
}

#Preview("Deliveries") {
    PreviewMatrix {
        DeliveriesContent(model: DeliveriesSamples.populated(), scrolls: false) { _ in }
    }
}

#Preview("Deliveries, empty and error") {
    PreviewMatrix {
        DeliveriesContent(model: DeliveriesSamples.empty(), scrolls: false) { _ in }
        DeliveriesContent(model: DeliveriesSamples.failed(), scrolls: false) { _ in }
    }
}
#endif
