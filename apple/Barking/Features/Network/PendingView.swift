import BarkingKit
import SwiftUI

/// "Pending" (spec Lot M §6.6), pushed from the Network screen: the packets
/// that have not left this iPhone. A message row opens the message sheet; a
/// swipe, the selection and "Cancel all" delete, each after a confirmation
/// (§7.4); what the core really did is said by a banner (§6.7).
struct PendingView: View {
    let core: CoreService
    @State private var model: PendingModel
    /// The message whose sheet is open.
    @State private var sheetOf: SheetTarget?
    /// The confirmation open, with the text it opened with (§9).
    @State private var dialog: Dialog?

    private struct SheetTarget: Identifiable { let id: Int64 }

    /// The three confirmations of §7.4.
    enum Dialog: Identifiable {
        case one(PendingModel.Ask)
        case selection(PendingModel.Confirmation)
        case all(PendingModel.Confirmation)

        var id: String {
            switch self {
            case .one(let ask): "one-\(ask.id)"
            case .selection: "selection"
            case .all: "all"
            }
        }

        var title: Text {
            switch self {
            case .one(let ask): Text(ask.confirmation.title)
            case .selection(let c), .all(let c): Text(verbatim: c.title)
            }
        }

        var button: Text {
            switch self {
            case .one(let ask): Text(ask.confirmation.button)
            case .selection(let c), .all(let c): Text(verbatim: c.button)
            }
        }

        var message: String {
            switch self {
            case .one(let ask): ask.message
            case .selection(let c), .all(let c): c.message
            }
        }
    }

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: PendingModel(core: core))
    }

    var body: some View {
        PendingContent(model: model, open: { sheetOf = SheetTarget(id: $0) }, delete: ask,
                       cancelAll: { dialog = .all(model.cancelAllConfirmation()) },
                       deleteSelected: { dialog = .selection(model.selectionConfirmation()) })
            .background(Color.surface)
            .navigationTitle(Text("Pending"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar(.hidden, for: .tabBar)
            .toolbar {
                if model.canSelect {
                    ToolbarItem(placement: .confirmationAction) {
                        Button { model.selecting.toggle() } label: {
                            Text(model.selecting ? LocalizedStringKey("Done") : LocalizedStringKey("Select"))
                        }
                            .accessibilityIdentifier("pending.select")
                    }
                }
            }
            .sheet(item: $sheetOf) { target in
                if let row = model.messages.first(where: { $0.id == target.id }) {
                    MessageSheet(core: core, messageId: row.id, contact: row.contact, contactName: row.name) {
                        model.showDeleted($0)
                    }
                }
            }
            .confirmationDialog(dialog?.title ?? Text(verbatim: ""), isPresented: dialogShown,
                                titleVisibility: .visible, presenting: dialog) { d in
                Button(role: .destructive) {
                    Task { await confirm(d) }
                } label: { d.button }
                Button("Keep", role: .cancel) {}
            } message: { d in
                Text(verbatim: d.message)
            }
            .task {
                // Subscribe before reading: a change during the load is not lost.
                let changes = await core.changes
                await model.load()
                for await change in changes { await model.apply(change) }
            }
    }

    private var dialogShown: Binding<Bool> {
        Binding(get: { dialog != nil }, set: { if !$0 { dialog = nil } })
    }

    /// A swipe on a row: the dialog of its case. None when it is gone (§9).
    private func ask(_ id: Int64) {
        Task { dialog = await model.askDelete(id).map(Dialog.one) }
    }

    private func confirm(_ d: Dialog) async {
        switch d {
        case .one(let ask): await model.delete(ask.messageId, shown: ask.shown)
        case .selection: await model.deleteSelected()
        case .all: await model.cancelAll()
        }
    }
}

/// The list itself, without the screen around it (previews and renders).
struct PendingContent: View {
    let model: PendingModel
    /// False where a `List` cannot draw: inside another scroll view
    /// (previews and renders).
    var listed = true
    let open: (Int64) -> Void
    let delete: (Int64) -> Void
    let cancelAll: () -> Void
    let deleteSelected: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.locale) private var locale
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        Group {
            if listed {
                List { sections }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
            } else {
                // The bar follows the rows: there is no safe area to inset.
                VStack(alignment: .leading, spacing: 0) {
                    sections
                    if model.selecting { selectionBar }
                }
            }
        }
        .background(Color.surface)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if listed, model.selecting { selectionBar }
        }
        .animation(Motion.gated(Motion.enter, reduceMotion: reduceMotion), value: model.messages)
        .animation(Motion.gated(Motion.feedback, reduceMotion: reduceMotion), value: model.selection)
    }

    // MARK: Sections

    @ViewBuilder private var sections: some View {
        if let notice = model.notice {
            noticeBanner(notice).plain(listed).padding(.bottom, Space.s3)
        }
        if model.readFailed {
            Banner(kind: .warning, title: "Couldn’t read the list. Your messages are unchanged.",
                   action: .init(label: "Retry", hint: "Reads the list again.") { Task { await model.load() } })
                .plain(listed).padding(.bottom, Space.s3)
        }
        if model.unreachable {
            StatusDot(.waiting, label: "Unreachable · nothing is lost")
                .plain(listed).padding(.bottom, Space.s3)
        }
        switch model.phase {
        case .loading:
            ProgressView().frame(maxWidth: .infinity).padding(.top, Space.danger).plain(listed)
        case .failed:
            EmptyView()
        case .loaded:
            if model.isEmpty { emptyState.plain(listed) } else { loadedSections }
        }
    }

    @ViewBuilder private var loadedSections: some View {
        Section {
            if model.syncOnly {
                Text("None of your messages are waiting.")
                    .font(.bBodySmall).foregroundStyle(Color.fgMuted)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, Space.s3)
                    .card(listed)
            }
            ForEach(model.messages) { row in
                messageRow(row).card(listed)
            }
        } header: {
            SectionLabel("Your messages · \(model.messagePackets) packets")
                .plain(listed).padding(.vertical, Space.s2)
        }
        if !model.sync.isEmpty {
            Section {
                ForEach(model.sync) { row in syncRow(row).card(listed) }
            } header: {
                SectionLabel("Sync · \(model.syncPackets) packets")
                    .plain(listed).padding(.top, Space.section - Space.s2).padding(.bottom, Space.s2)
            } footer: {
                Text("Receipts tell your contacts their messages arrived. Copies and updates keep your other devices in step; copies hold your messages, encrypted. Barking sends them on its own, and they can’t be deleted here.")
                    .font(.bBodySmall).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
                    .plain(listed).padding(.top, Space.s2)
            }
        }
        if model.showsCancelAll {
            DangerButton("Cancel all · \(model.messages.count)", hint: "Only your messages. Sync packets stay.",
                         identifier: "pending.cancelAll", action: cancelAll)
                .plain(listed).padding(.top, Space.danger).padding(.bottom, Space.s4)
        }
    }

    // MARK: Rows

    private func messageRow(_ row: PendingModel.Row) -> some View {
        let selecting = model.selecting
        let selected = model.selection.contains(row.id)
        let busy = model.deleting.contains(row.id)
        return TimelineView(.periodic(from: .now, by: 60)) { context in
            Button {
                if selecting { model.toggle(row.id) } else { open(row.id) }
            } label: {
                PendingRowView(row: row, now: context.date, selecting: selecting, selected: selected, busy: busy)
            }
            .buttonStyle(.plain)
            .disabled(busy)
            // One element: the recipient and the message, the state spoken as the value (§8).
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text(verbatim: "\(row.name), \(DeliveryRow.oneLine(row.body))"))
            .accessibilityValue(Text(verbatim: PendingModel.meta(for: row, now: context.date,
                                                                 bundle: .strings(for: locale), locale: locale).spoken))
            .accessibilityHint(selecting ? Text("") : Text("Opens the message details."))
            .accessibilityAddTraits(selecting && selected ? [.isButton, .isSelected] : .isButton)
            .accessibilityAction(named: Text("Delete")) { if !selecting { delete(row.id) } }
            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                if !selecting {
                    Button(role: .destructive) { delete(row.id) } label: { Text("Delete") }
                }
            }
        }
    }

    private func syncRow(_ row: PendingModel.SyncRow) -> some View {
        HStack(alignment: .top, spacing: Space.s3) {
            Image(systemName: row.symbol).font(.bSymbol(15, relativeTo: .body, maximum: 28))
                .foregroundStyle(Color.fgSoft).frame(width: 28)
                .accessibilityHidden(true)
            Text(verbatim: PendingModel.title(of: row, bundle: .strings(for: locale), locale: locale))
                .font(.bBodySmall).foregroundStyle(Color.fgMuted)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, Space.s3)
        .frame(minHeight: 44)
        // Read-only: text, not a button, nothing to delete or select.
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isStaticText)
        .deleteDisabled(true)
    }

    private var emptyState: some View {
        VStack(spacing: Space.s3) {
            Image(systemName: "checkmark").font(.bSymbol(28, weight: .semibold, maximum: 48)).foregroundStyle(Color.ok)
                .accessibilityHidden(true)
            Text("Nothing pending. Everything has gone out.")
                .font(.bBodySmall).foregroundStyle(Color.fgMuted).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, Space.danger)
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private func noticeBanner(_ notice: ConversationModel.Notice) -> some View {
        switch notice {
        case .deleted(let message): Banner(kind: .info, verbatim: message.string(bundle: .strings(for: locale), locale: locale))
        case .deleteFailed, .noReachableDevice:
            Banner(kind: .warning, verbatim: notice.text(bundle: .strings(for: locale), locale: locale))
        }
    }

    // MARK: Selection bar (§6.6)

    private var selectionBar: some View {
        let count = model.selectionCount
        let accessible = dynamicTypeSize.isAccessibilitySize
        return VStack(spacing: 0) {
            Rectangle().fill(Color.border).frame(height: 1)
            let all = TextLink("Select all") { model.selectAll() }
            let button = DangerButton("Delete (\(count))", identifier: "pending.deleteSelected", enabled: count > 0,
                                      reason: "Select messages to delete.", value: "\(count) selected",
                                      action: deleteSelected)
            Group {
                if accessible {
                    VStack(spacing: Space.s2) { button; all }
                } else {
                    HStack(alignment: .top, spacing: Space.s4) { all; button }
                }
            }
            .padding(.horizontal, Space.s4).padding(.vertical, Space.s3)
        }
        .background(Color.surface)
    }
}

/// A message of "Your messages": the clock, the recipient, the excerpt, how
/// long ago and how long left, and where a part of it already went.
private struct PendingRowView: View {
    let row: PendingModel.Row
    let now: Date
    let selecting: Bool
    let selected: Bool
    /// Its deletion runs: dimmed, a spinner for the symbol (§9).
    let busy: Bool

    @ScaledMetric(relativeTo: .body) private var column: CGFloat = 24
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.locale) private var locale

    var body: some View {
        let meta = PendingModel.meta(for: row, now: now, bundle: .strings(for: locale), locale: locale)
        let accessible = dynamicTypeSize.isAccessibilitySize
        HStack(alignment: .top, spacing: Space.s3) {
            if selecting {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.bSymbol(20, relativeTo: .body, maximum: 30))
                    .foregroundStyle(selected ? Color.accent : Color.fgSoft)
                    .frame(width: min(column, 28))
                    .accessibilityHidden(true)
            }
            Group {
                if busy {
                    ProgressView().frame(width: min(column, 28), height: min(column, 28))
                } else {
                    DeliveryGlyph(.pending, relativeTo: .body, maximum: min(column, 28))
                }
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: row.name).font(BarkingFont.sans(.subheadline, size: 15, weight: .semibold)).foregroundStyle(Color.fg)
                Text(verbatim: DeliveryRow.oneLine(row.body)).font(.bBodySmall).foregroundStyle(Color.fgMuted)
                    .lineLimit(accessible ? 2 : 1)
                metaText(meta).font(.bMeta).foregroundStyle(Color.fgSoft)
                    .fixedSize(horizontal: false, vertical: true)
                if let left = meta.left {
                    Text(verbatim: left).font(.bMeta).foregroundStyle(Color.fgSoft)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: Space.s2)
            if !selecting && !accessible {
                Text(verbatim: "›").font(.bMeta).foregroundStyle(Color.fgSoft).accessibilityHidden(true)
            }
        }
        .padding(.vertical, Space.s2)
        .frame(minHeight: 56)
        .opacity(busy ? 0.5 : 1)
        .contentShape(.rect)
    }

    /// "2 h ago · expires in 22 h"; under two hours the expiry takes the
    /// warning colour and the triangle (the colour is never alone).
    private func metaText(_ meta: PendingModel.Meta) -> Text {
        let ago = Text(verbatim: meta.ago + " · ")
        guard meta.warn else { return ago + Text(verbatim: meta.expires) }
        return ago + (Text(Image(systemName: "exclamationmark.triangle.fill")) + Text(verbatim: " " + meta.expires))
            .foregroundStyle(Color.warnFg)
    }
}

private extension View {
    /// A line of the list on the screen's ground, with the screen's gutter.
    @ViewBuilder func plain(_ listed: Bool) -> some View {
        if listed {
            self.listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
        } else {
            self.padding(.horizontal, Space.s4)
        }
    }

    /// A row on `surfaceCard`, a rule under it.
    @ViewBuilder func card(_ listed: Bool) -> some View {
        if listed {
            self.listRowBackground(Color.surfaceCard)
                .listRowSeparatorTint(Color.border)
        } else {
            self.padding(.horizontal, Space.s4)
                .background(Color.surfaceCard)
                .overlay(alignment: .bottom) { Rectangle().fill(Color.border).frame(height: 1) }
        }
    }
}

#if DEBUG
enum PendingSamples {
    private static var now: Date { .now }

    private static func message(_ id: Int64, _ name: String, _ contact: String, _ body: String,
                                ago: TimeInterval, expiresIn: TimeInterval, packets: UInt32 = 1,
                                devices: UInt32 = 1, left: UInt32 = 0) -> PendingMessage {
        PendingMessage(messageId: id, contact: contact, name: name, body: body,
                       sealedAt: UInt64(now.timeIntervalSince1970 - ago),
                       expiresAt: UInt64(now.timeIntervalSince1970 + expiresIn),
                       packets: packets, devices: devices, devicesLeft: left)
    }

    /// Every kind of packet: messages (one about to expire, one that left
    /// for a device) and the four sorts of sync.
    static let everything = PendingPackets(
        messages: [
            message(1, "Alice", "a", "On se voit au marché à 18 h,\ndevant la fontaine.", ago: 80_000, expiresIn: 4_000),
            message(2, "Sam", "s", "J’arrive dans dix minutes", ago: 7_200, expiresIn: 79_200, packets: 2, devices: 2, left: 1),
            message(3, "Alice", "a", "Tu as reçu mon message ?", ago: 900, expiresIn: 85_500),
        ],
        sync: [
            PendingSync(kind: .ack, packets: 2, names: ["Alice", "Sam"]),
            PendingSync(kind: .ownCopy, packets: 3, names: []),
            PendingSync(kind: .deviceSync, packets: 1, names: []),
            PendingSync(kind: .cardUpdate, packets: 1, names: ["Alice"]),
        ], packets: 11)

    static let syncOnly = PendingPackets(
        messages: [], sync: [PendingSync(kind: .ack, packets: 1, names: ["Sam"]), PendingSync(kind: .ownCopy, packets: 1, names: [])],
        packets: 2)

    @MainActor static func model(_ packets: PendingPackets, unreachable: Bool = false) -> PendingModel {
        let model = PendingModel(core: CoreService(device: PreviewSheetDevice(), runner: PreviewSheetRunner()))
        model.preload(packets, unreachable: unreachable)
        return model
    }

    @MainActor static func selecting() -> PendingModel {
        let m = model(everything)
        m.preloadSelection([1, 3])
        return m
    }

    @MainActor static func withBanner() -> PendingModel {
        let m = model(everything, unreachable: true)
        m.preloadNotice(.deleted(.several(count: 2, names: ["Alice", "Sam"])))
        return m
    }
}

#Preview("Pending") {
    PreviewMatrix {
        PendingContent(model: PendingSamples.model(PendingSamples.everything), listed: false,
                       open: { _ in }, delete: { _ in }, cancelAll: {}, deleteSelected: {})
    }
}

#Preview("Pending, selecting") {
    PreviewMatrix {
        PendingContent(model: PendingSamples.selecting(), listed: false,
                       open: { _ in }, delete: { _ in }, cancelAll: {}, deleteSelected: {})
    }
}

#Preview("Pending, empty, sync only and banner") {
    PreviewMatrix {
        PendingContent(model: PendingSamples.model(PendingPackets(messages: [], sync: [], packets: 0)), listed: false,
                       open: { _ in }, delete: { _ in }, cancelAll: {}, deleteSelected: {})
        PendingContent(model: PendingSamples.model(PendingSamples.syncOnly), listed: false,
                       open: { _ in }, delete: { _ in }, cancelAll: {}, deleteSelected: {})
        PendingContent(model: PendingSamples.withBanner(), listed: false,
                       open: { _ in }, delete: { _ in }, cancelAll: {}, deleteSelected: {})
    }
}
#endif
