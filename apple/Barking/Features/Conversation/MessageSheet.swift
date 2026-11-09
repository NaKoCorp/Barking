import BarkingKit
import SwiftUI

/// The message sheet (spec Lot M §6.4): quote, legend, delivery timeline,
/// the contact's devices, my copies, the privacy block and the danger zone.
/// A received message shows its path instead of a state; one sent from
/// another of my devices says it is tracked there. Large detent, one
/// "Close". It closes on its own once the message is deleted, here or
/// elsewhere; a deletion made here hands its banner to `onDeleted`.
struct MessageSheet: View {
    let core: CoreService
    let onDeleted: (DeleteBanner.Message?) -> Void
    @State private var model: MessageSheetModel
    @Environment(\.dismiss) private var dismiss

    /// The confirmation as it was when it opened: its text stays (§9).
    private struct Asking: Identifiable {
        let id = UUID()
        let confirmation: DeleteConfirmation
        let message: String
        let shown: Delivery?
    }
    @State private var asking: Asking?

    init(core: CoreService, messageId: Int64, contact: String, contactName: String,
         onDeleted: @escaping (DeleteBanner.Message?) -> Void = { _ in }) {
        self.core = core
        self.onDeleted = onDeleted
        _model = State(initialValue: MessageSheetModel(core: core, messageId: messageId, contact: contact,
                                                       contactName: contactName))
    }

    var body: some View {
        NavigationStack {
            MessageSheetContent(model: model, ask: ask, retry: retry)
                .navigationTitle(Text("Message"))
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
        }
        .presentationDetents([.large])
        .presentationBackground(Color.surface)
        .confirmationDialog(asking?.confirmation.title ?? "", isPresented: askingShown,
                            titleVisibility: .visible, presenting: asking) { a in
            Button(a.confirmation.button, role: .destructive) {
                Task { await model.delete(shown: a.shown) }
            }
            Button("Keep", role: .cancel) {}
        } message: { a in
            Text(verbatim: a.message)
        }
        .onChange(of: model.exit) { _, exit in
            guard let exit else { return }
            asking = nil
            if case .deleted(let banner) = exit { onDeleted(banner) }
            dismiss()
        }
        .task {
            // Subscribe before reading: a change during the load is not lost.
            let changes = await core.changes
            await model.load()
            for await change in changes { await model.handle(change) }
        }
    }

    private var askingShown: Binding<Bool> {
        Binding(get: { asking != nil }, set: { if !$0 { asking = nil } })
    }

    private func ask() {
        asking = Asking(confirmation: model.confirmation, message: model.confirmationMessage(), shown: model.delivery)
    }

    private func retry() {
        // The send haptic: a retry sends (§8); no new haptic.
        Haptic.send.play()
        Task { await model.retry() }
    }
}

/// The sheet's scrolling content, apart from its navigation and dialog.
struct MessageSheetContent: View {
    let model: MessageSheetModel
    let ask: () -> Void
    let retry: () -> Void

    var body: some View {
        ScrollView {
            MessageSheetBody(model: model, ask: ask, retry: retry)
        }
        .background(Color.surface)
    }
}

/// What scrolls in the sheet (renders draw it without the scroll view).
struct MessageSheetBody: View {
    let model: MessageSheetModel
    let ask: () -> Void
    let retry: () -> Void

    var body: some View {
            VStack(alignment: .leading, spacing: 0) {
                if let notice = model.notice {
                    Banner(kind: .warning, verbatim: notice.text())
                        .padding(.bottom, Space.s4)
                }
                switch model.content {
                case .loading:
                    ProgressView().frame(maxWidth: .infinity).padding(.top, Space.section)
                case .unavailable:
                    Banner(kind: .warning, title: "Details unavailable. The message itself is unchanged.")
                    if !model.quote.isEmpty { QuoteCard(text: model.quote).padding(.top, Space.s4) }
                case .sent:
                    sent
                case .sentElsewhere:
                    QuoteCard(text: model.quote)
                    Text("Sent from another of your devices. Its delivery is tracked there.")
                        .font(.bBodySmall).foregroundStyle(Color.fgMuted)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, Space.s4)
                    danger
                case .received:
                    QuoteCard(text: model.quote)
                    section("Delivery")
                    if let path = model.path {
                        PathStops(rows: path.rows, notRecorded: path.notRecorded)
                    }
                    PrivacyBlock(contactName: model.contactName).padding(.top, Space.section)
                    danger
                }
            }
            .padding(.horizontal, Space.gutter)
            .padding(.vertical, Space.s4)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.surface)
    }

    @ViewBuilder private var sent: some View {
        QuoteCard(text: model.quote)
        if let state = model.delivery?.state {
            DeliveryLegend(current: state).padding(.top, Space.s4)
        }
        section("Delivery")
        DeliveryTimeline(steps: model.steps)
            .accessibilityIdentifier("sheet.timeline")
        // Asked again each minute: a sheet left open past the expiry says so.
        TimelineView(.periodic(from: .now, by: 60)) { context in
            if let verdict = model.verdict(at: context.date) {
                Text(verbatim: verdict).font(.bBodySmall).foregroundStyle(Color.fgSoft)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, Space.s2)
            }
        }
        if model.canRetry {
            PrimaryButton("Retry", identifier: "sheet.retry", action: retry).padding(.top, Space.s4)
        }
        if model.showsDevices {
            section("\(model.contactName)’s devices")
            if let sentence = model.devicesSentence {
                Text(verbatim: sentence).font(.bBodySmall).foregroundStyle(Color.fg)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.bottom, Space.s2)
            }
            FormCard {
                ForEach(model.devices) { DeviceLine(row: $0) }
            }
        }
        if let copies = model.ownCopies {
            Text(verbatim: copies).font(.bBodySmall).foregroundStyle(Color.fgMuted)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, Space.s3)
        }
        PrivacyBlock(contactName: model.contactName).padding(.top, Space.section)
        danger
    }

    /// 24 pt above a section title, 8 below (§6.4).
    private func section(_ title: LocalizedStringKey) -> some View {
        SectionLabel(title).padding(.top, Space.section).padding(.bottom, Space.s2)
    }

    /// No card, 32 pt above (§6.4 point 6).
    private var danger: some View {
        DangerButton("Delete message", identifier: "sheet.delete", action: ask)
            .padding(.top, Space.danger)
    }
}

/// The quoted message, 4 lines then "Show all", which unfolds in place.
private struct QuoteCard: View {
    let text: String
    @State private var expanded = false
    @State private var full: CGFloat = 0
    @State private var shown: CGFloat = 0

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            quote.lineLimit(expanded ? nil : 4)
                .onGeometryChange(for: CGFloat.self, of: { $0.size.height }) { shown = $0 }
                .background(alignment: .topLeading) {
                    // The whole text, unseen, measures whether 4 lines cut it.
                    quote.fixedSize(horizontal: false, vertical: true).hidden()
                        .onGeometryChange(for: CGFloat.self, of: { $0.size.height }) { full = $0 }
                        .accessibilityHidden(true)
                }
            if !expanded && full > shown + 1 {
                TextLink("Show all") { expanded = true }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.surfaceCard, in: RoundedRectangle(cornerRadius: Radius.card))
        .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
    }

    private var quote: Text {
        Text("“\(text)”").font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fg)
    }
}

/// One device of the contact: the card's name, its state and time in Fira
/// 12, the glyph at the trailing edge. One VoiceOver element.
private struct DeviceLine: View {
    let row: MessageSheetModel.DeviceRow

    var body: some View {
        HStack(spacing: Space.s3) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: row.name).font(.bBody.weight(.semibold)).foregroundStyle(Color.fg)
                Text(verbatim: row.status).font(BarkingFont.mono(.caption, size: 12)).foregroundStyle(Color.fgMuted)
            }
            .multilineTextAlignment(.leading)
            .frame(maxWidth: .infinity, alignment: .leading)
            DeliveryGlyph(row.state, relativeTo: .body, maximum: 28)
        }
        .padding(.horizontal, FormRowMetrics.inset)
        .padding(.vertical, 10)
        .frame(minHeight: FormRowMetrics.minHeight(hasSubtitle: true))
        .accessibilityElement(children: .combine)
    }
}

#if DEBUG
enum MessageSheetSamples {
    static let t0: UInt64 = 1_794_060_127

    static func delivery(_ state: DeliveryState, deposited: UInt64? = nil, received: UInt64? = nil,
                         expired: UInt64? = nil, devices: UInt32 = 1, devicesReceived: UInt32 = 0,
                         left: UInt32 = 0, pending: UInt32 = 0) -> Delivery {
        Delivery(state: state, sealedAt: t0, depositedAt: deposited, receivedAt: received, expiredAt: expired,
                 devices: devices, devicesReceived: devicesReceived, devicesLeft: left, devicesPending: pending)
    }

    static let relay = RelayHop(node: "K7QX2M4A", at: t0 + 34, size: 1100)
    static let copies = OwnCopies(total: 1, left: 1, waiting: 0)

    /// The five cases the renders show: the four states and a mixed 1 of 2.
    static var cases: [(name: String, sheet: MessageDelivery)] {
        [
            ("pending", MessageDelivery(messageId: 1, delivery: delivery(.pending, pending: 1), devices: [], relays: [],
                                        ownCopies: OwnCopies(total: 1, left: 0, waiting: 1))),
            ("onnetwork", MessageDelivery(messageId: 1, delivery: delivery(.onNetwork, deposited: t0 + 34, left: 1),
                                          devices: [], relays: [relay], ownCopies: copies)),
            ("received", MessageDelivery(
                messageId: 1,
                delivery: delivery(.received, deposited: t0 + 34, received: t0 + 185, devices: 2, devicesReceived: 1, left: 2),
                devices: [DeviceDelivery(device: "a1b2c3", name: "Alice’s iPhone", state: .received, sealedAt: t0,
                                         depositedAt: t0 + 34, node: "K7QX2M4A", receivedAt: t0 + 185, expiredAt: nil),
                          DeviceDelivery(device: "d4e5f6", name: "iPad", state: .onNetwork, sealedAt: t0,
                                         depositedAt: t0 + 36, node: "K7QX2M4A", receivedAt: nil, expiredAt: nil)],
                relays: [relay], ownCopies: copies)),
            ("notdelivered", MessageDelivery(messageId: 1, delivery: delivery(.notDelivered, expired: t0 + 86_400),
                                             devices: [], relays: [], ownCopies: OwnCopies(total: 0, left: 0, waiting: 0))),
            ("mixed", MessageDelivery(
                messageId: 1,
                delivery: delivery(.onNetwork, deposited: t0 + 34, devices: 2, left: 1, pending: 1),
                devices: [DeviceDelivery(device: "a1b2c3", name: "Alice’s iPhone", state: .onNetwork, sealedAt: t0,
                                         depositedAt: t0 + 34, node: "K7QX2M4A", receivedAt: nil, expiredAt: nil),
                          DeviceDelivery(device: "d4e5f6", name: "iPad", state: .pending, sealedAt: t0,
                                         depositedAt: nil, node: nil, receivedAt: nil, expiredAt: nil)],
                relays: [relay], ownCopies: OwnCopies(total: 1, left: 0, waiting: 1))),
        ]
    }

    /// A model shown as if loaded (previews and renders cannot wait for a load).
    @MainActor static func model(_ sheet: MessageDelivery?, contactName: String = "Alice") -> MessageSheetModel {
        let core = CoreService(device: PreviewSheetDevice(), runner: PreviewSheetRunner())
        let model = MessageSheetModel(core: core, messageId: 1, contact: "alice", contactName: contactName)
        model.preload(quote: "On se voit au marché à 18 h, devant la fontaine.", sheet: sheet)
        return model
    }
}

#Preview("Message sheet") {
    PreviewMatrix {
        ForEach(MessageSheetSamples.cases, id: \.name) { c in
            MessageSheetBody(model: MessageSheetSamples.model(c.sheet), ask: {}, retry: {})
        }
    }
}

/// Answers nothing: the previews never reach the device.
struct PreviewSheetRunner: CallRunner {
    func run<T: Sendable>(_ name: String, _ body: @escaping @Sendable () throws -> T) async throws -> T {
        throw CancellationError()
    }
}

/// Never called (the runner refuses every call); only satisfies `CoreService`.
final class PreviewSheetDevice: DeviceHandle, @unchecked Sendable {
    private struct Never: Error {}
    func fingerprint() throws -> String { throw Never() }
    func displayName() throws -> String { throw Never() }
    func setDisplayName(name: String) throws { throw Never() }
    func contacts() throws -> [Contact] { throw Never() }
    func messagesWith(contact: String) throws -> [Message] { throw Never() }
    func messageRoute(messageId: Int64) throws -> [RouteStepInfo] { throw Never() }
    func sendText(contact: String, text: String) throws { throw Never() }
    func addContactBytes(card: Data, alias: String?) throws -> String { throw Never() }
    func addContact(card: String, alias: String?) throws -> String { throw Never() }
    func contactCardBytes() throws -> Data { throw Never() }
    func contactCard(displayName: String) throws -> String { throw Never() }
    func setAlias(contact: String, alias: String) throws { throw Never() }
    func removeContact(contact: String) throws { throw Never() }
    func markVerified(contact: String) throws { throw Never() }
    func unmarkVerified(contact: String) throws { throw Never() }
    func safetyNumber(contact: String) throws -> [String] { throw Never() }
    func unreadCounts() throws -> [UnreadCount] { throw Never() }
    func chatSummaries() throws -> [ChatSummary] { throw Never() }
    func markRead(contact: String, upTo: Int64) throws { throw Never() }
    func keyChanges(since: UInt64) throws -> [KeyChange] { throw Never() }
    func transparencyLog(limit: UInt32, before: Int64?, securityOnly: Bool) throws -> [LogEntry] { throw Never() }
    func contactDevices(contact: String) throws -> [MyDeviceInfo] { throw Never() }
    func sync(deadlineMs: UInt64) throws -> SyncSummary { throw Never() }
    func quickSync(deadlineMs: UInt64) throws -> SyncSummary { throw Never() }
    func nodes() throws -> [NodeInfo] { throw Never() }
    func addNode(id: String, addr: String) throws { throw Never() }
    func setPush(settings: PushSettings?) throws {}
    func pendingCount() throws -> UInt32 { throw Never() }
    func myDevices() throws -> [MyDeviceInfo] { throw Never() }
    func linkOffer() throws -> Data { throw Never() }
    func linkDevice(request: Data, withHistory: Bool) throws -> Data { throw Never() }
    func isPendingLink() throws -> Bool { throw Never() }
    func finishLink(package: Data) throws { throw Never() }
    func transferAdmin(deviceId: String) throws { throw Never() }
    func adminTransferPending() throws -> String? { throw Never() }
    func removed() throws -> RemovedInfo? { throw Never() }
    func removeDevice(deviceId: String) throws { throw Never() }
    func leave() throws { throw Never() }
    func transferAndLeave(deviceId: String) throws { throw Never() }
    func leaveReady() throws -> Bool { throw Never() }
    func leaveState() throws -> LeaveState { throw Never() }
    func deliveriesOf(ids: [Int64]) throws -> [DeliveryUpdate] { throw Never() }
    func messageDelivery(messageId: Int64) throws -> MessageDelivery? { throw Never() }
    func deliveryCounts(contact: String) throws -> DeliveryCounts { throw Never() }
    func deliveryPage(contact: String, state: DeliveryState, limit: UInt32, offset: UInt32) throws -> [DeliveryRowInfo] { throw Never() }
    func deleteMessage(messageId: Int64) throws -> DeleteOutcome { throw Never() }
    func deleteMessages(ids: [Int64]) throws -> DeleteOutcome { throw Never() }
    func cancelAllPending() throws -> DeleteOutcome { throw Never() }
    func retryMessage(messageId: Int64) throws { throw Never() }
    func retryAll(contact: String) throws -> UInt32 { throw Never() }
    func pendingPackets() throws -> PendingPackets { throw Never() }
}
#endif
