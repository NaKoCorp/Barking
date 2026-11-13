import Foundation

/// The only holder of the `Device` (spec iOS messaging §4.1). Calls go one at
/// a time through the runner, syncs are never concurrent, and every
/// mutation publishes a `CoreChange`.
public actor CoreService {
    private let device: any DeviceHandle
    private let runner: any CallRunner
    private var inFlight: Task<SyncOutcome, Never>?
    /// The sync in flight is a quick one (`quickSync`).
    private var inFlightQuick = false
    /// Device calls running now (`close` waits for them).
    private var running = 0
    /// Set by `close`: no call reaches the device any more.
    private var closed = false
    private var subscribers: [UUID: AsyncStream<CoreChange>.Continuation] = [:]
    /// Window over which the state changes of sent messages are gathered
    /// into one `.delivery` per contact (spec Lot M §5.9).
    public static let deliveryWindow: Duration = .milliseconds(250)
    private let sleep: @Sendable (Duration) async -> Void
    /// Told, after each sync, which sent messages it found confirmed not
    /// delivered (the app turns them into a notification when it is not in
    /// front, spec Lot M §15.6).
    private let onFailed: (@Sendable ([DeliveryChange]) async -> Void)?
    /// State changes waiting for the end of the window, by contact.
    private var pendingDelivery: [String: Set<Int64>] = [:]
    private var deliveryFlush: Task<Void, Never>?
    public private(set) var lastSync: SyncOutcome?
    public private(set) var lastSyncAt: Date?

    /// `sleep` waits out the delivery window (tests open it by hand).
    public init(device: any DeviceHandle, runner: any CallRunner,
                onFailed: (@Sendable ([DeliveryChange]) async -> Void)? = nil,
                sleep: @escaping @Sendable (Duration) async -> Void = { try? await Task.sleep(for: $0) }) {
        self.device = device
        self.runner = runner
        self.onFailed = onFailed
        self.sleep = sleep
    }

    /// A new stream of changes; ends when the consumer stops iterating.
    public var changes: AsyncStream<CoreChange> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<CoreChange>.makeStream()
        subscribers[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { await self?.unsubscribe(id) }
        }
        return stream
    }

    private func unsubscribe(_ id: UUID) { subscribers[id] = nil }

    private func publish(_ change: CoreChange) {
        // The conversation reloads whole: no state change of it follows.
        if case .messages(let contact) = change { pendingDelivery[contact] = nil }
        for c in subscribers.values { c.yield(change) }
    }

    /// Notes state changes; the first one opens the window, the next ones
    /// join it, and the window's end publishes one `.delivery` per contact.
    private func noteDelivery(_ changes: [DeliveryChange]) {
        guard !changes.isEmpty, !closed else { return }
        for c in changes { pendingDelivery[c.contact, default: []].insert(c.messageId) }
        guard deliveryFlush == nil else { return }
        let window = Self.deliveryWindow, sleep = self.sleep
        deliveryFlush = Task { [weak self] in
            await sleep(window)
            await self?.flushDelivery()
        }
    }

    private func flushDelivery() {
        let batch = pendingDelivery
        pendingDelivery = [:]
        deliveryFlush = nil
        guard !closed else { return }
        for contact in batch.keys.sorted() {
            publish(.delivery(contact: contact, ids: batch[contact]!.sorted()))
        }
    }

    /// Publishes what a deletion touched: the conversations to reload whole,
    /// the chat list, and the pending count.
    private func publishDeleted(_ outcome: DeleteOutcome) {
        var seen: Set<String> = []
        for c in outcome.changes where seen.insert(c.contact).inserted { publish(.messages(contact: c.contact)) }
        publish(.contacts)
        publish(.network)
    }

    private func call<T: Sendable>(_ name: String, _ body: @escaping @Sendable (any DeviceHandle) throws -> T) async throws -> T {
        if closed { throw CancellationError() }
        let device = self.device
        running += 1
        defer { running -= 1 }
        return try await runner.run(name) { try body(device) }
    }

    /// Stops using the device before its files are erased (reset of a device
    /// removed from its account): new calls and syncs are refused, then this
    /// waits for the sync and the calls in flight.
    public func close() async {
        closed = true
        deliveryFlush?.cancel()
        pendingDelivery = [:]
        if let inFlight { _ = await inFlight.value }
        while running > 0 { try? await Task.sleep(for: .milliseconds(10)) }
    }

    // MARK: Identity

    public func fingerprint() async throws -> String { try await call("fingerprint") { try $0.fingerprint() } }
    public func displayName() async throws -> String { try await call("name") { try $0.displayName() } }
    public func setDisplayName(_ name: String) async throws {
        try await call("name") { try $0.setDisplayName(name: name) }
        publish(.identity)
    }
    public func myCard() async throws -> (bytes: Data, text: String) {
        try await call("card") { d in
            (try d.contactCardBytes(), try d.contactCard(displayName: try d.displayName()))
        }
    }
    public func myDevices() async throws -> [MyDeviceInfo] { try await call("devices") { try $0.myDevices() } }
    /// Hands the root key to my device `id`; this one keeps it until the ack.
    public func transferAdmin(to id: String) async throws {
        try await call("transfer") { try $0.transferAdmin(deviceId: id) }
        publish(.devices)
    }
    public func adminTransferPending() async throws -> String? {
        try await call("transfer") { try $0.adminTransferPending() }
    }
    /// Set once a newer device list removed this device from the account.
    public func removed() async throws -> RemovedInfo? { try await call("removed") { try $0.removed() } }
    /// Removes my device `id` (administrator only); a sync sends the new list.
    public func removeDevice(_ id: String) async throws {
        try await call("remove-device") { try $0.removeDevice(deviceId: id) }
        publish(.devices)
        Task { _ = await self.sync(reason: .afterSend) }
    }
    /// This linked device asks my other devices to remove it (`leaveReady`
    /// is then true; a sync sends the request).
    public func leave() async throws {
        try await call("leave") { try $0.leave() }
        publish(.devices)
    }
    /// The administrator hands the root key to `id`, which removes this
    /// device at the ack (`leaveReady`).
    public func transferAndLeave(to id: String) async throws {
        try await call("transfer") { try $0.transferAndLeave(deviceId: id) }
        publish(.devices)
    }
    /// The request to be removed is queued: once sent, this device may be wiped.
    public func leaveReady() async throws -> Bool { try await call("leave-ready") { try $0.leaveReady() } }
    /// Where that request stands: wipe on `.left` only, leave again on `.expired`.
    public func leaveState() async throws -> LeaveState { try await call("leave-state") { try $0.leaveState() } }

    // MARK: Contacts

    public func contacts() async throws -> [Contact] { try await call("contacts") { try $0.contacts() } }
    public func addContact(card: Data, alias: String?) async throws -> String {
        let fp = try await call("add") { try $0.addContactBytes(card: card, alias: alias) }
        publish(.contacts)
        return fp
    }
    public func addContact(text: String, alias: String?) async throws -> String {
        let fp = try await call("add") { try $0.addContact(card: text, alias: alias) }
        publish(.contacts)
        return fp
    }
    public func setAlias(_ contact: String, alias: String) async throws {
        try await call("alias") { try $0.setAlias(contact: contact, alias: alias) }
        publish(.contacts)
    }
    public func removeContact(_ contact: String) async throws {
        try await call("remove") { try $0.removeContact(contact: contact) }
        publish(.contacts)
    }
    public func markVerified(_ contact: String) async throws {
        try await call("verify") { try $0.markVerified(contact: contact) }
        publish(.contacts)
    }
    public func unmarkVerified(_ contact: String) async throws {
        try await call("unverify") { try $0.unmarkVerified(contact: contact) }
        publish(.contacts)
    }
    public func safetyNumber(for contact: String) async throws -> [String] {
        try await call("safety") { try $0.safetyNumber(contact: contact) }
    }
    public func keyChanges(since: UInt64) async throws -> [KeyChange] {
        try await call("keys") { try $0.keyChanges(since: since) }
    }
    /// A page of the transparency log, newest first: up to `limit` entries
    /// older than the entry `before` (`LogEntry.id`; nil: from the newest).
    public func transparencyLog(limit: UInt32, before: Int64?, securityOnly: Bool) async throws -> [LogEntry] {
        try await call("log") { try $0.transparencyLog(limit: limit, before: before, securityOnly: securityOnly) }
    }
    /// Devices of a contact, as its card lists them.
    public func contactDevices(_ contact: String) async throws -> [MyDeviceInfo] {
        try await call("contactDevices") { try $0.contactDevices(contact: contact) }
    }

    // MARK: Messages

    public func messages(with contact: String) async throws -> [Message] {
        try await call("messages") { try $0.messagesWith(contact: contact) }
    }
    /// Recorded steps of the message `id` (`Message.id`), by date.
    public func messageRoute(_ id: Int64) async throws -> [RouteStepInfo] {
        try await call("route") { try $0.messageRoute(messageId: id) }
    }
    public func send(_ text: String, to contact: String) async throws {
        try await call("send") { try $0.sendText(contact: contact, text: text) }
        publish(.messages(contact: contact))
        Task { _ = await self.sync(reason: .afterSend) }
    }
    // MARK: Delivery

    /// Fresh delivery of the messages `ids`, in that order; a deleted or
    /// unknown id comes back `removed`.
    public func deliveriesOf(_ ids: [Int64]) async throws -> [DeliveryUpdate] {
        try await call("deliveries") { try $0.deliveriesOf(ids: ids) }
    }
    /// The message sheet of a sent message (nil: received, or unknown).
    public func messageDelivery(_ id: Int64) async throws -> MessageDelivery? {
        try await call("delivery") { try $0.messageDelivery(messageId: id) }
    }
    /// Sent messages to `contact` per state (the "Sent" group titles).
    public func deliveryCounts(contact: String) async throws -> DeliveryCounts {
        try await call("delivery-counts") { try $0.deliveryCounts(contact: contact) }
    }
    /// A page of the sent messages to `contact` in `state`, newest first.
    public func deliveryPage(contact: String, state: DeliveryState, limit: UInt32, offset: UInt32) async throws -> [DeliveryRowInfo] {
        try await call("delivery-page") { try $0.deliveryPage(contact: contact, state: state, limit: limit, offset: offset) }
    }
    /// Deletes one message; the outcome says what it really did (spec §6.7).
    public func deleteMessage(_ id: Int64) async throws -> DeleteOutcome {
        let outcome = try await call("delete") { try $0.deleteMessage(messageId: id) }
        publishDeleted(outcome)
        return outcome
    }
    public func deleteMessages(_ ids: [Int64]) async throws -> DeleteOutcome {
        let outcome = try await call("delete") { try $0.deleteMessages(ids: ids) }
        publishDeleted(outcome)
        return outcome
    }
    /// Deletes every sent message still pending, all contacts.
    public func cancelAllPending() async throws -> DeleteOutcome {
        let outcome = try await call("cancel-all") { try $0.cancelAllPending() }
        publishDeleted(outcome)
        return outcome
    }
    /// Sends a not delivered message to `contact` again (same row, back to
    /// pending); a sync deposits it. The core returns no change, so the
    /// row is named here: every screen showing it updates, even offline.
    public func retryMessage(_ id: Int64, contact: String) async throws {
        try await call("retry") { try $0.retryMessage(messageId: id) }
        noteDelivery([DeliveryChange(contact: contact, messageId: id)])
        publish(.contacts)
        publish(.network)
        Task { _ = await self.sync(reason: .afterSend) }
    }
    /// Sends every not delivered message to `contact` again; returns how many.
    @discardableResult
    public func retryAll(contact: String) async throws -> Int {
        let n = try await call("retry-all") { try $0.retryAll(contact: contact) }
        publish(.messages(contact: contact))
        publish(.network)
        if n > 0 { Task { _ = await self.sync(reason: .afterSend) } }
        return Int(n)
    }
    /// The pending packets screen.
    public func pendingPackets() async throws -> PendingPackets {
        try await call("pending-packets") { try $0.pendingPackets() }
    }

    public func chatSummaries() async throws -> [ChatSummary] {
        try await call("chats") { try $0.chatSummaries() }
    }
    public func unreadCounts() async throws -> [String: Int] {
        let counts = try await call("unread") { try $0.unreadCounts() }
        return Dictionary(counts.map { ($0.contact, Int($0.count)) }, uniquingKeysWith: { a, _ in a })
    }
    public func markRead(_ contact: String, upTo: Int64) async throws {
        try await call("read") { try $0.markRead(contact: contact, upTo: upTo) }
        publish(.contacts)
    }

    // MARK: Network

    /// One sync at a time: a request during a full sync gets that sync's
    /// outcome. During a quick sync it waits for it, then runs its own: a
    /// quick sync deposits no message (a send would wait for the next timer).
    public func sync(reason: SyncReason) async -> SyncOutcome {
        while inFlightQuick, let task = inFlight {
            _ = await task.value
            if inFlight == task { finish(task) }
        }
        return await runSync("sync", quick: false) { try $0.sync(deadlineMs: Budget.appSyncMs) }
    }

    /// The short sync of a background (receipt) wake, within
    /// `Budget.appQuickSyncMs`: my mailboxes of yesterday and today, and
    /// those where a sent message awaits its receipt; then receipts only.
    /// During any sync it gets that sync's outcome (a full one fetches all of
    /// these too). A failure gives `networkUp: false`.
    public func quickSync() async -> SyncOutcome {
        await runSync("quick-sync", quick: true) { try $0.quickSync(deadlineMs: Budget.appQuickSyncMs) }
    }

    /// Clears the sync in flight, if it is still `task`.
    private func finish(_ task: Task<SyncOutcome, Never>) {
        guard inFlight == task else { return }
        inFlight = nil
        inFlightQuick = false
    }

    private func runSync(_ name: String, quick: Bool,
                         _ body: @escaping @Sendable (any DeviceHandle) throws -> SyncSummary) async -> SyncOutcome {
        if let inFlight { return await inFlight.value }
        if closed {
            return SyncOutcome(networkUp: false, received: 0, sent: 0, lines: ["$ barking sync"])
        }
        let task = Task { () -> SyncOutcome in
            do {
                let summary = try await call(name, body)
                return SyncOutcome.from(summary)
            } catch {
                return SyncOutcome(networkUp: false, received: 0, sent: 0,
                                   lines: ["$ barking sync", "internet: network unreachable, nothing is lost"])
            }
        }
        inFlight = task
        inFlightQuick = quick
        let outcome = await task.value
        // A full sync waiting for this one may have cleared it and started.
        finish(task)
        lastSync = outcome
        lastSyncAt = Date()
        publish(.network)
        if outcome.received > 0 || outcome.sent > 0 { publish(.contacts) }
        // A new message (or a copy of one I sent from another device)
        // reloads its conversation whole; the others, whose state alone
        // changed, refresh their rows after the window.
        noteDelivery(outcome.deliveryChanges)
        if !outcome.failed.isEmpty { await onFailed?(outcome.failed) }
        for contact in Set(outcome.newMessageContacts + outcome.syncedContacts).sorted() {
            publish(.messages(contact: contact))
        }
        return outcome
    }
    public func nodes() async throws -> [NodeInfo] { try await call("nodes") { try $0.nodes() } }
    public func addNode(id: String, addr: String) async throws {
        try await call("node") { try $0.addNode(id: id, addr: addr) }
        publish(.network)
    }
    /// Wake-up settings (`nil`: push off), used from the next full sync.
    public func setPush(_ settings: PushSettings?) async throws {
        try await call("push") { try $0.setPush(settings: settings) }
    }
    public func notificationPrefs() async throws -> NotificationPrefs {
        try await call("notification-prefs") { try $0.notificationPrefs() }
    }
    public func setInstant(_ on: Bool) async throws {
        try await call("instant") { try $0.setInstant(on: on) }
    }
    public func setPreview(_ preview: PushPreview) async throws {
        try await call("preview") { try $0.setPreview(preview: preview) }
    }
    /// Notes that a push woke the app now; a failure changes nothing.
    public func noteWake() async {
        let now = UInt64(Date().timeIntervalSince1970)
        try? await call("note-wake") { try $0.noteWake(atSecs: now) }
    }
    public func wakeStatus() async throws -> WakeStatus {
        try await call("wake-status") { try $0.wakeStatus() }
    }
    /// Packets no node accepted yet (the pending packets screen's count).
    public func pendingCount() async throws -> Int { Int(try await call("pending") { try $0.pendingCount() }) }

    // MARK: Linking

    public func linkOffer() async throws -> Data { try await call("offer") { try $0.linkOffer() } }
    public func linkDevice(request: Data, history: Bool) async throws -> Data {
        let package = try await call("link") { try $0.linkDevice(request: request, withHistory: history) }
        publish(.devices)
        return package
    }
    public func isPendingLink() async throws -> Bool { try await call("pending") { try $0.isPendingLink() } }
    public func finishLink(_ package: Data) async throws {
        try await call("finish") { try $0.finishLink(package: package) }
        publish(.contacts)
        publish(.devices)
    }
}
