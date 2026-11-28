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
    /// A sync is running now, whoever started it.
    public var isSyncing: Bool { inFlight != nil }

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
    /// After a deletion: the screens it touched reload; something deleted
    /// syncs at once, so that my other devices hear of it (`SyncDelete`).
    private func publishDeleted(_ outcome: DeleteOutcome) {
        var seen: Set<String> = []
        for c in outcome.changes where seen.insert(c.contact).inserted { publish(.messages(contact: c.contact)) }
        publish(.contacts)
        publish(.network)
        if outcome.deleted > 0 { Task { _ = await self.sync(reason: .afterSend) } }
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
    /// Every contact's avatar, kept on this device only (never synced nor
    /// sent). A read: it does not wait for a sync.
    public func contactAvatars() async throws -> [ContactAvatarEntry] {
        try await call("avatars") { try $0.contactAvatars() }
    }
    /// Sets (or, with nil, clears) a contact's avatar on this device; the
    /// lists showing it reload on `.contacts`.
    public func setContactAvatar(_ contact: String, _ avatar: ContactAvatar?) async throws {
        try await call("avatar") { try $0.setContactAvatar(contact: contact, avatar: avatar) }
        publish(.contacts)
    }
    public func removeContact(_ contact: String) async throws {
        try await call("remove") { try $0.removeContact(contact: contact) }
        publish(.contacts)
    }
    /// Keeps the unsent text of a conversation (blank clears it). No change
    /// is published: nothing else shows a draft.
    public func setDraft(_ contact: String, text: String) async throws {
        try await call("draft-set") { try $0.setDraft(contact: contact, text: text) }
    }
    public func draft(_ contact: String) async throws -> String? {
        try await call("draft") { try $0.draft(contact: contact) }
    }
    public func markVerified(_ contact: String) async throws {
        try await call("verify") { try $0.markVerified(contact: contact) }
        publish(.contacts)
    }
    public func unmarkVerified(_ contact: String) async throws {
        try await call("unverify") { try $0.unmarkVerified(contact: contact) }
        publish(.contacts)
    }
    /// Blocks a contact: it leaves the contact and chat lists, its messages
    /// are dropped and nothing is sent to it. Synchronized with my devices.
    public func blockContact(_ contact: String) async throws {
        try await call("block") { try $0.blockContact(contact: contact) }
        publish(.contacts)
    }
    public func unblockContact(_ contact: String) async throws {
        try await call("unblock") { try $0.unblockContact(contact: contact) }
        publish(.contacts)
    }
    public func blockedContacts() async throws -> [Contact] {
        try await call("blocked") { try $0.blockedContacts() }
    }
    /// Blocked fingerprints that are no contact (a blocked requester), for
    /// the same list; `unblockContact` takes them.
    public func blockedFingerprints() async throws -> [String] {
        try await call("blocked-fp") { try $0.blockedFingerprints() }
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

    // MARK: Contact requests

    /// Contact requests, hidden ones included (`ContactRequestInfo.hidden`).
    /// The chat list shows them: every change to one publishes `.contacts`.
    public func requests() async throws -> [ContactRequestInfo] {
        try await call("requests") { try $0.requests() }
    }
    public func requestSafetyNumber(_ fp: String) async throws -> [String] {
        try await call("request-safety") { try $0.requestSafetyNumber(fingerprint: fp) }
    }
    /// The requester becomes a contact (not verified); returns its
    /// fingerprint. Its held messages show in its conversation. Accepting,
    /// refusing, blocking and inviting queue packets: a sync sends them now.
    public func acceptRequest(_ fp: String, alias: String?) async throws -> String {
        let contact = try await call("accept") { try $0.acceptRequest(fingerprint: fp, alias: alias) }
        publish(.contacts)
        publish(.messages(contact: contact))
        Task { _ = await self.sync(reason: .afterSend) }
        return contact
    }
    /// Drops the request; nothing goes to the requester.
    public func refuseRequest(_ fp: String) async throws {
        try await call("refuse") { try $0.refuseRequest(fingerprint: fp) }
        publish(.contacts)
        Task { _ = await self.sync(reason: .afterSend) }
    }
    /// Drops the request and the requester's later invitations.
    public func blockRequest(_ fp: String) async throws {
        try await call("block-request") { try $0.blockRequest(fingerprint: fp) }
        publish(.contacts)
        Task { _ = await self.sync(reason: .afterSend) }
    }
    public func setRequestHidden(_ fp: String, hidden: Bool) async throws {
        try await call("request-hidden") { try $0.setRequestHidden(fingerprint: fp, hidden: hidden) }
        publish(.contacts)
    }
    /// The requests screen was opened: none is new any more.
    public func markRequestsSeen() async throws {
        try await call("requests-seen") { try $0.markRequestsSeen() }
        publish(.contacts)
    }
    /// Invites a contact who has not added me yet; within 24 hours of the
    /// last one: `BarkingError.TooSoon(retryAt:)`.
    public func invite(_ contact: String) async throws {
        try await call("invite") { try $0.invite(contact: contact) }
        publish(.contacts)
        Task { _ = await self.sync(reason: .afterSend) }
    }
    public func inviteStatus(_ contact: String) async throws -> InviteStatus {
        try await call("invite-status") { try $0.inviteStatus(contact: contact) }
    }
    public func setInviteNotifications(_ on: Bool) async throws {
        try await call("invite-notifications") { try $0.setInviteNotifications(on: on) }
    }
    /// Contacts whose devices were replaced, logged at or after `since` (Unix seconds).
    public func deviceChanges(since: UInt64) async throws -> [DeviceChange] {
        try await call("device-changes") { try $0.deviceChanges(since: since) }
    }

    // MARK: Messages

    public func messages(with contact: String) async throws -> [Message] {
        try await call("messages") { try $0.messagesWith(contact: contact) }
    }
    /// Recorded steps of the message `id` (`Message.id`), by date.
    public func messageRoute(_ id: Int64) async throws -> [RouteStepInfo] {
        try await call("route") { try $0.messageRoute(messageId: id) }
    }
    /// Queues `text` for `contact`; `replyTo`: the `Message.id` it answers
    /// (`BarkingError.MessageNotFound` if that row is gone or not quotable).
    /// `ttlSecs`: an ephemeral message, erased that long after it is seen
    /// (60 to 604 800 seconds, else `BarkingError.InvalidInput`); nil: a
    /// plain one.
    /// Returns the conversation's rows, read in the same call, before the
    /// sync starts: that sync holds the core through its network round, so
    /// a read after it would leave the sent bubble without its row (no
    /// details, no menu) until the round ends. Nil if that read failed.
    /// `clearingDraft`: the stored draft goes in that call too, once sent
    /// (a failed send keeps it); `false` if clearing it failed.
    @discardableResult
    public func send(_ text: String, to contact: String, replyTo: Int64? = nil,
                     ttlSecs: UInt32? = nil, clearingDraft: Bool = false) async throws -> SendResult {
        let result = try await call("send") { device -> SendResult in
            try device.sendText(contact: contact, text: text, replyTo: replyTo, ttlSecs: ttlSecs)
            let cleared = clearingDraft ? (try? device.setDraft(contact: contact, text: "")) != nil : false
            return SendResult(rows: try? device.messagesWith(contact: contact), draftCleared: cleared)
        }
        publish(.messages(contact: contact))
        Task { _ = await self.sync(reason: .afterSend) }
        return result
    }

    /// What `send` read and did in its call.
    public struct SendResult: Sendable {
        public let rows: [Message]?
        public let draftCleared: Bool
    }
    /// Replaces my reactions on message `messageId` of the conversation with
    /// `contact` (empty: removes mine); the packets leave with the next sync.
    public func setReactions(_ messageId: Int64, emojis: [String], contact: String) async throws {
        try await call("reactions") { try $0.setReactions(message: messageId, emojis: emojis) }
        publish(.messages(contact: contact))
        Task { _ = await self.sync(reason: .afterSend) }
    }
    /// The ephemeral rows `ids` are on screen: seen now. The core ignores
    /// rows that are not ephemeral or already seen; a sync starts at once
    /// so that my other devices start the countdown too (not hours later,
    /// if the app goes to the background first). Nothing is published: the
    /// conversation that reported them reloads itself.
    public func markSeen(_ ids: [Int64]) async throws {
        guard !ids.isEmpty else { return }
        try await call("seen") { try $0.markSeen(ids: ids) }
        Task { _ = await self.sync(reason: .afterSend) }
    }
    /// When the next ephemeral is due (Unix seconds); nil without any.
    public func nextExpiry() async throws -> UInt64? {
        try await call("next-expiry") { try $0.nextExpiry() }
    }
    /// Erases the ephemerals due now and publishes their rows (`.expired`).
    @discardableResult
    public func expireEphemeral() async throws -> [Int64] {
        let ids = try await call("expire") { try $0.expireEphemeral() }
        if !ids.isEmpty { publish(.expired(ids: ids)) }
        return ids
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
    /// The send of my reactions on the message `id` toward its contact (nil:
    /// none tracked). It covers the contact send only: `ownCopies.total` can
    /// be 0 after a retry, which does not mean "no copies".
    public func reactionDelivery(_ id: Int64) async throws -> ReactionDelivery? {
        try await call("reaction-delivery") { try $0.reactionDelivery(message: id) }
    }
    /// Sends my reactions on the message `id` to `contact` again (a manual
    /// resend; a sync deposits them). The row is named here so every screen
    /// showing it updates, even offline.
    public func retryReactions(_ id: Int64, contact: String) async throws {
        try await call("retry-reactions") { try $0.retryReactions(message: id) }
        noteDelivery([DeliveryChange(contact: contact, messageId: id)])
        publish(.network)
        Task { _ = await self.sync(reason: .afterSend) }
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
        await waitForQuickSync()
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

    /// The full sync of a background refresh, within `Budget.refreshSyncMs`.
    /// Its outcome carries the new messages to notify.
    public func refreshSync() async -> SyncOutcome {
        await waitForQuickSync()
        return await runSync("refresh", quick: false) { try $0.sync(deadlineMs: Budget.refreshSyncMs) }
    }

    /// Waits out a quick sync in flight (a full sync must not take its outcome).
    private func waitForQuickSync() async {
        while inFlightQuick, let task = inFlight {
            _ = await task.value
            if inFlight == task { finish(task) }
        }
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
        publish(.syncStarted)
        let outcome = await task.value
        // A full sync waiting for this one may have cleared it and started.
        finish(task)
        lastSync = outcome
        lastSyncAt = Date()
        publish(.network)
        // Contact requests show in the chat list: one that moved reloads it.
        if outcome.received > 0 || outcome.sent > 0 || !outcome.requestContacts.isEmpty { publish(.contacts) }
        // It expired first: the rows it erased leave every screen.
        if !outcome.expired.isEmpty { publish(.expired(ids: outcome.expired)) }
        // A new message (or a copy of one I sent from another device)
        // reloads its conversation whole; the others, whose state alone
        // changed, refresh their rows after the window.
        noteDelivery(outcome.deliveryChanges)
        if !outcome.failed.isEmpty { await onFailed?(outcome.failed) }
        for contact in Set(outcome.newMessageContacts + outcome.syncedContacts + outcome.reactionContacts).sorted() {
            publish(.messages(contact: contact))
        }
        return outcome
    }
    public func nodes() async throws -> [NodeInfo] { try await call("nodes") { try $0.nodes() } }
    public func addNode(id: String, addr: String) async throws {
        try await call("node") { try $0.addNode(id: id, addr: addr) }
        publish(.network)
    }
    public func nodeDetail(id: String) async throws -> NodeDetail {
        try await call("node-detail") { try $0.nodeDetail(id: id) }
    }
    public func refreshNodeInfo(id: String) async throws -> NodeDetail {
        let detail = try await call("node-refresh") { try $0.refreshNodeInfo(id: id) }
        publish(.network)
        return detail
    }
    public func removeNode(id: String) async throws {
        try await call("node-remove") { try $0.removeNode(id: id) }
        publish(.network)
    }
    public func blockNode(id: String) async throws {
        try await call("node-block") { try $0.blockNode(id: id) }
        publish(.network)
    }
    public func unblockNode(id: String) async throws {
        try await call("node-unblock") { try $0.unblockNode(id: id) }
        publish(.network)
    }
    public func blockedNodes() async throws -> [BlockedNode] {
        try await call("blocked-nodes") { try $0.blockedNodes() }
    }
    /// Adds the nodes the app was built with (one call), unless dismissed.
    public func addDefaultNodes(_ entries: [DefaultNode]) async throws {
        try await call("default-nodes") { try $0.addDefaultNodes(entries: entries) }
        publish(.network)
    }
    /// Restores the dismissed default nodes; how many came back.
    public func resetDefaultNodes(_ entries: [DefaultNode]) async throws -> Int {
        let restored = try await call("default-nodes-reset") { try $0.resetDefaultNodes(entries: entries) }
        publish(.network)
        return Int(restored)
    }
    public func dismissedDefaultsCount() async throws -> Int {
        Int(try await call("dismissed-defaults") { try $0.dismissedDefaultsCount() })
    }
    /// How many nodes would still be usable if `id` were blocked.
    public func usableNodesIfBlocked(id: String) async throws -> Int {
        Int(try await call("usable-if-blocked") { try $0.usableNodesIfBlocked(id: id) })
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

    // MARK: GIFs (spec GIF §6.6)

    /// The provider keys the app was built with; kept in memory by the core.
    public func configureGifs(klipyKey: String?) async throws {
        try await call("gif-keys") { $0.configureGifs(klipyKey: klipyKey) }
    }
    public func gifProvider() async throws -> GifProviderInfo { try await call("gif-provider") { $0.gifProvider() } }
    public func gifSettings() async throws -> GifSettingsInfo { try await call("gif-settings") { try $0.gifSettings() } }
    /// After the warning was accepted. The change leaves for my other
    /// devices with the next sync, started at once (as after a send).
    /// Returns the settings read in the same call, before that sync holds
    /// the core (nil if that read failed; the write stands).
    @discardableResult
    public func enableGifProvider(_ provider: UInt8, warningVersion: UInt16) async throws -> GifSettingsInfo? {
        try await gifWrite("gif-enable") { try $0.enableGifProvider(provider: provider, warningVersion: warningVersion) }
    }
    /// As `enableGifProvider`.
    @discardableResult
    public func disableGifProvider(_ provider: UInt8) async throws -> GifSettingsInfo? {
        try await gifWrite("gif-disable") { try $0.disableGifProvider(provider: provider) }
    }
    /// As `enableGifProvider`.
    @discardableResult
    public func setGifAutoLoad(_ on: Bool) async throws -> GifSettingsInfo? {
        try await gifWrite("gif-auto-load") { try $0.setGifAutoLoad(on: on) }
    }
    /// A GIF settings write, the settings read back in the same call, then the sync.
    private func gifWrite(_ name: String,
                          _ body: @escaping @Sendable (any DeviceHandle) throws -> Void) async throws -> GifSettingsInfo? {
        let settings = try await call(name) { device -> GifSettingsInfo? in
            try body(device)
            return try? device.gifSettings()
        }
        Task { _ = await self.sync(reason: .afterSend) }
        return settings
    }
    public func gifSearch(_ query: String, page: UInt32) async throws -> GifPageInfo {
        try await call("gif-search") { try $0.gifSearch(query: query, page: page) }
    }
    public func gifTrending(page: UInt32) async throws -> GifPageInfo {
        try await call("gif-trending") { try $0.gifTrending(page: page) }
    }
    /// A picker preview's MP4, from the core (consent, hosts, counted).
    public func gifPreview(_ url: String) async throws -> Data {
        try await call("gif-preview") { try $0.gifPreview(url: url) }
    }
    public func gifData(provider: UInt8, id: String) async throws -> GifMediaInfo {
        try await call("gif-data") { try $0.gifData(provider: provider, id: id) }
    }
    /// Queues `gif` for `contact`, as `send` a text (same `replyTo` and
    /// `ttlSecs` rules); the conversation's rows, read in the same call.
    @discardableResult
    public func sendGif(_ gif: GifInfo, to contact: String, replyTo: Int64? = nil,
                        ttlSecs: UInt32? = nil) async throws -> [Message]? {
        let rows = try await call("send-gif") { device -> [Message]? in
            try device.sendGif(contact: contact, gif: gif, replyTo: replyTo, ttlSecs: ttlSecs)
            return try? device.messagesWith(contact: contact)
        }
        publish(.messages(contact: contact))
        Task { _ = await self.sync(reason: .afterSend) }
        return rows
    }
    /// Usage of the last `days` days with a use, newest first (this device).
    public func gifUsage(days: UInt8) async throws -> [GifUsageDayInfo] {
        try await call("gif-usage") { try $0.gifUsage(days: days) }
    }

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
