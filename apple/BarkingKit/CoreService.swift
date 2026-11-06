import Foundation

/// The only holder of the `Device` (spec iOS messaging §4.1). Calls go one at
/// a time through the runner, syncs are never concurrent, and every
/// mutation publishes a `CoreChange`.
public actor CoreService {
    private let device: any DeviceHandle
    private let runner: any CallRunner
    private var inFlight: Task<SyncOutcome, Never>?
    /// Device calls running now (`close` waits for them).
    private var running = 0
    /// Set by `close`: no call reaches the device any more.
    private var closed = false
    private var subscribers: [UUID: AsyncStream<CoreChange>.Continuation] = [:]
    public private(set) var lastSync: SyncOutcome?
    public private(set) var lastSyncAt: Date?

    public init(device: any DeviceHandle, runner: any CallRunner) {
        self.device = device
        self.runner = runner
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
        for c in subscribers.values { c.yield(change) }
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

    /// One sync at a time: a request during a sync gets that sync's outcome.
    public func sync(reason: SyncReason) async -> SyncOutcome {
        if let inFlight { return await inFlight.value }
        if closed {
            return SyncOutcome(networkUp: false, received: 0, sent: 0, lines: ["$ barking sync"])
        }
        let task = Task { () -> SyncOutcome in
            do {
                let summary = try await call("sync") { try $0.sync(deadlineMs: Budget.appSyncMs) }
                return SyncOutcome.from(summary)
            } catch {
                return SyncOutcome(networkUp: false, received: 0, sent: 0,
                                   lines: ["$ barking sync", "internet: network unreachable, nothing is lost"])
            }
        }
        inFlight = task
        let outcome = await task.value
        inFlight = nil
        lastSync = outcome
        lastSyncAt = Date()
        publish(.network)
        if outcome.received > 0 || outcome.sent > 0 { publish(.contacts) }
        return outcome
    }
    public func nodes() async throws -> [NodeInfo] { try await call("nodes") { try $0.nodes() } }
    public func addNode(id: String, addr: String) async throws {
        try await call("node") { try $0.addNode(id: id, addr: addr) }
        publish(.network)
    }
    public func outboxCount() async throws -> Int { Int(try await call("outbox") { try $0.outboxCount() }) }

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
