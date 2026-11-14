import Foundation
@testable import BarkingKit

/// In-memory stand-in for the FFI `Device`: records calls, returns canned data.
final class FakeDevice: DeviceHandle, @unchecked Sendable {
    private let lock = NSLock()
    private var _syncCalls = 0
    private var _sent: [(String, String)] = []
    var syncDelay: TimeInterval = 0
    var summary = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: true, error: nil)
    var contactList: [Contact] = []
    var messageList: [String: [Message]] = [:]
    /// Route of each message, by message id.
    var routes: [Int64: [RouteStepInfo]] = [:]
    var verified: Set<String> = []
    var reads: [(String, Int64)] = []
    var unread: [UnreadCount] = []
    var keyChangeList: [KeyChange] = []
    /// The transparency log, newest first.
    var logEntries: [LogEntry] = []
    /// Devices of each contact's card.
    var contactDeviceList: [String: [MyDeviceInfo]] = [:]
    var devicesList: [MyDeviceInfo] = []
    var removedInfo: RemovedInfo?
    private var _transferredTo: [String] = []
    var transferredTo: [String] { lock.withLock { _transferredTo } }
    var pending = false
    /// Packets no node accepted yet (`pendingCount`).
    var pendingCountValue: UInt32 = 0
    var sendError: Error?
    /// Thrown by markVerified / unmarkVerified when set.
    var verifyError: Error?
    private var _linkCalls = 0
    private var _summaryCalls = 0
    var summaryCalls: Int { lock.withLock { _summaryCalls } }
    var linkCalls: Int { lock.withLock { _linkCalls } }

    var syncCalls: Int { lock.withLock { _syncCalls } }
    var sent: [(String, String)] { lock.withLock { _sent } }

    func fingerprint() throws -> String { "fp-me" }
    func displayName() throws -> String { "Me" }
    func setDisplayName(name: String) throws {}
    func contacts() throws -> [Contact] { contactList }
    private var _messagesCalls = 0
    /// How many times `messagesWith` ran (a conversation's full reloads).
    var messagesCalls: Int { lock.withLock { _messagesCalls } }
    func messagesWith(contact: String) throws -> [Message] {
        lock.withLock { _messagesCalls += 1 }
        return messageList[contact] ?? []
    }
    func messageRoute(messageId: Int64) throws -> [RouteStepInfo] { routes[messageId] ?? [] }
    func sendText(contact: String, text: String) throws {
        if let sendError { throw sendError }
        Thread.sleep(forTimeInterval: syncDelay)
        lock.withLock { _sent.append((contact, text)) }
    }
    /// How long `addContactBytes` takes, and how many times it ran.
    var addDelay: TimeInterval = 0
    private var _addCalls = 0
    var addCalls: Int { lock.withLock { _addCalls } }
    func addContactBytes(card: Data, alias: String?) throws -> String {
        Thread.sleep(forTimeInterval: addDelay)
        lock.withLock { _addCalls += 1 }
        return "fp-new"
    }
    func addContact(card: String, alias: String?) throws -> String { "fp-new" }
    func contactCardBytes() throws -> Data { Data([1, 2, 3]) }
    func contactCard(displayName: String) throws -> String { "barking1:abc" }
    func setAlias(contact: String, alias: String) throws {}
    func removeContact(contact: String) throws {}
    func markVerified(contact: String) throws {
        if let verifyError { throw verifyError }
        verified.insert(contact)
    }
    func unmarkVerified(contact: String) throws {
        if let verifyError { throw verifyError }
        verified.remove(contact)
    }
    func safetyNumber(contact: String) throws -> [String] { Array(repeating: "12345", count: 12) }
    func unreadCounts() throws -> [UnreadCount] { unread }
    func chatSummaries() throws -> [ChatSummary] {
        lock.withLock { _summaryCalls += 1 }
        return contactList.map { c in
            ChatSummary(contact: c, last: messageList[c.fingerprint]?.last,
                        unread: unread.first { $0.contact == c.fingerprint }?.count ?? 0,
                        route: messageList[c.fingerprint]?.last?.route)
        }
    }
    func markRead(contact: String, upTo: Int64) throws { reads.append((contact, upTo)) }
    func keyChanges(since: UInt64) throws -> [KeyChange] { keyChangeList }
    func transparencyLog(limit: UInt32, before: Int64?, securityOnly: Bool) throws -> [LogEntry] {
        let all = securityOnly ? logEntries.filter(\.security) : logEntries
        return Array(all.filter { before == nil || $0.id < before! }.prefix(Int(limit)))
    }
    func contactDevices(contact: String) throws -> [MyDeviceInfo] { contactDeviceList[contact] ?? [] }
    func sync(deadlineMs: UInt64) throws -> SyncSummary {
        // A sync deposits what was queued when it started.
        let queued = lock.withLock {
            _syncCalls += 1
            _syncEvents.append("sync")
            return _leaveReady && !_leaveExpired
        }
        defer { lock.withLock { _syncEvents.append("sync-done") } }
        Thread.sleep(forTimeInterval: syncDelay)
        if queued, summary.networkUp, !depositFails { lock.withLock { _leaveDeposited = true } }
        return summary
    }
    private var _quickSyncDeadlines: [UInt64] = []
    /// Deadline of each quick sync, in call order.
    var quickSyncDeadlines: [UInt64] { lock.withLock { _quickSyncDeadlines } }
    /// Thrown by `quickSync` when set.
    var quickSyncError: Error?
    func quickSync(deadlineMs: UInt64) throws -> SyncSummary {
        lock.withLock { _quickSyncDeadlines.append(deadlineMs); _syncEvents.append("quick") }
        defer { lock.withLock { _syncEvents.append("quick-done") } }
        if let quickSyncError { throw quickSyncError }
        Thread.sleep(forTimeInterval: syncDelay)
        return summary
    }
    private var _syncEvents: [String] = []
    /// Starts and ends of syncs, in order ("sync", "sync-done", "quick", "quick-done").
    var syncEvents: [String] { lock.withLock { _syncEvents } }
    func nodes() throws -> [NodeInfo] { [] }
    private var _addedNodes: [String] = []
    /// `id@addr` of each `addNode` call, in order.
    var addedNodes: [String] { lock.withLock { _addedNodes } }
    func addNode(id: String, addr: String) throws { lock.withLock { _addedNodes.append("\(id)@\(addr)") } }
    private var _pushSettings: [PushSettings?] = []
    /// Every `setPush` call, in order (`nil`: push off).
    var pushSettings: [PushSettings?] { lock.withLock { _pushSettings } }
    func setPush(settings: PushSettings?) throws { lock.withLock { _pushSettings.append(settings) } }
    func pendingCount() throws -> UInt32 { pendingCountValue }
    func myDevices() throws -> [MyDeviceInfo] { devicesList }
    func linkOffer() throws -> Data { Data([0xAA]) }
    func linkDevice(request: Data, withHistory: Bool) throws -> Data {
        lock.withLock { _linkCalls += 1 }
        Thread.sleep(forTimeInterval: syncDelay)
        return Data([0xBB])
    }
    func isPendingLink() throws -> Bool { pending }
    func transferAdmin(deviceId: String) throws { lock.withLock { _transferredTo.append(deviceId) } }
    func adminTransferPending() throws -> String? {
        if let readError { throw readError }
        return lock.withLock { transferExpired ? nil : _transferredTo.last }
    }
    func removed() throws -> RemovedInfo? { removedInfo }
    private var _removedIds: [String] = []
    var removedIds: [String] { lock.withLock { _removedIds } }
    func removeDevice(deviceId: String) throws { lock.withLock { _removedIds.append(deviceId) } }
    private var _leaveCalls = 0
    var leaveCalls: Int { lock.withLock { _leaveCalls } }
    func leave() throws {
        lock.withLock {
            _leaveCalls += 1
            _leaveReady = true
            _leaveExpired = false
            _leaveDeposited = false
        }
    }
    private var _leavingTo: [String] = []
    var leavingTo: [String] { lock.withLock { _leavingTo } }
    func transferAndLeave(deviceId: String) throws {
        lock.withLock {
            _leavingTo.append(deviceId)
            _transferredTo.append(deviceId)
        }
    }
    private var _leaveReady = false
    var leaveReadyValue: Bool {
        get { lock.withLock { _leaveReady } }
        set { lock.withLock { _leaveReady = newValue } }
    }
    func leaveReady() throws -> Bool {
        if let readError { throw readError }
        return leaveReadyValue
    }
    private var _leaveDeposited = false
    /// Nodes refuse the deposits (the network is up).
    var depositFails = false
    private var _leaveExpired = false
    /// The queued request expired before any node took it.
    var leaveExpired: Bool {
        get { lock.withLock { _leaveExpired } }
        set { lock.withLock { _leaveExpired = newValue } }
    }
    func leaveState() throws -> LeaveState {
        lock.withLock {
            if !_leaveReady { return .notQueued }
            if _leaveDeposited { return .left }
            return _leaveExpired ? .expired : .waiting
        }
    }
    /// Thrown by `leaveReady` and `adminTransferPending` (lock held elsewhere).
    var readError: Error?
    /// The root key transfer expired without its ack.
    var transferExpired = false
    func finishLink(package: Data) throws {}

    // MARK: Delivery

    /// Answers of `deliveriesOf`, by message id (an unknown id comes back removed).
    var deliveryUpdates: [Int64: DeliveryUpdate] = [:]
    var messageDeliveries: [Int64: MessageDelivery] = [:]
    var deliveryCountsByContact: [String: DeliveryCounts] = [:]
    var deliveryRows: [String: [DeliveryState: [DeliveryRowInfo]]] = [:]
    var pendingInfo = PendingPackets(messages: [], sync: [], packets: 0)
    /// What the next deletion rates (`deleteMessage`, `deleteMessages`, `cancelAllPending`).
    var deleteResult = FakeDevice.nothingDeleted
    /// Thrown by the delivery reads and writes when set.
    var deliveryError: Error?
    private var _deleted: [[Int64]] = []
    private var _retried: [Int64] = []
    private var _retriedAll: [String] = []
    private var _cancelAllCalls = 0
    /// Ids given to each deletion call, in order.
    var deleted: [[Int64]] { lock.withLock { _deleted } }
    var retried: [Int64] { lock.withLock { _retried } }
    var retriedAll: [String] { lock.withLock { _retriedAll } }
    var cancelAllCalls: Int { lock.withLock { _cancelAllCalls } }
    var retryAllCount: UInt32 = 0
    /// Thrown by `retryAll` only, when set (before `deliveryError`).
    var retryAllError: Error?
    /// Thrown by `deliveryPage` only, when set.
    var pageError: Error?
    /// Seconds `deliveryPage` takes (a page in flight while something changes).
    var pageDelay: TimeInterval = 0
    private var _deliveryPageCalls = 0
    /// Calls of `deliveryPage`.
    var deliveryPageCalls: Int { lock.withLock { _deliveryPageCalls } }

    static let nothingDeleted = DeleteOutcome(deleted: 0, cancelled: 0, partlyCancelled: 0, alreadyLeft: 0,
                                              stillReceiving: [], ownCopiesKept: false, devicesLeft: 0, devicesTotal: 0, changes: [])

    func deliveriesOf(ids: [Int64]) throws -> [DeliveryUpdate] {
        if let deliveryError { throw deliveryError }
        return ids.map { deliveryUpdates[$0] ?? DeliveryUpdate(messageId: $0, delivery: nil, removed: true) }
    }
    func messageDelivery(messageId: Int64) throws -> MessageDelivery? {
        if let deliveryError { throw deliveryError }
        return messageDeliveries[messageId]
    }
    func deliveryCounts(contact: String) throws -> DeliveryCounts {
        if let deliveryError { throw deliveryError }
        return deliveryCountsByContact[contact] ?? DeliveryCounts(pending: 0, onNetwork: 0, received: 0, notDelivered: 0)
    }
    func deliveryPage(contact: String, state: DeliveryState, limit: UInt32, offset: UInt32) throws -> [DeliveryRowInfo] {
        if let deliveryError { throw deliveryError }
        if let pageError { throw pageError }
        lock.withLock { _deliveryPageCalls += 1 }
        if pageDelay > 0 { Thread.sleep(forTimeInterval: pageDelay) }
        let all = deliveryRows[contact]?[state] ?? []
        return Array(all.dropFirst(Int(offset)).prefix(Int(limit)))
    }
    func deleteMessage(messageId: Int64) throws -> DeleteOutcome {
        if let deliveryError { throw deliveryError }
        lock.withLock { _deleted.append([messageId]) }
        return deleteResult
    }
    func deleteMessages(ids: [Int64]) throws -> DeleteOutcome {
        if let deliveryError { throw deliveryError }
        lock.withLock { _deleted.append(ids) }
        return deleteResult
    }
    func cancelAllPending() throws -> DeleteOutcome {
        if let deliveryError { throw deliveryError }
        lock.withLock { _cancelAllCalls += 1 }
        return deleteResult
    }
    /// Thrown by `retryMessage` only, when set (before `deliveryError`).
    var retryError: Error?
    func retryMessage(messageId: Int64) throws {
        if let retryError { throw retryError }
        if let deliveryError { throw deliveryError }
        Thread.sleep(forTimeInterval: syncDelay)
        lock.withLock { _retried.append(messageId) }
    }
    func retryAll(contact: String) throws -> UInt32 {
        if let retryAllError { throw retryAllError }
        if let deliveryError { throw deliveryError }
        lock.withLock { _retriedAll.append(contact) }
        return retryAllCount
    }
    /// What `notificationPrefs`, `setInstant` and `setPreview` keep.
    var prefs = NotificationPrefs(instant: true, preview: .nameAndText, lastWake: nil)
    var wakeStatusValue = WakeStatus(configSet: false, nodes: [])
    private var _wakeNotes: [UInt64] = []
    /// Every `noteWake` time, in call order.
    var wakeNotes: [UInt64] { lock.withLock { _wakeNotes } }
    /// Thrown by `notificationPrefs` when set.
    var prefsError: Error?
    func notificationPrefs() throws -> NotificationPrefs {
        if let prefsError { throw prefsError }
        return lock.withLock { prefs }
    }
    /// Thrown by `setInstant` / `setPreview` when set (nothing is stored then).
    var setInstantError: Error?
    var setPreviewError: Error?
    func setInstant(on: Bool) throws {
        if let setInstantError { throw setInstantError }
        lock.withLock { prefs.instant = on }
    }
    func setPreview(preview: PushPreview) throws {
        if let setPreviewError { throw setPreviewError }
        lock.withLock { prefs.preview = preview }
    }
    func noteWake(atSecs: UInt64) throws {
        lock.withLock { _wakeNotes.append(atSecs); prefs.lastWake = atSecs }
    }
    /// Thrown by `wakeStatus` when set.
    var wakeStatusError: Error?
    func wakeStatus() throws -> WakeStatus {
        if let wakeStatusError { throw wakeStatusError }
        return wakeStatusValue
    }
    func pendingPackets() throws -> PendingPackets {
        if let deliveryError { throw deliveryError }
        return pendingInfo
    }
}

/// Runs device calls directly (no background task) in tests.
struct DirectRunner: CallRunner {
    func run<T: Sendable>(_ name: String, _ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await Task.detached { try body() }.value
    }
}

extension Delivery {
    /// A one-device delivery in `state`, for canned messages.
    static func state(_ state: DeliveryState) -> Delivery {
        Delivery(state: state, sealedAt: 1, depositedAt: nil, receivedAt: nil, expiredAt: nil,
                 devices: 1, devicesReceived: state == .received ? 1 : 0,
                 devicesLeft: state == .onNetwork || state == .received ? 1 : 0,
                 devicesPending: state == .pending ? 1 : 0)
    }
}
