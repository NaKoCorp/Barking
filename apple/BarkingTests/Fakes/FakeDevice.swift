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
    var verified: Set<String> = []
    var reads: [(String, Int64)] = []
    var unread: [UnreadCount] = []
    var keyChangeList: [KeyChange] = []
    var devicesList: [MyDeviceInfo] = []
    var removedInfo: RemovedInfo?
    private var _transferredTo: [String] = []
    var transferredTo: [String] { lock.withLock { _transferredTo } }
    var pending = false
    var sendError: Error?
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
    func messagesWith(contact: String) throws -> [Message] { messageList[contact] ?? [] }
    func sendText(contact: String, text: String) throws {
        if let sendError { throw sendError }
        Thread.sleep(forTimeInterval: syncDelay)
        lock.withLock { _sent.append((contact, text)) }
    }
    func addContactBytes(card: Data, alias: String?) throws -> String { "fp-new" }
    func addContact(card: String, alias: String?) throws -> String { "fp-new" }
    func contactCardBytes() throws -> Data { Data([1, 2, 3]) }
    func contactCard(displayName: String) throws -> String { "barking1:abc" }
    func setAlias(contact: String, alias: String) throws {}
    func removeContact(contact: String) throws {}
    func markVerified(contact: String) throws { verified.insert(contact) }
    func unmarkVerified(contact: String) throws { verified.remove(contact) }
    func safetyNumber(contact: String) throws -> [String] { Array(repeating: "12345", count: 12) }
    func unreadCounts() throws -> [UnreadCount] { unread }
    func chatSummaries() throws -> [ChatSummary] {
        lock.withLock { _summaryCalls += 1 }
        return contactList.map { c in
            ChatSummary(contact: c, last: messageList[c.fingerprint]?.last,
                        unread: unread.first { $0.contact == c.fingerprint }?.count ?? 0)
        }
    }
    func markRead(contact: String, upTo: Int64) throws { reads.append((contact, upTo)) }
    func keyChanges(since: UInt64) throws -> [KeyChange] { keyChangeList }
    func sync(deadlineMs: UInt64) throws -> SyncSummary {
        lock.withLock { _syncCalls += 1 }
        Thread.sleep(forTimeInterval: syncDelay)
        return summary
    }
    func nodes() throws -> [NodeInfo] { [] }
    func addNode(id: String, addr: String) throws {}
    func outboxCount() throws -> UInt32 { 0 }
    func myDevices() throws -> [MyDeviceInfo] { devicesList }
    func linkOffer() throws -> Data { Data([0xAA]) }
    func linkDevice(request: Data, withHistory: Bool) throws -> Data {
        lock.withLock { _linkCalls += 1 }
        Thread.sleep(forTimeInterval: syncDelay)
        return Data([0xBB])
    }
    func isPendingLink() throws -> Bool { pending }
    func transferAdmin(deviceId: String) throws { lock.withLock { _transferredTo.append(deviceId) } }
    func adminTransferPending() throws -> String? { lock.withLock { _transferredTo.last } }
    func removed() throws -> RemovedInfo? { removedInfo }
    func finishLink(package: Data) throws {}
}

/// Runs device calls directly (no background task) in tests.
struct DirectRunner: CallRunner {
    func run<T: Sendable>(_ name: String, _ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await Task.detached { try body() }.value
    }
}
