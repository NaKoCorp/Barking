import Foundation

/// The FFI `Device` calls the app uses: the real `Device` conforms, tests
/// use a fake.
public protocol DeviceHandle: AnyObject, Sendable {
    func fingerprint() throws -> String
    func displayName() throws -> String
    func setDisplayName(name: String) throws
    func contacts() throws -> [Contact]
    func messagesWith(contact: String) throws -> [Message]
    func messageRoute(messageId: Int64) throws -> [RouteStepInfo]
    func sendText(contact: String, text: String) throws
    func addContactBytes(card: Data, alias: String?) throws -> String
    func addContact(card: String, alias: String?) throws -> String
    func contactCardBytes() throws -> Data
    func contactCard(displayName: String) throws -> String
    func setAlias(contact: String, alias: String) throws
    func removeContact(contact: String) throws
    func markVerified(contact: String) throws
    func unmarkVerified(contact: String) throws
    func safetyNumber(contact: String) throws -> [String]
    func unreadCounts() throws -> [UnreadCount]
    func chatSummaries() throws -> [ChatSummary]
    func markRead(contact: String, upTo: Int64) throws
    func keyChanges(since: UInt64) throws -> [KeyChange]
    func transparencyLog(limit: UInt32, offset: UInt32, securityOnly: Bool) throws -> [LogEntry]
    func contactDevices(contact: String) throws -> [MyDeviceInfo]
    func sync(deadlineMs: UInt64) throws -> SyncSummary
    func nodes() throws -> [NodeInfo]
    func addNode(id: String, addr: String) throws
    func outboxCount() throws -> UInt32
    func myDevices() throws -> [MyDeviceInfo]
    func linkOffer() throws -> Data
    func linkDevice(request: Data, withHistory: Bool) throws -> Data
    func isPendingLink() throws -> Bool
    func finishLink(package: Data) throws
    func transferAdmin(deviceId: String) throws
    func adminTransferPending() throws -> String?
    func removed() throws -> RemovedInfo?
    func removeDevice(deviceId: String) throws
    func leave() throws
    func transferAndLeave(deviceId: String) throws
    func leaveReady() throws -> Bool
    func leaveState() throws -> LeaveState
}

extension Device: DeviceHandle {}

/// Runs one device call. The app's runner wraps it in a background task
/// (`DeviceCall`, app only: `UIApplication` is off limits here, in the
/// extension's framework); tests run it directly.
public protocol CallRunner: Sendable {
    func run<T: Sendable>(_ name: String, _ body: @escaping @Sendable () throws -> T) async throws -> T
}

/// What changed, for the screen models to reload.
public enum CoreChange: Sendable, Equatable {
    case contacts
    case messages(contact: String)
    case network
    case devices
    case identity
}

public enum SyncReason: Sendable {
    case launch, foreground, afterSend, timer, pull
}

/// A sync's outcome, as the Network screen shows it.
public struct SyncOutcome: Sendable, Equatable {
    public let networkUp: Bool
    public let received: Int
    public let sent: Int
    /// CLI-style lines (`$ barking sync`, …), in English like the CLI.
    public let lines: [String]

    static func from(_ s: SyncSummary) -> SyncOutcome {
        let received = s.newMessages.count
        let sent = Int(s.sent)
        let result = s.networkUp
            ? "internet: \(received) messages received, \(sent) sent"
            : "internet: network unreachable, nothing is lost"
        return SyncOutcome(networkUp: s.networkUp, received: received, sent: sent,
                           lines: ["$ barking sync", result])
    }
}

/// Foreground sync cadence (spec iOS messaging §4.2).
public struct SyncScheduler: Sendable {
    public var conversationOpen: Bool
    public init(conversationOpen: Bool) { self.conversationOpen = conversationOpen }
    public func nextDelay() -> Duration { conversationOpen ? .seconds(15) : .seconds(60) }
}
