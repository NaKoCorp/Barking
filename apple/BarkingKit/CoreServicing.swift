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
    /// `ttlSecs`: an ephemeral message (60 to 604 800 seconds); nil: a plain one.
    func sendText(contact: String, text: String, replyTo: Int64?, ttlSecs: UInt32?) throws
    func setReactions(message: Int64, emojis: [String]) throws
    func addContactBytes(card: Data, alias: String?) throws -> String
    func addContact(card: String, alias: String?) throws -> String
    func contactCardBytes() throws -> Data
    func contactCard(displayName: String) throws -> String
    func setAlias(contact: String, alias: String) throws
    func removeContact(contact: String) throws
    func setDraft(contact: String, text: String) throws
    func draft(contact: String) throws -> String?
    func markVerified(contact: String) throws
    func unmarkVerified(contact: String) throws
    func blockContact(contact: String) throws
    func unblockContact(contact: String) throws
    func blockedContacts() throws -> [Contact]
    func safetyNumber(contact: String) throws -> [String]
    func unreadCounts() throws -> [UnreadCount]
    func chatSummaries() throws -> [ChatSummary]
    func markRead(contact: String, upTo: Int64) throws
    func keyChanges(since: UInt64) throws -> [KeyChange]
    func transparencyLog(limit: UInt32, before: Int64?, securityOnly: Bool) throws -> [LogEntry]
    func contactDevices(contact: String) throws -> [MyDeviceInfo]
    func sync(deadlineMs: UInt64) throws -> SyncSummary
    func quickSync(deadlineMs: UInt64) throws -> SyncSummary
    func nodes() throws -> [NodeInfo]
    func addNode(id: String, addr: String) throws
    func nodeDetail(id: String) throws -> NodeDetail
    func refreshNodeInfo(id: String) throws -> NodeDetail
    func removeNode(id: String) throws
    func blockNode(id: String) throws
    func unblockNode(id: String) throws
    func blockedNodes() throws -> [BlockedNode]
    func addDefaultNodes(entries: [DefaultNode]) throws
    func resetDefaultNodes(entries: [DefaultNode]) throws -> UInt32
    func dismissedDefaultsCount() throws -> UInt32
    func usableNodesIfBlocked(id: String) throws -> UInt32
    func setPush(settings: PushSettings?) throws
    func pendingCount() throws -> UInt32
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
    func deliveriesOf(ids: [Int64]) throws -> [DeliveryUpdate]
    func messageDelivery(messageId: Int64) throws -> MessageDelivery?
    func reactionDelivery(message: Int64) throws -> ReactionDelivery?
    func retryReactions(message: Int64) throws
    func deliveryCounts(contact: String) throws -> DeliveryCounts
    func deliveryPage(contact: String, state: DeliveryState, limit: UInt32, offset: UInt32) throws -> [DeliveryRowInfo]
    func deleteMessage(messageId: Int64) throws -> DeleteOutcome
    func deleteMessages(ids: [Int64]) throws -> DeleteOutcome
    func cancelAllPending() throws -> DeleteOutcome
    func retryMessage(messageId: Int64) throws
    func retryAll(contact: String) throws -> UInt32
    func pendingPackets() throws -> PendingPackets
    func notificationPrefs() throws -> NotificationPrefs
    func setInstant(on: Bool) throws
    func setPreview(preview: PushPreview) throws
    func noteWake(atSecs: UInt64) throws
    func wakeStatus() throws -> WakeStatus
    /// Ephemeral messages of rows `ids` are on screen: seen now.
    func markSeen(ids: [Int64]) throws
    /// When the next ephemeral is due (Unix seconds); nil without any.
    func nextExpiry() throws -> UInt64?
    /// Erases the ephemeral messages due now; their rows.
    func expireEphemeral() throws -> [Int64]
    /// Contact requests (people who added me and sent an invitation).
    func requests() throws -> [ContactRequestInfo]
    func requestSafetyNumber(fingerprint: String) throws -> [String]
    /// The new contact's fingerprint; an alias in use: `InvalidInput("alias taken")`.
    func acceptRequest(fingerprint: String, alias: String?) throws -> String
    func refuseRequest(fingerprint: String) throws
    func blockRequest(fingerprint: String) throws
    func setRequestHidden(fingerprint: String, hidden: Bool) throws
    func markRequestsSeen() throws
    /// Again within 24 hours: `TooSoon(retryAt:)`.
    func invite(contact: String) throws
    func inviteStatus(contact: String) throws -> InviteStatus
    func setInviteNotifications(on: Bool) throws
    func deviceChanges(since: UInt64) throws -> [DeviceChange]
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
    /// A new message or a deletion: the conversation reloads whole.
    case messages(contact: String)
    /// Only the delivery state of these messages changed (`Message.id`),
    /// bursts coalesced: a screen refreshes those rows
    /// (`CoreService.deliveriesOf`).
    case delivery(contact: String, ids: [Int64])
    case network
    /// A sync started (any: the launch, the timer, a pull): the Network
    /// tab shows it running. Its end publishes `.network`.
    case syncStarted
    case devices
    case identity
    /// Ephemeral rows erased (`Message.id`): the expiry names no contact,
    /// so each screen checks whether it shows one of them.
    case expired(ids: [Int64])
}

public enum SyncReason: Sendable {
    /// `background`: the last sync as the app leaves the screen.
    case launch, foreground, afterSend, timer, pull, background
}

/// A sync's outcome, as the Network screen shows it.
public struct SyncOutcome: Sendable, Equatable {
    public let networkUp: Bool
    public let received: Int
    public let sent: Int
    /// CLI-style lines (`$ barking sync`, …), in English like the CLI.
    public let lines: [String]
    /// Items fetched (messages, receipts…): a receipt changes a message's
    /// status without adding one to `received`.
    public var items: Int = 0
    /// Sent messages whose delivery changed during the sync.
    public var deliveryChanges: [DeliveryChange] = []
    /// Contacts a new message came in from.
    public var newMessageContacts: [String] = []
    /// Sent messages that became not delivered during the sync.
    public var failed: [DeliveryChange] = []
    /// Contacts a copy of a message I sent from another device arrived for.
    public var syncedContacts: [String] = []
    /// The new messages themselves, for the notifications of a background refresh.
    public var newMessages: [NewMessage] = []
    /// Reactions a contact added (never a removal), for the notifications.
    public var newReactions: [NewReaction] = []
    /// Contacts whose conversation a reaction changed (a contact's, or one of
    /// mine from another device, a removal included): it reloads.
    public var reactionContacts: [String] = []
    /// Ephemeral rows the sync erased (it expires first).
    public var expired: [Int64] = []
    /// Contact requests to notify (already filtered by the invitations setting).
    public var newRequests: [NewRequest] = []
    /// Requesters whose request moved during the sync, notified or not.
    public var requestContacts: [String] = []

    /// Something came in or went out: what a background wake reports.
    public var changed: Bool { items > 0 || received > 0 || sent > 0 }

    static func from(_ s: SyncSummary) -> SyncOutcome {
        let received = s.newMessages.count
        let sent = Int(s.sent)
        let result = s.networkUp
            ? "internet: \(received) messages received, \(sent) sent"
            : "internet: network unreachable, nothing is lost"
        return SyncOutcome(networkUp: s.networkUp, received: received, sent: sent,
                           lines: ["$ barking sync", result], items: Int(s.itemsReceived),
                           deliveryChanges: s.deliveryChanges,
                           newMessageContacts: s.newMessages.map(\.contact), failed: s.failed,
                           syncedContacts: s.syncedContacts, newMessages: s.newMessages,
                           newReactions: s.newReactions, reactionContacts: s.reactionContacts,
                           expired: s.expired, newRequests: s.newRequests,
                           requestContacts: s.requestContacts)
    }
}

/// Foreground sync cadence (spec iOS messaging §4.2).
public struct SyncScheduler: Sendable {
    public var conversationOpen: Bool
    public init(conversationOpen: Bool) { self.conversationOpen = conversationOpen }
    public func nextDelay() -> Duration { conversationOpen ? .seconds(15) : .seconds(60) }
}
