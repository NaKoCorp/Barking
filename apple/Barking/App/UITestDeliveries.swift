#if BARKING_DEV
import BarkingKit
import Foundation

/// The core seen by the UI tests (spec Lot M §6.8): every call goes to the
/// real device, except what a second party would have changed, which UI
/// tests have no network or second device to produce.
///
/// - `-BarkingUITestSeed deliveries`: the four messages the seed sent to Sam
///   read as Pending, On the network, Received on 1 of 2 devices and Not
///   delivered, in every read (`messagesWith`, `deliveriesOf`,
///   `messageDelivery`, `deliveryCounts`, `deliveryPage`, `pendingPackets`,
///   `pendingCount`). Deletions and retries go to the real core; a retried
///   message drops its forced state and shows the real one, and "Cancel
///   all" deletes the messages "Pending" shows (the forced ones really wait
///   on this iPhone too). Syncs report the network unreachable at once.
/// - `-BarkingUITestFakeReceived`: one received message from Sam (its route
///   is given by `-BarkingUITestFakeRoute`).
///
/// Never compiled into Release.
final class UITestDeliveries: DeviceHandle, @unchecked Sendable {
    /// What the seed recorded: the contact, the four messages (Not
    /// delivered, Received, On the network, Pending, oldest first) and when.
    struct Seed: Codable, Equatable {
        let contact: String
        let ids: [Int64]
        let base: UInt64

        static let key = "barking.uitest.deliveries"

        func save(_ defaults: UserDefaults = .standard) {
            defaults.set(try? JSONEncoder().encode(self), forKey: Self.key)
        }

        static func load(_ defaults: UserDefaults = .standard) -> Seed? {
            defaults.data(forKey: key).flatMap { try? JSONDecoder().decode(Seed.self, from: $0) }
        }
    }

    /// The four states, in the order the seed sends them.
    static let states: [DeliveryState] = [.notDelivered, .received, .onNetwork, .pending]

    /// The four messages, in the phone's language (French screenshots read French).
    static func bodies(french: Bool = Locale.preferredLanguages.first?.hasPrefix("fr") == true) -> [String] {
        french
            ? ["Tu as récupéré les clés\u{202F}?", "J’arrive, dix minutes.",
               "On se voit au marché à 18\u{00A0}h.", "Prends le sac bleu, s’il te plaît."]
            : ["Did you get the keys?", "On my way, ten minutes.",
               "Meet at the market at six.", "Bring the blue bag, please."]
    }

    /// How long before the seed each message shows as sent: the Not
    /// delivered one yesterday (it expired 24 h later), the others today.
    private static let ages: [UInt64] = [26 * 3600, 40 * 60, 12 * 60, 2 * 60]
    private static let lifetime: UInt64 = 86_400
    static let relay = "K7QX2M4A"
    /// The two devices on Sam's card, in this world.
    private static let devices = [("5a3f9c21d4e8b706", "iPhone"), ("c90e14b7a2f65d38", "iPad")]

    private let device: any DeviceHandle
    private let seed: Seed?
    private let fakeReceived: Bool
    private let lock = NSLock()
    /// Forced state by message; a retry removes its entry.
    private var forced: [Int64: DeliveryState]
    /// Shown time by message (kept after a retry: the message keeps its date).
    private let shownAt: [Int64: UInt64]

    init(device: any DeviceHandle, seed: Seed?, fakeReceived: Bool) {
        self.device = device
        self.seed = seed
        self.fakeReceived = fakeReceived
        var forced: [Int64: DeliveryState] = [:]
        var shownAt: [Int64: UInt64] = [:]
        if let seed {
            for (i, id) in seed.ids.prefix(Self.states.count).enumerated() {
                forced[id] = Self.states[i]
                shownAt[id] = seed.base - Self.ages[i]
            }
        }
        self.forced = forced
        self.shownAt = shownAt
    }

    /// The device the app should use: decorated when a UI test asks for it.
    static func wrap(_ device: any DeviceHandle,
                     arguments: [String] = ProcessInfo.processInfo.arguments) -> any DeviceHandle {
        let seeded = arguments.firstIndex(of: "-BarkingUITestSeed").map {
            $0 + 1 < arguments.count && arguments[$0 + 1] == "deliveries"
        } ?? false
        let fakeReceived = arguments.contains("-BarkingUITestFakeReceived")
        guard seeded || fakeReceived else { return device }
        return UITestDeliveries(device: device, seed: seeded ? Seed.load() : nil, fakeReceived: fakeReceived)
    }

    // MARK: The forced states

    private func state(of id: Int64) -> DeliveryState? {
        lock.withLock { forced[id] }
    }

    private func at(_ id: Int64) -> UInt64? { shownAt[id] }

    /// The aggregate delivery shown for a forced message (§5.10 fields).
    private func delivery(_ state: DeliveryState, at t: UInt64) -> Delivery {
        switch state {
        case .pending:
            Delivery(state: .pending, sealedAt: t, depositedAt: nil, receivedAt: nil, expiredAt: nil,
                     devices: 2, devicesReceived: 0, devicesLeft: 0, devicesPending: 2)
        case .onNetwork:
            Delivery(state: .onNetwork, sealedAt: t, depositedAt: t + 41, receivedAt: nil, expiredAt: nil,
                     devices: 2, devicesReceived: 0, devicesLeft: 2, devicesPending: 0)
        case .received:
            Delivery(state: .received, sealedAt: t, depositedAt: t + 34, receivedAt: t + 185, expiredAt: nil,
                     devices: 2, devicesReceived: 1, devicesLeft: 2, devicesPending: 0)
        case .notDelivered:
            Delivery(state: .notDelivered, sealedAt: t, depositedAt: nil, receivedAt: nil,
                     expiredAt: t + Self.lifetime, devices: 2, devicesReceived: 0, devicesLeft: 0, devicesPending: 0)
        }
    }

    /// Per device: Received has one device received and one on the network.
    private func deviceDeliveries(_ state: DeliveryState, at t: UInt64) -> [DeviceDelivery] {
        Self.devices.enumerated().map { i, d in
            switch state {
            case .pending:
                DeviceDelivery(device: d.0, name: d.1, state: .pending, sealedAt: t, depositedAt: nil, node: nil,
                               receivedAt: nil, expiredAt: nil)
            case .onNetwork:
                DeviceDelivery(device: d.0, name: d.1, state: .onNetwork, sealedAt: t, depositedAt: t + 41,
                               node: Self.relay, receivedAt: nil, expiredAt: nil)
            case .received:
                DeviceDelivery(device: d.0, name: d.1, state: i == 0 ? .received : .onNetwork, sealedAt: t,
                               depositedAt: t + 34, node: Self.relay, receivedAt: i == 0 ? t + 185 : nil, expiredAt: nil)
            case .notDelivered:
                DeviceDelivery(device: d.0, name: d.1, state: .notDelivered, sealedAt: t, depositedAt: nil, node: nil,
                               receivedAt: nil, expiredAt: t + Self.lifetime)
            }
        }
    }

    private func relays(_ state: DeliveryState, at t: UInt64) -> [RelayHop] {
        switch state {
        case .onNetwork: [RelayHop(node: Self.relay, at: t + 41, size: 1024)]
        case .received: [RelayHop(node: Self.relay, at: t + 34, size: 1024)]
        case .pending, .notDelivered: []
        }
    }

    private func decorate(_ d: Delivery?, id: Int64) -> Delivery? {
        guard let d, let state = state(of: id), let t = at(id) else { return d }
        return delivery(state, at: t)
    }

    /// Every sent message to `contact` as "Deliveries" shows it, newest first.
    private func rows(contact: String) throws -> [DeliveryRowInfo] {
        var all: [DeliveryRowInfo] = []
        for s in [DeliveryState.notDelivered, .pending, .onNetwork, .received] {
            all += try device.deliveryPage(contact: contact, state: s, limit: 10_000, offset: 0)
        }
        return all.map { row in
            var row = row
            if let t = at(row.messageId) { row.at = t }
            row.delivery = decorate(row.delivery, id: row.messageId) ?? row.delivery
            return row
        }
        .sorted { ($0.at, $0.messageId) > ($1.at, $1.messageId) }
    }

    // MARK: Decorated reads

    func messagesWith(contact: String) throws -> [Message] {
        var messages = try device.messagesWith(contact: contact).map { m in
            var m = m
            if let t = at(m.id) { m.at = t }
            m.delivery = decorate(m.delivery, id: m.id)
            return m
        }
        if fakeReceived {
            // UI tests have no second device to write to this one: one
            // received message, its route given by `-BarkingUITestFakeRoute`.
            let at = UInt64(Date().timeIntervalSince1970)
            messages.append(Message(id: 900_001, outgoing: false, body: "hi from Sam", at: at,
                                    delivery: nil, route: "internet:1"))
        }
        return messages
    }

    func deliveriesOf(ids: [Int64]) throws -> [DeliveryUpdate] {
        try device.deliveriesOf(ids: ids).map { u in
            var u = u
            if !u.removed { u.delivery = decorate(u.delivery, id: u.messageId) }
            return u
        }
    }

    func messageDelivery(messageId: Int64) throws -> MessageDelivery? {
        guard let real = try device.messageDelivery(messageId: messageId) else { return nil }
        guard let state = state(of: messageId), let t = at(messageId) else { return real }
        return MessageDelivery(messageId: messageId, delivery: delivery(state, at: t),
                               devices: deviceDeliveries(state, at: t), relays: relays(state, at: t),
                               ownCopies: real.ownCopies)
    }

    func deliveryCounts(contact: String) throws -> DeliveryCounts {
        guard seed?.contact == contact else { return try device.deliveryCounts(contact: contact) }
        let rows = try rows(contact: contact)
        func n(_ s: DeliveryState) -> UInt32 { UInt32(rows.filter { $0.delivery.state == s }.count) }
        return DeliveryCounts(pending: n(.pending), onNetwork: n(.onNetwork), received: n(.received),
                              notDelivered: n(.notDelivered))
    }

    func deliveryPage(contact: String, state: DeliveryState, limit: UInt32, offset: UInt32) throws -> [DeliveryRowInfo] {
        guard seed?.contact == contact else {
            return try device.deliveryPage(contact: contact, state: state, limit: limit, offset: offset)
        }
        return Array(try rows(contact: contact).filter { $0.delivery.state == state }
            .dropFirst(Int(offset)).prefix(Int(limit)))
    }

    /// Only the forced Pending message stays among "Your messages" (with
    /// its two devices), and the sync section has one card update for Sam,
    /// so that "Pending" has both sections. The total follows.
    func pendingPackets() throws -> PendingPackets {
        var p = try device.pendingPackets()
        guard seed != nil else { return p }
        var packets = Int(p.packets)
        p.messages = p.messages.compactMap { m in
            guard let state = state(of: m.messageId), let t = at(m.messageId) else { return m }
            packets -= Int(m.packets)
            guard state == .pending else { return nil }
            var m = m
            m.sealedAt = t
            m.expiresAt = t + Self.lifetime
            m.packets = 2
            m.devices = 2
            m.devicesLeft = 0
            m.devicesTried = 0
            packets += 2
            return m
        }
        .sorted { ($0.expiresAt, $0.messageId) < ($1.expiresAt, $1.messageId) }
        if !p.sync.contains(where: { $0.kind == .cardUpdate }) {
            p.sync.append(PendingSync(kind: .cardUpdate, packets: 1, names: ["Sam"]))
            packets += 1
        }
        p.packets = UInt32(max(packets, 0))
        return p
    }

    func pendingCount() throws -> UInt32 {
        seed == nil ? try device.pendingCount() : try pendingPackets().packets
    }

    // MARK: Sync: offline

    /// The `deliveries` world has no network: a real sync would hold the
    /// core for its whole deadline (every read waits behind it) and could
    /// deposit the seeded messages under their forced states.
    private static let offline = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: false, error: nil)

    // MARK: Retries: the real core, the forced state dropped

    func retryMessage(messageId: Int64) throws {
        let wasForced = lock.withLock { () -> Bool in
            guard forced[messageId] == .notDelivered else { return false }
            forced[messageId] = nil
            return true
        }
        do {
            try device.retryMessage(messageId: messageId)
        } catch BarkingError.NothingToRetry where wasForced {
            // Really still pending on this iPhone: the retry is what it shows now.
        }
    }

    func retryAll(contact: String) throws -> UInt32 {
        let dropped = lock.withLock { () -> UInt32 in
            guard seed?.contact == contact else { return 0 }
            let ids = forced.filter { $0.value == .notDelivered }.map(\.key)
            for id in ids { forced[id] = nil }
            return UInt32(ids.count)
        }
        do {
            return try device.retryAll(contact: contact) + dropped
        } catch BarkingError.NothingToRetry where dropped > 0 {
            return dropped
        }
    }

    // MARK: Everything else: the real device

    func fingerprint() throws -> String { try device.fingerprint() }
    func displayName() throws -> String { try device.displayName() }
    func setDisplayName(name: String) throws { try device.setDisplayName(name: name) }
    func contacts() throws -> [Contact] { try device.contacts() }
    func messageRoute(messageId: Int64) throws -> [RouteStepInfo] { try device.messageRoute(messageId: messageId) }
    func sendText(contact: String, text: String) throws { try device.sendText(contact: contact, text: text) }
    func addContactBytes(card: Data, alias: String?) throws -> String { try device.addContactBytes(card: card, alias: alias) }
    func addContact(card: String, alias: String?) throws -> String { try device.addContact(card: card, alias: alias) }
    func contactCardBytes() throws -> Data { try device.contactCardBytes() }
    func contactCard(displayName: String) throws -> String { try device.contactCard(displayName: displayName) }
    func setAlias(contact: String, alias: String) throws { try device.setAlias(contact: contact, alias: alias) }
    func removeContact(contact: String) throws { try device.removeContact(contact: contact) }
    func markVerified(contact: String) throws { try device.markVerified(contact: contact) }
    func unmarkVerified(contact: String) throws { try device.unmarkVerified(contact: contact) }
    func safetyNumber(contact: String) throws -> [String] { try device.safetyNumber(contact: contact) }
    func unreadCounts() throws -> [UnreadCount] { try device.unreadCounts() }
    func chatSummaries() throws -> [ChatSummary] { try device.chatSummaries() }
    func markRead(contact: String, upTo: Int64) throws { try device.markRead(contact: contact, upTo: upTo) }
    func keyChanges(since: UInt64) throws -> [KeyChange] { try device.keyChanges(since: since) }
    func transparencyLog(limit: UInt32, before: Int64?, securityOnly: Bool) throws -> [LogEntry] {
        try device.transparencyLog(limit: limit, before: before, securityOnly: securityOnly)
    }
    func contactDevices(contact: String) throws -> [MyDeviceInfo] { try device.contactDevices(contact: contact) }
    func sync(deadlineMs: UInt64) throws -> SyncSummary {
        seed == nil ? try device.sync(deadlineMs: deadlineMs) : Self.offline
    }
    func quickSync(deadlineMs: UInt64) throws -> SyncSummary {
        seed == nil ? try device.quickSync(deadlineMs: deadlineMs) : Self.offline
    }
    func nodes() throws -> [NodeInfo] { try device.nodes() }
    func addNode(id: String, addr: String) throws { try device.addNode(id: id, addr: addr) }
    func setPush(settings: PushSettings?) throws { try device.setPush(settings: settings) }
    func notificationPrefs() throws -> NotificationPrefs { try device.notificationPrefs() }
    func setInstant(on: Bool) throws { try device.setInstant(on: on) }
    func setPreview(preview: PushPreview) throws { try device.setPreview(preview: preview) }
    func noteWake(atSecs: UInt64) throws { try device.noteWake(atSecs: atSecs) }
    func wakeStatus() throws -> WakeStatus { try device.wakeStatus() }
    func myDevices() throws -> [MyDeviceInfo] { try device.myDevices() }
    func linkOffer() throws -> Data { try device.linkOffer() }
    func linkDevice(request: Data, withHistory: Bool) throws -> Data {
        try device.linkDevice(request: request, withHistory: withHistory)
    }
    func isPendingLink() throws -> Bool { try device.isPendingLink() }
    func finishLink(package: Data) throws { try device.finishLink(package: package) }
    func transferAdmin(deviceId: String) throws { try device.transferAdmin(deviceId: deviceId) }
    func adminTransferPending() throws -> String? { try device.adminTransferPending() }
    func removed() throws -> RemovedInfo? { try device.removed() }
    func removeDevice(deviceId: String) throws { try device.removeDevice(deviceId: deviceId) }
    func leave() throws { try device.leave() }
    func transferAndLeave(deviceId: String) throws { try device.transferAndLeave(deviceId: deviceId) }
    func leaveReady() throws -> Bool { try device.leaveReady() }
    func leaveState() throws -> LeaveState { try device.leaveState() }
    func deleteMessage(messageId: Int64) throws -> DeleteOutcome { try device.deleteMessage(messageId: messageId) }
    func deleteMessages(ids: [Int64]) throws -> DeleteOutcome { try device.deleteMessages(ids: ids) }
    /// The messages "Pending" shows, not the forced ones that really wait too.
    func cancelAllPending() throws -> DeleteOutcome {
        guard seed != nil else { return try device.cancelAllPending() }
        return try device.deleteMessages(ids: try pendingPackets().messages.map(\.messageId))
    }
}
#endif
