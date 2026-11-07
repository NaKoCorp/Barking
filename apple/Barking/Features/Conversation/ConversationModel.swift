import BarkingKit
import Foundation
import Observation
import SwiftUI

/// One conversation (screen 4, spec §5.5). The rows are loaded whole on
/// opening and on `.messages`; a state change patches only the rows it
/// names (spec Lot M §6.3).
@MainActor @Observable
final class ConversationModel {
    struct Item: Identifiable, Equatable {
        let id: Int64
        let outgoing: Bool
        let text: String
        let at: Date
        /// Delivery of a sent message; nil for a received message, or one
        /// sent from another of my devices.
        var delivery: Delivery?

        /// The state under the bubble; nil shows the time only.
        var state: DeliveryState? { outgoing ? delivery?.state : nil }
    }

    /// What the banner above the messages says.
    enum Notice: Equatable {
        /// After a deletion, when the core did not do what the confirmation said (§6.7).
        case deleted(DeleteBanner.Message)
        /// The deletion wrote nothing (§9).
        case deleteFailed
        /// A retry found no device of the contact to seal for (§9).
        case noReachableDevice(name: String)

        /// What the banner says, spoken when it appears.
        func text(bundle: Bundle = .main, locale: Locale = .current) -> String {
            switch self {
            case .deleted(let message): message.string(bundle: bundle, locale: locale)
            case .deleteFailed:
                String(localized: "Deletion failed. Nothing has changed.", bundle: bundle, locale: locale)
            case .noReachableDevice(let name):
                String(localized: "\(name) has no reachable device left. The message can’t be sent again.",
                       bundle: bundle, locale: locale)
            }
        }
    }

    static let maxBytes = 4000
    static let counterFrom = 3500

    let contact: String
    private let core: CoreService
    private(set) var items: [Item] = []
    private(set) var name = ""
    private(set) var verified = false
    /// What the header says (U-20).
    var trust: Trust { Trust(verified: verified) }
    private(set) var keyChanged = false
    private var sending = false
    /// Rows whose retry is running: a second tap on one does nothing.
    private var retrying: Set<Int64> = []
    private var visible = false
    private(set) var sendError: String?
    /// Said to VoiceOver when it appears: the banner itself is not focused.
    private(set) var notice: Notice? {
        didSet { if let notice, notice != oldValue { announce(notice.text()) } }
    }
    /// Rows whose deletion is running (§9: dimmed, a spinner for the symbol).
    private(set) var deleting: Set<Int64> = []
    /// This device was removed from the account: it can no longer send.
    private(set) var removed = false
    var draft = ""

    /// Bubbles on screen: only their changes are announced (§8).
    private var onScreen: Set<Int64> = []
    private var announcements = DeliveryAnnouncements()
    private var announcementFlush: Task<Void, Never>?
    /// Posts a VoiceOver announcement (tests record it).
    var announce: (String) -> Void = { AccessibilityNotification.Announcement($0).post() }
    var now: () -> Date = Date.init

    init(contact: String, core: CoreService) {
        self.contact = contact
        self.core = core
    }

    var byteCount: Int { draft.utf8.count }
    var lastMessageId: Int64? { items.last?.id }
    /// The header button opens the last sent message.
    var lastSentId: Int64? { items.last(where: \.outgoing)?.id }
    var showsCounter: Bool { byteCount >= Self.counterFrom }
    var canSend: Bool {
        !sending && !removed && byteCount <= Self.maxBytes
            && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func onAppear() async {
        visible = true
        removed = ((try? await core.removed()) ?? nil) != nil
        await reload()
        let changes = (try? await core.keyChanges(since: 0)) ?? []
        keyChanged = !verified && changes.contains { $0.contact == contact }
    }

    func onDisappear() {
        visible = false
        onScreen = []
    }

    /// What a change of the core means here: `.messages` of this contact
    /// reloads whole, `.delivery` patches its rows, `.contacts` refreshes
    /// the header. Nothing else touches the messages.
    func handle(_ change: CoreChange) async {
        switch change {
        case .messages(let c) where c == contact: await reload()
        case .delivery(let c, let ids) where c == contact: await refresh(ids)
        case .contacts: await refreshContact()
        default: break
        }
    }

    private func refreshContact() async {
        if let c = try? await core.contacts().first(where: { $0.fingerprint == contact }) {
            name = c.alias ?? c.displayName
            verified = c.verified
        }
    }

    func reload() async {
        await refreshContact()
        let messages = (try? await core.messages(with: contact)) ?? []
        // A failed message with a later sent copy was retried the old way
        // (before Lot M, a new row): hide it, even after reopening.
        let resent = messages.filter { $0.failed && $0.outgoing }.filter { f in
            messages.contains { $0.outgoing && !$0.failed && $0.id > f.id && $0.body == f.body }
        }.map(\.id)
        items = messages.filter { !resent.contains($0.id) }.map {
            Item(id: $0.id, outgoing: $0.outgoing, text: $0.body,
                 at: Date(timeIntervalSince1970: TimeInterval($0.at)), delivery: $0.delivery)
        }
        // What arrives while the conversation is on screen is read.
        if visible, let last = items.last(where: { !$0.outgoing }) {
            try? await core.markRead(contact, upTo: last.id)
        }
    }

    /// Fresh delivery of the rows `ids` shown here, patched in place.
    func refresh(_ ids: [Int64]) async {
        let shown = ids.filter { id in items.contains { $0.id == id } }
        guard !shown.isEmpty, let updates = try? await core.deliveriesOf(shown) else { return }
        apply(updates)
    }

    /// Replaces the delivery of the rows named (identity by message id);
    /// a removed one leaves. Announces a row on screen reaching Received
    /// or Not delivered.
    func apply(_ updates: [DeliveryUpdate]) {
        var received = 0, notDelivered = 0
        for u in updates {
            guard let i = items.firstIndex(where: { $0.id == u.messageId }) else { continue }
            if u.removed {
                items.remove(at: i)
                continue
            }
            let before = items[i].state
            items[i].delivery = u.delivery
            let after = items[i].state
            guard visible, onScreen.contains(u.messageId), after != before else { continue }
            if after == .received { received += 1 }
            if after == .notDelivered { notDelivered += 1 }
        }
        guard received + notDelivered > 0 else { return }
        announcements.add(received: received, notDelivered: notDelivered)
        flushAnnouncements()
    }

    func bubbleAppeared(_ id: Int64) { onScreen.insert(id) }
    func bubbleDisappeared(_ id: Int64) { onScreen.remove(id) }

    /// Says what waits, if the last announcement is 3 s old; otherwise
    /// comes back when it is.
    func flushAnnouncements() {
        if let text = announcements.take(now: now(), name: name) { announce(text) }
        guard let due = announcements.due, announcementFlush == nil else { return }
        let wait = max(0, due.timeIntervalSince(now()))
        announcementFlush = Task { [weak self] in
            try? await Task.sleep(for: .seconds(wait))
            guard let self else { return }
            self.announcementFlush = nil
            self.flushAnnouncements()
        }
    }

    /// Sends the draft; a second call while one runs does nothing.
    func send() async {
        guard canSend else { return }
        sending = true
        defer { sending = false }
        let text = draft
        draft = ""
        sendError = nil
        notice = nil
        do {
            try await core.send(text, to: contact)
        } catch {
            draft = text
            sendError = "Not sent. Try again in a moment."
        }
        await reload()
    }

    /// Sends a not delivered message again: same row, back to pending,
    /// patched here without a reload.
    func retry(_ id: Int64) async {
        guard !retrying.contains(id), items.contains(where: { $0.id == id }) else { return }
        retrying.insert(id)
        defer { retrying.remove(id) }
        notice = nil
        do {
            try await core.retryMessage(id, contact: contact)
        } catch BarkingError.NoSession {
            // Every device of the contact left their card.
            notice = .noReachableDevice(name: name)
        } catch {
            // NothingToRetry: it left or was received meanwhile; the row
            // below shows where it is.
        }
        await refresh([id])
    }

    /// Deletes one message. The bubble goes at once; the banner says what
    /// really happened, against `shown` (the delivery the confirmation
    /// showed; the row's own by default).
    @discardableResult
    func delete(_ id: Int64, shown: Delivery? = nil) async -> DeleteOutcome? {
        guard let item = items.first(where: { $0.id == id }), !deleting.contains(id) else { return nil }
        let delivery = shown ?? item.delivery
        deleting.insert(id)
        defer { deleting.remove(id) }
        notice = nil
        do {
            let outcome = try await core.deleteMessage(id)
            items.removeAll { $0.id == id }
            if item.outgoing, let delivery {
                // The device counts come from the deletion's own transaction.
                let devices = (left: Int(outcome.devicesLeft), total: Int(outcome.devicesTotal))
                notice = DeleteBanner.message(shown: delivery.state, outcome: outcome, contactName: name,
                                              devices: devices).map(Notice.deleted)
            }
            return outcome
        } catch {
            notice = .deleteFailed
            return nil
        }
    }

    /// Whether deleting `item` keeps a copy for my other devices: the
    /// confirmation then says so on its own line (§5.1, §7.4).
    func keepsOwnCopies(_ item: Item) async -> Bool {
        guard item.outgoing else {
            // A received message: my linked devices got their own packet.
            return ((try? await core.myDevices()) ?? []).contains { !$0.thisDevice }
        }
        // Sent from another device: its confirmation already says it.
        guard item.delivery != nil, let sheet = try? await core.messageDelivery(item.id) else { return false }
        return DeleteConfirmation.keepsOwnCopies(delivery: sheet.delivery, ownCopies: sheet.ownCopies)
    }

    /// After a deletion made in the message sheet: its banner, or none (§6.7).
    func showDeleted(_ message: DeleteBanner.Message?) {
        notice = message.map(Notice.deleted)
    }

    /// The rows showing their time and state line (§6.3): two sent messages
    /// in a row, in the same minute and the same state, show it under the
    /// last only. Not at accessibility sizes, and never for Not delivered
    /// (each keeps its Retry). VoiceOver reads every bubble's state anyway.
    static func metaShown(_ items: [Item], accessibilitySize: Bool) -> Set<Int64> {
        var shown = Set(items.map(\.id))
        guard !accessibilitySize else { return shown }
        let minute = { (d: Date) in Int((d.timeIntervalSince1970 / 60).rounded(.down)) }
        for (a, b) in zip(items, items.dropFirst())
        where a.outgoing && b.outgoing && a.state == b.state && a.state != .notDelivered
            && minute(a.at) == minute(b.at) {
            shown.remove(a.id)
        }
        return shown
    }
}

/// VoiceOver announcements of state changes (§8): at most one every 3 s;
/// what comes meanwhile waits and is said together.
struct DeliveryAnnouncements {
    static let interval: TimeInterval = 3
    private(set) var lastAt: Date?
    private var received = 0
    private var notDelivered = 0

    mutating func add(received: Int, notDelivered: Int) {
        self.received += received
        self.notDelivered += notDelivered
    }

    /// When the waiting announcement may be said; nil if none waits.
    var due: Date? {
        guard received + notDelivered > 0 else { return nil }
        return lastAt.map { $0.addingTimeInterval(Self.interval) } ?? .distantPast
    }

    /// The announcement to say at `now`, if one waits and is due.
    mutating func take(now: Date, name: String, bundle: Bundle = .main, locale: Locale = .current) -> String? {
        guard let due, now >= due else { return nil }
        var parts: [String] = []
        if received == 1 {
            parts.append(String(localized: "Message received by \(name).", bundle: bundle, locale: locale))
        } else if received > 1 {
            parts.append(String(localized: "\(received) messages received by \(name).", bundle: bundle, locale: locale))
        }
        if notDelivered > 0 {
            parts.append(String(localized: "Message not delivered. Retry is in the actions.", bundle: bundle, locale: locale))
        }
        received = 0
        notDelivered = 0
        lastAt = now
        return parts.joined(separator: " ")
    }
}
