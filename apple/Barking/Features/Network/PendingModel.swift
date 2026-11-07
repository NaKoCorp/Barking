import BarkingKit
import Foundation
import Observation
import SwiftUI

/// "Pending" (spec Lot M §6.6): the packets that have not left this iPhone.
/// "Your messages" can be opened, deleted one by one, selected and cancelled
/// all together; "Sync" (receipts, copies for my other devices, updates, my
/// card) is read-only, one line per kind. Any change that can alter the
/// queue reads it again; a selected message that leaves is deselected.
@MainActor @Observable
final class PendingModel {
    /// One of my messages with packets still waiting here.
    struct Row: Identifiable, Equatable {
        let id: Int64
        /// Contact fingerprint, for the message sheet.
        let contact: String
        let name: String
        let body: String
        let sealedAt: Date
        let expiresAt: Date
        let packets: Int
        let devices: Int
        let devicesLeft: Int

        init(_ m: PendingMessage) {
            id = m.messageId
            contact = m.contact
            name = m.name
            body = m.body
            sealedAt = Date(timeIntervalSince1970: TimeInterval(m.sealedAt))
            expiresAt = Date(timeIntervalSince1970: TimeInterval(m.expiresAt))
            packets = Int(m.packets)
            devices = Int(m.devices)
            devicesLeft = Int(m.devicesLeft)
        }

        /// Part of it already left for a device (it cannot be recalled).
        var partlyLeft: Bool { devicesLeft > 0 }
    }

    /// One line of the "Sync" section: a sort of packet, in numbers.
    struct SyncRow: Identifiable, Equatable {
        let kind: PendingKind
        let packets: Int
        let names: [String]

        init(_ s: PendingSync) { self.init(kind: s.kind, packets: Int(s.packets), names: s.names) }
        init(kind: PendingKind, packets: Int, names: [String]) {
            self.kind = kind
            self.packets = packets
            self.names = names
        }

        var id: Int { Self.order.firstIndex(of: kind) ?? 0 }
        static let order: [PendingKind] = [.ack, .ownCopy, .deviceSync, .cardUpdate]

        var symbol: String {
            switch kind {
            case .ack: "arrow.uturn.backward"
            case .ownCopy: "arrow.triangle.2.circlepath"
            case .deviceSync: "iphone.and.arrow.forward"
            case .cardUpdate: "person.text.rectangle"
            }
        }
    }

    /// What the line under a message says (§6.6).
    struct Meta: Equatable {
        /// "2 h ago".
        let ago: String
        /// "expires in 22 h".
        let expires: String
        /// Under two hours left: the expiry in `warnFg`, with the triangle.
        let warn: Bool
        /// "already left for 1 of their 2 devices", when a part left.
        let left: String?

        /// One sentence for VoiceOver.
        var spoken: String { [ago, expires, left].compactMap { $0 }.joined(separator: ", ") }
    }

    /// A confirmation's texts (§7.4), already in words.
    struct Confirmation: Equatable {
        let title: String
        let message: String
        let button: String
    }

    /// The confirmation before deleting one message, as it was when it
    /// opened: its text stays while the core may have moved (§9).
    struct Ask: Identifiable, Equatable {
        let id = UUID()
        let messageId: Int64
        let confirmation: DeleteConfirmation
        let message: String
        /// The delivery the dialog was built from, for the banner (§6.7).
        let shown: Delivery

        static func == (a: Ask, b: Ask) -> Bool { a.id == b.id }
    }

    enum Phase: Equatable {
        case loading
        case loaded
        /// Nothing could be read.
        case failed
    }

    typealias Notice = ConversationModel.Notice

    /// Under this much time left, the expiry warns (§6.6).
    static let warnBelow: TimeInterval = 7_200

    private let core: CoreService
    private(set) var phase: Phase = .loading
    /// A refresh failed: the rows shown are the last read.
    private(set) var readFailed = false
    private(set) var messages: [Row] = []
    private(set) var sync: [SyncRow] = []
    /// Ids of the selected messages; only rows of "Your messages".
    private(set) var selection: Set<Int64> = []
    /// The selection mode. Leaving it forgets the selection.
    var selecting = false {
        didSet { if !selecting { selection = [] } }
    }
    /// The last sync found no network (§6.6 banner).
    private(set) var unreachable = false
    /// Rows whose deletion is running (§9: dimmed, a spinner for the symbol).
    private(set) var deleting: Set<Int64> = []
    /// A warning or a correction above the list (§6.6, §6.7).
    private(set) var notice: Notice? {
        didSet { if let notice, notice != oldValue { announce(notice.text()) } }
    }
    /// The clock (tests set it).
    var now: () -> Date = { .now }
    /// Posts a VoiceOver announcement (tests record it).
    var announce: (String) -> Void = { AccessibilityNotification.Announcement($0).post() }

    private var loading = false
    private var stale = false
    private var working = false

    init(core: CoreService) { self.core = core }

    // MARK: Numbers and states

    var messagePackets: Int { messages.reduce(0) { $0 + $1.packets } }
    var syncPackets: Int { sync.reduce(0) { $0 + $1.packets } }
    /// Both sections together: the number of the Network line (§5.7).
    var total: Int { messagePackets + syncPackets }
    var selectionCount: Int { selection.count }

    /// "Nothing pending. Everything has gone out."
    var isEmpty: Bool { messages.isEmpty && sync.isEmpty }
    /// Only sync packets wait: "None of your messages are waiting."
    var syncOnly: Bool { messages.isEmpty && !sync.isEmpty }
    /// "Select" is offered when a message can be selected, or while selecting
    /// (to leave: "Done").
    var canSelect: Bool { !messages.isEmpty || selecting }
    /// The danger zone: not while selecting, not without a message.
    var showsCancelAll: Bool { !messages.isEmpty && !selecting }
    var canDeleteSelected: Bool { !selection.isEmpty && !working }

    // MARK: Reading

    func load() async {
        if loading {
            stale = true
            return
        }
        loading = true
        defer { loading = false }
        repeat {
            stale = false
            await read()
        } while stale
    }

    private func read() async {
        do {
            let packets = try await core.pendingPackets()
            let up = await core.lastSync?.networkUp
            messages = packets.messages.map(Row.init).sorted {
                $0.expiresAt != $1.expiresAt ? $0.expiresAt < $1.expiresAt : $0.id < $1.id
            }
            sync = Self.merged(packets.sync)
            unreachable = up == false
            // A message that left the queue (deposited during a sync) leaves the selection.
            selection.formIntersection(messages.map(\.id))
            if messages.isEmpty { selecting = false }
            phase = .loaded
            readFailed = false
        } catch {
            // A failed refresh keeps what the screen shows, and says so.
            if phase != .loaded { phase = .failed }
            readFailed = true
        }
    }

    /// One row per kind, in a fixed order, the empty ones absent.
    private static func merged(_ list: [PendingSync]) -> [SyncRow] {
        SyncRow.order.compactMap { kind in
            let same = list.filter { $0.kind == kind }
            let packets = same.reduce(0) { $0 + Int($1.packets) }
            guard packets > 0 else { return nil }
            var names: [String] = []
            for n in same.flatMap(\.names) where !names.contains(n) { names.append(n) }
            return SyncRow(kind: kind, packets: packets, names: names)
        }
    }

    /// What the core says changed: anything that can alter the queue reads it again.
    func apply(_ change: CoreChange) async {
        switch change {
        case .network, .messages, .delivery, .contacts, .devices: await load()
        case .identity: break
        }
    }

    // MARK: Selection

    func toggle(_ id: Int64) {
        guard selecting, messages.contains(where: { $0.id == id }) else { return }
        if !selection.insert(id).inserted { selection.remove(id) }
    }

    func selectAll() {
        guard selecting else { return }
        selection = Set(messages.map(\.id))
    }

    // MARK: Deleting

    /// The dialog for one message (§7.4), from the delivery the core has
    /// now. Nil when the message is gone (deleted elsewhere, §9): nothing to
    /// ask, the list reads again.
    func askDelete(_ id: Int64, bundle: Bundle = .main, locale: Locale = .current) async -> Ask? {
        guard let row = messages.first(where: { $0.id == id }) else { return nil }
        var shown = Self.estimate(of: row)
        var keepsCopies = false
        do {
            guard let sheet = try await core.messageDelivery(id) else {
                await load()
                return nil
            }
            shown = sheet.delivery
            keepsCopies = DeleteConfirmation.keepsOwnCopies(delivery: sheet.delivery, ownCopies: sheet.ownCopies)
        } catch {
            // Unreadable: the row's own numbers say enough for the case.
        }
        let confirmation = DeleteConfirmation(outgoing: true, delivery: shown)
        return Ask(messageId: id, confirmation: confirmation,
                   message: confirmation.message(name: row.name, keepsOwnCopies: keepsCopies, bundle: bundle, locale: locale),
                   shown: shown)
    }

    /// What the queue knows of a message's delivery: enough to pick the §7.4 case.
    private static func estimate(of row: Row) -> Delivery {
        Delivery(state: row.partlyLeft ? .onNetwork : .pending,
                 sealedAt: UInt64(row.sealedAt.timeIntervalSince1970), depositedAt: nil, receivedAt: nil, expiredAt: nil,
                 devices: UInt32(row.devices), devicesReceived: 0, devicesLeft: UInt32(row.devicesLeft),
                 devicesPending: UInt32(max(1, row.devices - row.devicesLeft)))
    }

    /// Deletes one message once confirmed; the banner says what the core really did (§6.7).
    func delete(_ id: Int64, shown: Delivery) async {
        guard let row = messages.first(where: { $0.id == id }), !deleting.contains(id), !working else { return }
        working = true
        deleting.insert(id)
        defer {
            deleting.remove(id)
            working = false
        }
        notice = nil
        do {
            let outcome = try await core.deleteMessage(id)
            // The device counts come from the deletion's own transaction.
            notice = DeleteBanner.message(shown: shown.state, outcome: outcome, contactName: row.name,
                                          devices: (left: Int(outcome.devicesLeft), total: Int(outcome.devicesTotal)))
                .map(Notice.deleted)
            selection.remove(id)
        } catch {
            notice = .deleteFailed
        }
        await load()
    }

    /// Deletes the selected messages once confirmed.
    func deleteSelected() async {
        let ids = messages.map(\.id).filter(selection.contains)
        guard !ids.isEmpty, !working else { return }
        working = true
        deleting.formUnion(ids)
        defer {
            deleting.subtract(ids)
            working = false
        }
        notice = nil
        do {
            let outcome = try await core.deleteMessages(ids)
            notice = DeleteBanner.message(shown: nil, outcome: outcome, contactName: "").map(Notice.deleted)
            selecting = false
        } catch {
            // Nothing changed: the selection stays.
            notice = .deleteFailed
        }
        await load()
    }

    /// Cancels every message of "Your messages" once confirmed.
    func cancelAll() async {
        guard !messages.isEmpty, !working else { return }
        working = true
        let ids = Set(messages.map(\.id))
        deleting.formUnion(ids)
        defer {
            deleting.subtract(ids)
            working = false
        }
        notice = nil
        do {
            let outcome = try await core.cancelAllPending()
            notice = DeleteBanner.message(shown: nil, outcome: outcome, contactName: "").map(Notice.deleted)
        } catch {
            notice = .deleteFailed
        }
        await load()
    }

    /// A deletion from a message sheet: what the banner says (§6.7).
    func showDeleted(_ message: DeleteBanner.Message?) {
        notice = message.map(Notice.deleted)
    }

    // MARK: Texts

    /// §7.4 "Sélection": what is cancelled, and what still arrives.
    func selectionConfirmation(bundle: Bundle = .main, locale: Locale = .current) -> Confirmation {
        let rows = messages.filter { selection.contains($0.id) }
        return Confirmation(
            title: Self.title(delete: rows.count, bundle: bundle, locale: locale),
            message: Self.cancelledAndKept(rows, bundle: bundle, locale: locale),
            button: String(localized: "Delete \(rows.count)", bundle: bundle, locale: locale))
    }

    /// §7.4 "Tout annuler". When some message already left for a device, the
    /// text says what stays instead of claiming nobody receives it (§14.1).
    func cancelAllConfirmation(bundle: Bundle = .main, locale: Locale = .current) -> Confirmation {
        let rows = messages
        let title = String(localized: "Cancel \(rows.count) messages?", bundle: bundle, locale: locale)
        let button = String(localized: "Delete and cancel", bundle: bundle, locale: locale)
        guard !rows.contains(where: \.partlyLeft) else {
            return Confirmation(title: title, message: Self.cancelledAndKept(rows, bundle: bundle, locale: locale), button: button)
        }
        let names = Self.recipients(of: rows)
        let text = String(localized: "They haven’t left this iPhone. \(DeleteBanner.names(names, bundle: bundle, locale: locale)) won’t receive them.\(rows.count)\(names.count)",
                          bundle: bundle, locale: locale)
        return Confirmation(title: title, message: text, button: button)
    }

    private static func title(delete count: Int, bundle: Bundle, locale: Locale) -> String {
        String(localized: "Delete \(count) messages?", bundle: bundle, locale: locale)
    }

    /// "2 haven’t left and will be cancelled. 1 is already on the network: Sam will still receive it."
    private static func cancelledAndKept(_ rows: [Row], bundle: Bundle, locale: Locale) -> String {
        let cancelled = rows.filter { !$0.partlyLeft }.count
        let kept = rows.filter(\.partlyLeft)
        var sentences: [String] = []
        if cancelled > 0 {
            sentences.append(String(localized: "\(cancelled) haven’t left and will be cancelled.", bundle: bundle, locale: locale))
        }
        if !kept.isEmpty {
            let names = recipients(of: kept)
            sentences.append(String(localized: "\(kept.count) are already on the network: \(DeleteBanner.names(names, bundle: bundle, locale: locale)) will still receive it.\(names.count)",
                                    bundle: bundle, locale: locale))
        }
        return sentences.joined(separator: " ")
    }

    /// The distinct recipients, in the order of the rows.
    private static func recipients(of rows: [Row]) -> [String] {
        var seen: Set<String> = []
        return rows.filter { seen.insert($0.contact).inserted }.map(\.name)
    }

    /// The line under a message: how long ago, how long left (rounded up to
    /// the minute, so it never promises more than there is), and where a part
    /// of it already went.
    static func meta(for row: Row, now: Date, bundle: Bundle = .main, locale: Locale = .current) -> Meta {
        /// "2 h", "5 min": hours from an hour on, otherwise minutes, at least one.
        func duration(_ seconds: TimeInterval, up: Bool) -> String {
            let minutes = max(1, Int(up ? (seconds / 60).rounded(.up) : (seconds / 60).rounded(.down)))
            return minutes >= 60
                ? String(localized: "\(minutes / 60) h", bundle: bundle, locale: locale)
                : String(localized: "\(minutes) min", bundle: bundle, locale: locale)
        }
        let ago = duration(now.timeIntervalSince(row.sealedAt), up: false)
        let remaining = row.expiresAt.timeIntervalSince(now)
        let left: String? = row.partlyLeft
            ? String(localized: "already left for \(row.devicesLeft) of \(row.devices) devices", bundle: bundle, locale: locale)
            : nil
        return Meta(ago: String(localized: "\(ago) ago", bundle: bundle, locale: locale),
                    expires: String(localized: "expires in \(duration(remaining, up: true))", bundle: bundle, locale: locale),
                    warn: remaining < warnBelow, left: left)
    }

    /// A line of the "Sync" section.
    static func title(of row: SyncRow, bundle: Bundle = .main, locale: Locale = .current) -> String {
        let n = row.packets
        switch row.kind {
        case .ack:
            if row.names.isEmpty { return String(localized: "Receipts · \(n)", bundle: bundle, locale: locale) }
            let names = DeleteBanner.names(row.names, bundle: bundle, locale: locale)
            return String(localized: "Receipts for \(names) · \(n)", bundle: bundle, locale: locale)
        case .ownCopy:
            return String(localized: "Copies of your messages for your other devices · \(n)", bundle: bundle, locale: locale)
        case .deviceSync:
            return String(localized: "Updates for your other devices · \(n)", bundle: bundle, locale: locale)
        case .cardUpdate:
            return String(localized: "Your card, for your contacts · \(n)", bundle: bundle, locale: locale)
        }
    }
}

#if DEBUG
extension PendingModel {
    /// Previews and renders: the screen as if loaded.
    func preload(_ packets: PendingPackets, unreachable: Bool = false) {
        messages = packets.messages.map(Row.init).sorted {
            $0.expiresAt != $1.expiresAt ? $0.expiresAt < $1.expiresAt : $0.id < $1.id
        }
        sync = Self.merged(packets.sync)
        self.unreachable = unreachable
        phase = .loaded
    }

    func preloadSelection(_ ids: Set<Int64>) {
        selecting = true
        selection = ids
    }

    func preloadNotice(_ notice: Notice) { self.notice = notice }
}
#endif

extension Bundle {
    /// The bundle holding the strings of `locale`'s language: a built
    /// sentence follows the environment's locale (a French preview or render,
    /// not only the device language). The main bundle when there is none.
    static func strings(for locale: Locale) -> Bundle {
        guard let code = locale.language.languageCode?.identifier,
              let path = Bundle.main.path(forResource: code, ofType: "lproj"),
              let bundle = Bundle(path: path) else { return .main }
        return bundle
    }
}
