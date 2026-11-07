import BarkingKit
import Foundation
import Observation
import SwiftUI

/// "Deliveries" (spec Lot M §6.5): the messages sent to one contact, in
/// groups by state, newest first in each. A group loads 50 rows and the
/// rest as it is scrolled to; a `.delivery` change moves the rows it names
/// between groups without reading the screen again; `.messages` reads it
/// all again (it absorbs the `.delivery` ids still waiting).
@MainActor @Observable
final class DeliveriesModel {
    struct Row: Identifiable, Equatable {
        /// The message id.
        let id: Int64
        let text: String
        let at: Date
        var delivery: Delivery

        /// Newest first; the id breaks a tie, as the core does.
        fileprivate func precedes(_ other: Row) -> Bool {
            at != other.at ? at > other.at : id > other.id
        }
    }

    struct Group: Identifiable, Equatable {
        let state: DeliveryState
        /// Messages in this state, from the core: more than `rows` while pages wait.
        var count: Int
        var rows: [Row]

        var id: DeliveryState { state }
        var hasMore: Bool { rows.count < count }
    }

    enum Phase: Equatable {
        case loading
        case loaded
        /// Nothing could be read (§6.5 "Erreur").
        case failed
    }

    /// The groups, in the order the screen shows them.
    static let order: [DeliveryState] = [.notDelivered, .pending, .onNetwork, .received]
    static let pageSize = 50

    typealias Notice = ConversationModel.Notice

    let contact: String
    let contactName: String
    private let core: CoreService
    private(set) var phase: Phase = .loading
    /// A read or a page failed: the screen shows its warning with Retry.
    private(set) var readFailed = false
    /// The clock (tests set it).
    var now: () -> Date = { .now }
    /// A warning above the list (a retry found no device; a deletion failed or
    /// left something to say, §6.7).
    private(set) var notice: Notice? {
        didSet { if let notice, notice != oldValue { announce(notice.text()) } }
    }
    private var byState: [DeliveryState: Group] = [:]
    /// Posts a VoiceOver announcement (tests record it).
    var announce: (String) -> Void = { AccessibilityNotification.Announcement($0).post() }

    private var loading = false
    /// A change came while the screen was being read: read it again after.
    private var stale = false
    private var paging: Set<DeliveryState> = []
    private var retrying = false
    /// Counts the changes made to the rows: a page read across one is read again.
    private var epoch = 0
    private var announcements = DeliveryAnnouncements()
    private var announcementFlush: Task<Void, Never>?

    init(core: CoreService, contact: String, contactName: String = "") {
        self.core = core
        self.contact = contact
        self.contactName = contactName
    }

    /// The groups to show: the empty ones are absent.
    var groups: [Group] { Self.order.compactMap { byState[$0] }.filter { $0.count > 0 } }

    /// Nothing sent to list (§6.5 "Vide").
    var isEmpty: Bool { phase == .loaded && groups.isEmpty }

    // MARK: Reading

    /// Reads the counts, then the first page of each group.
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
            let counts = try await core.deliveryCounts(contact: contact)
            var next: [DeliveryState: Group] = [:]
            for state in Self.order {
                let n = Self.count(counts, state)
                let rows = n > 0 ? try await page(state, limit: Self.pageSize, offset: 0) : []
                next[state] = Group(state: state, count: n, rows: rows)
            }
            byState = next
            epoch += 1
            phase = .loaded
            readFailed = false
        } catch {
            // A failed refresh keeps what the screen shows, and says so.
            if phase != .loaded { phase = .failed }
            readFailed = true
        }
    }

    /// The next 50 rows of a group (as its last row comes on screen).
    func loadMore(_ state: DeliveryState) async {
        guard let group = byState[state], group.hasMore, paging.insert(state).inserted else { return }
        defer { paging.remove(state) }
        let start = epoch
        guard let more = try? await page(state, limit: Self.pageSize, offset: group.rows.count) else {
            // Not dropped: the screen's warning, with Retry.
            readFailed = true
            return
        }
        // Rows moved meanwhile: this page may start in the wrong place.
        guard start == epoch, var current = byState[state] else {
            paging.remove(state)
            await loadMore(state)
            return
        }
        let known = Set(current.rows.map(\.id))
        current.rows += more.filter { !known.contains($0.id) }
        // The count was ahead of the rows (a deletion unseen): stop asking.
        if more.isEmpty { current.count = current.rows.count }
        byState[state] = current
        epoch += 1
    }

    private func page(_ state: DeliveryState, limit: Int, offset: Int) async throws -> [Row] {
        try await core.deliveryPage(contact: contact, state: state, limit: UInt32(limit), offset: UInt32(offset)).map {
            Row(id: $0.messageId, text: $0.body, at: Date(timeIntervalSince1970: TimeInterval($0.at)),
                delivery: $0.delivery)
        }
    }

    private static func count(_ c: DeliveryCounts, _ state: DeliveryState) -> Int {
        switch state {
        case .pending: Int(c.pending)
        case .onNetwork: Int(c.onNetwork)
        case .received: Int(c.received)
        case .notDelivered: Int(c.notDelivered)
        }
    }

    // MARK: Changes

    /// What the core says changed: a `.messages` of this contact reads the
    /// screen again; a `.delivery` moves the rows it names.
    func apply(_ change: CoreChange) async {
        switch change {
        case .messages(let c) where c == contact:
            await load()
        case .delivery(let c, let ids) where c == contact:
            // Not read yet, or being read: the read will see these changes.
            if loading || phase != .loaded {
                stale = true
                await load()
                return
            }
            guard let updates = try? await core.deliveriesOf(ids) else {
                await load()
                return
            }
            let rest = apply(updates)
            await resolve(rest)
            await refill()
        default: break
        }
    }

    /// A group that lost rows to a move and holds fewer than a page while
    /// more wait reads on: its rows are on screen already, so nothing would
    /// ask for the next page.
    private func refill() async {
        for state in Self.order where !readFailed {
            guard let g = byState[state], g.hasMore, g.rows.count < Self.pageSize else { continue }
            await loadMore(state)
        }
    }

    /// What `apply(_:)` could not place from the rows it holds.
    struct Unplaced: Equatable {
        /// Groups a row of unknown text moved into: read again.
        var states: Set<DeliveryState> = []
        /// The counts moved by rows it never saw.
        var counts = false

        var isEmpty: Bool { states.isEmpty && !counts }
    }

    /// Moves each row to the group of its new state, in order, and the
    /// counts with it. A row that left the core (removed, or no summary any
    /// more) goes. A row going where it falls past the rows loaded only adds
    /// to the count: it shows as that group loads on.
    @discardableResult
    func apply(_ updates: [DeliveryUpdate]) -> Unplaced {
        var unplaced = Unplaced()
        var received = 0, notDelivered = 0
        for u in updates {
            let found = locate(u.messageId)
            guard !u.removed, let d = u.delivery else {
                if let found { remove(found) } else { unplaced.counts = true }
                continue
            }
            guard let found else {
                // Never loaded: its text is unknown, so its new group reads again.
                unplaced.states.insert(d.state)
                unplaced.counts = true
                continue
            }
            var row = remove(found, keepingCount: found.state == d.state)
            row.delivery = d
            insert(row, into: d.state, countsIt: found.state != d.state)
            // A row on screen reaching Received or Not delivered is announced (§8).
            if found.state != d.state {
                if d.state == .received { received += 1 }
                if d.state == .notDelivered { notDelivered += 1 }
            }
        }
        if !updates.isEmpty { epoch += 1 }
        if received + notDelivered > 0 {
            announcements.add(received: received, notDelivered: notDelivered)
            flushAnnouncements()
        }
        return unplaced
    }

    private struct Location { let state: DeliveryState; let index: Int }

    private func locate(_ id: Int64) -> Location? {
        for state in Self.order {
            if let i = byState[state]?.rows.firstIndex(where: { $0.id == id }) { return Location(state: state, index: i) }
        }
        return nil
    }

    @discardableResult
    private func remove(_ at: Location, keepingCount: Bool = false) -> Row {
        let row = byState[at.state]!.rows.remove(at: at.index)
        if !keepingCount { byState[at.state]!.count -= 1 }
        return row
    }

    private func insert(_ row: Row, into state: DeliveryState, countsIt: Bool) {
        var group = byState[state] ?? Group(state: state, count: 0, rows: [])
        let complete = !group.hasMore
        let place = group.rows.firstIndex { row.precedes($0) } ?? group.rows.count
        // Past the last row loaded of a group with more to come: it is on a
        // page not read yet.
        if complete || place < group.rows.count || !countsIt {
            group.rows.insert(row, at: place)
        }
        if countsIt { group.count += 1 }
        byState[state] = group
    }

    /// Reads what `apply(_:)` left: the counts, then the groups that got
    /// rows it never saw, over the rows already loaded.
    private func resolve(_ unplaced: Unplaced) async {
        guard !unplaced.isEmpty else { return }
        do {
            if unplaced.counts {
                let counts = try await core.deliveryCounts(contact: contact)
                for state in Self.order {
                    byState[state, default: Group(state: state, count: 0, rows: [])].count = Self.count(counts, state)
                }
            }
            for state in unplaced.states {
                let have = byState[state]?.rows.count ?? 0
                let rows = try await page(state, limit: max(Self.pageSize, have + 1), offset: 0)
                byState[state, default: Group(state: state, count: rows.count, rows: [])].rows = rows
            }
            epoch += 1
        } catch {
            await load()
            return
        }
        // Rows shown that the counts no longer hold: something moved unseen.
        if byState.values.contains(where: { $0.rows.count > $0.count }) { await load() }
    }

    /// Says what waits, if the last announcement is 3 s old; otherwise
    /// comes back when it is.
    private func flushAnnouncements() {
        if let text = announcements.take(now: now(), name: contactName) { announce(text) }
        guard let due = announcements.due, announcementFlush == nil else { return }
        let wait = max(0, due.timeIntervalSince(now()))
        announcementFlush = Task { [weak self] in
            try? await Task.sleep(for: .seconds(wait))
            guard let self else { return }
            self.announcementFlush = nil
            self.flushAnnouncements()
        }
    }

    // MARK: Actions

    /// Sends every not delivered message again; the groups follow.
    func retryAll() async {
        guard !retrying else { return }
        retrying = true
        defer { retrying = false }
        notice = nil
        var failed = false
        do {
            try await core.retryAll(contact: contact)
        } catch BarkingError.NoSession {
            notice = .noReachableDevice(name: contactName)
        } catch BarkingError.NothingToRetry {
            // They moved meanwhile; the read shows where.
        } catch {
            failed = true
        }
        await load()
        // After the read, which clears it: the warning stays until Retry.
        if failed { readFailed = true }
    }

    /// A deletion from a message sheet: what the banner says (§6.7).
    func showDeleted(_ message: DeleteBanner.Message?) {
        notice = message.map(Notice.deleted)
    }

    // MARK: VoiceOver focus

    /// The row VoiceOver was on, and the group it was in.
    struct FocusMemory: Equatable {
        let id: Int64
        let state: DeliveryState
    }

    /// The row to give the focus back to: only one that itself moved group.
    static func focusRestore(_ memory: FocusMemory?, in groups: [Group]) -> Int64? {
        guard let memory,
              let now = groups.first(where: { $0.rows.contains { $0.id == memory.id } })?.state,
              now != memory.state else { return nil }
        return memory.id
    }

    /// The group a loaded row is in.
    func state(of id: Int64) -> DeliveryState? {
        groups.first { $0.rows.contains { $0.id == id } }?.state
    }

    // MARK: Texts

    /// "14:02" today, "lun. 14:02" within the week, "3 nov." before (§6.5).
    static func timeText(_ at: Date, now: Date = .now, calendar: Calendar = .current,
                         locale: Locale = .current) -> String {
        var cal = calendar
        cal.locale = locale
        let style: Date.FormatStyle
        if cal.isDate(at, inSameDayAs: now) {
            style = Date.FormatStyle(locale: locale, calendar: cal, timeZone: cal.timeZone).hour().minute()
        } else if let week = cal.date(byAdding: .day, value: -6, to: cal.startOfDay(for: now)), at >= week, at <= now {
            style = Date.FormatStyle(locale: locale, calendar: cal, timeZone: cal.timeZone)
                .weekday(.abbreviated).hour().minute()
        } else {
            style = Date.FormatStyle(locale: locale, calendar: cal, timeZone: cal.timeZone)
                .day().month(.abbreviated)
        }
        return at.formatted(style)
    }
}

#if DEBUG
extension DeliveriesModel {
    /// Previews and renders: groups shown as if loaded (`counts` may run
    /// ahead of the rows, as while pages wait).
    func preload(_ rows: [DeliveryState: [Row]], counts: [DeliveryState: Int] = [:]) {
        byState = Dictionary(uniqueKeysWithValues: Self.order.map { state in
            let list = rows[state] ?? []
            return (state, Group(state: state, count: counts[state] ?? list.count, rows: list))
        })
        phase = .loaded
    }

    func preloadFailed() {
        byState = [:]
        phase = .failed
    }

    func preloadNotice(_ notice: Notice) { self.notice = notice }
}
#endif
