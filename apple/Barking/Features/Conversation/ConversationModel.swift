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
        /// Shown at Send, before the core has the row (negative id): no
        /// details, delete or retry yet.
        var local = false
        /// What this message answers; nil when it is not a reply.
        var quote: Quote?
        /// The emoji under it, ordered by the core.
        var reactions: [ReactionChip] = []
        /// A placeholder for content this version cannot read.
        var needsUpdate = false
        /// Send state of my reactions toward the contact; nil without a
        /// tracked send (the chip then keeps the neutral look).
        var myReactionState: DeliveryState?
        /// The delay of an ephemeral, in seconds; nil for a plain message.
        var ttl: UInt32?
        /// When it was first seen (Unix seconds); nil while it waits.
        var seenAt: UInt64?
        /// When the core erases it (Unix seconds). While unseen, only the
        /// 7-day ceiling.
        var expireAt: UInt64?

        /// Seconds left before it disappears at `now`: the whole delay while
        /// unseen (the countdown has not started), else until `expireAt`.
        /// nil for a plain message.
        func remaining(at now: Date) -> Int? {
            guard let ttl else { return nil }
            guard seenAt != nil, let expireAt else { return Int(ttl) }
            return Int(expireAt) - Int(now.timeIntervalSince1970.rounded(.down))
        }

        /// An ephemeral not seen yet: reported once on screen.
        var awaitsSeen: Bool { ttl != nil && seenAt == nil && !local }

        /// A local row (not in the core yet) or a placeholder can be neither
        /// replied to, reacted to, nor copied.
        var canReplyOrReact: Bool { !local && !needsUpdate }

        /// Copy is not offered on an ephemeral: the pasteboard would keep
        /// its text after the message is erased.
        var canCopy: Bool { canReplyOrReact && ttl == nil }

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
        /// A reaction was refused: 20 emoji of mine on the message at most.
        case reactionTooMany
        /// A reaction was not saved (the emoji or the message is gone, or the core failed).
        case reactionFailed
        /// A manual resend of my reaction failed; the reaction itself is saved.
        case reactionResendFailed
        /// The contact was removed meanwhile; nothing can be sent to them.
        case contactRemoved

        /// What the banner says, spoken when it appears.
        func text(bundle: Bundle = .main, locale: Locale = .current) -> String {
            switch self {
            case .deleted(let message): message.string(bundle: bundle, locale: locale)
            case .deleteFailed:
                String(localized: "Deletion failed. Nothing has changed.", bundle: bundle, locale: locale)
            case .noReachableDevice(let name):
                String(localized: "\(name) has no reachable device left. The message can’t be sent again.",
                       bundle: bundle, locale: locale)
            case .reactionTooMany:
                String(localized: "You can react with 20 emoji at most on one message.", bundle: bundle, locale: locale)
            case .reactionFailed:
                String(localized: "Reaction not saved. Try again.", bundle: bundle, locale: locale)
            case .reactionResendFailed:
                String(localized: "Couldn't resend the reaction.", bundle: bundle, locale: locale)
            case .contactRemoved:
                String(localized: "This contact was removed. Nothing can be sent to them.", bundle: bundle, locale: locale)
            }
        }
    }

    static let maxBytes = 4000
    static let counterFrom = 3500
    /// The quick row of the reaction picker.
    static let frequentEmoji = ["👍", "❤️", "😂", "😮", "😢", "🙏"]
    /// Emoji of mine on one message at most (the core refuses more).
    static let maxReactions = 20
    /// Characters of the original the reply banner shows.
    static let bannerChars = 60

    let contact: String
    private let core: CoreService
    private(set) var items: [Item] = []
    /// The history was read once: no message then means an empty
    /// conversation, not one still loading.
    private(set) var loaded = false
    private(set) var name = "" {
        // A renamed contact: the changed-device line says the new name too.
        didSet { if name != oldValue { deviceChangedText = deviceChangedLine(bundle: language.bundle, locale: language.locale) } }
    }
    private(set) var verified = false
    /// What the header says (U-20).
    var trust: Trust { Trust(verified: verified) }
    private(set) var keyChanged = false
    /// The contact's latest device change of the last 7 days (§7.7): a
    /// quiet line, not a warning, since the root key did not change.
    private(set) var deviceChangedAt: Date?
    /// `deviceChangedLine` in the app's language, built when the change is
    /// read or the language changes, not at every render.
    private(set) var deviceChangedText: String?
    /// How long the changed-device line stays.
    static let deviceChangeShownFor: TimeInterval = 7 * 86_400
    /// The contact was read from the core: until then `verified` says nothing.
    private var contactLoaded = false
    /// Writing to a contact whose safety code was never compared: a warning,
    /// never a block. The key-changed banner says more and replaces it.
    var showsUnverified: Bool { contactLoaded && !verified && !keyChanged }
    private var sending = false
    /// The bubble of the send running: a send can wait seconds on the core
    /// lock while a sync holds it, so it shows at once and survives reloads.
    private var shownAtSend: Item?
    /// The newest core row shown when that send started: a later sent row
    /// with its text is the send's own row, which replaces the bubble.
    private var shownAtSendAfter: Int64 = 0
    private var nextLocalId: Int64 = -1
    /// Rows whose retry is running: a second tap on one does nothing.
    private var retrying: Set<Int64> = []
    /// Rows whose manual reaction resend is running.
    private var retryingReaction: Set<Int64> = []
    private var visible = false
    private(set) var sendError: String?
    /// Said to VoiceOver when it appears: the banner itself is not focused.
    private(set) var notice: Notice? {
        didSet { if let notice, notice != oldValue { announce(notice.text(bundle: language.bundle, locale: language.locale)) } }
    }
    /// Rows whose deletion is running (§9: dimmed, a spinner for the symbol).
    private(set) var deleting: Set<Int64> = []
    /// This device was removed from the account: it can no longer send.
    private(set) var removed = false
    var draft = ""
    /// The message the next send answers. Not part of the draft (spec §5.6):
    /// it is kept when a send fails and dropped when its row is gone.
    private(set) var replyingTo: Item?
    /// The disappearing delay of the next send, in seconds (spec §5.5). Never
    /// part of the draft: it goes back to nil after a send and when the
    /// conversation disappears; a failed send keeps it with the draft.
    var ttl: UInt32?
    /// The row a tapped quote jumped to, lit for `highlightDuration`.
    private(set) var highlighted: Int64?
    var highlightDuration: Duration = .milliseconds(1500)
    private var highlightClear: Task<Void, Never>?
    /// Rows whose reaction change is running: a second tap waits for the first.
    private var reacting: Set<Int64> = []
    /// What the core holds as this conversation's draft, as far as known:
    /// a save only runs when `draft` differs from it.
    private var lastSaved = ""

    /// Bubbles on screen: only their changes are announced (§8).
    private var onScreen: Set<Int64> = []
    private var announcements = DeliveryAnnouncements()
    private var announcementFlush: Task<Void, Never>?
    /// The app's language, set by the view: what is spoken follows the same
    /// override as what is shown.
    var language: (bundle: Bundle, locale: Locale) = (.main, .current) {
        didSet { deviceChangedText = deviceChangedLine(bundle: language.bundle, locale: language.locale) }
    }
    /// Posts a VoiceOver announcement (tests record it).
    var announce: (String) -> Void = { AccessibilityNotification.Announcement($0).post() }
    var now: () -> Date = Date.init

    // MARK: Ephemerals (spec deletion/ephemeral §5.3, §5.5)

    /// The scene is active: seen and the expiry timer only count then.
    private var active = false
    /// The app's lock screen is up: nothing on screen is seen.
    var covered = false {
        didSet { if covered != oldValue { reportSeen() } }
    }
    /// Bubbles more than half inside the visible part of the list.
    private var visibleBubbles: Set<Int64> = []
    /// Gathers what is seen and calls the core at most once a second.
    let seen: SeenTracker
    /// How the seen tracker waits (tests end the wait by hand).
    var seenSleep: @Sendable (Duration) async throws -> Void {
        get { seen.sleep }
        set { seen.sleep = newValue }
    }
    /// How the expiry timer waits (tests end the wait by hand).
    var expirySleep: @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) }
    /// Sleeps until the next ephemeral is due, then erases it; one at a time.
    private(set) var expiryTimer: Task<Void, Never>?
    /// A due time already past (the core's clock and this one differ):
    /// wait this long rather than spin.
    static let pastDueWait: Duration = .seconds(1)

    init(contact: String, core: CoreService) {
        self.contact = contact
        self.core = core
        seen = SeenTracker()
        seen.report = { [weak self] ids in await self?.markSeen(ids) ?? false }
    }

    /// The banner above the field while replying: who is quoted and the
    /// first line of their text.
    var replyBanner: (name: String, excerpt: String)? { replyBanner() }

    /// The same, with "You" in the language of `bundle` (the app's own
    /// override, not only the device's).
    func replyBanner(bundle: Bundle = .main, locale: Locale = .current) -> (name: String, excerpt: String)? {
        guard let item = replyingTo else { return nil }
        let line = item.text.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
        return (item.outgoing ? String(localized: "You", bundle: bundle, locale: locale) : name,
                String(line.prefix(Self.bannerChars)))
    }

    /// The warning above the field while a delay is set: when it erases here
    /// and there, and that the contact can still take a screenshot.
    func ephemeralBanner(bundle: Bundle = .main, locale: Locale = .current) -> String? {
        guard let ttl else { return nil }
        let delay = EphemeralDelay(seconds: ttl).longLabel(bundle: bundle, locale: locale)
        let format = bundle.localizedString(
            forKey: "Disappears %1$@ after sending for you, %1$@ after reading for %2$@. %2$@ can take a screenshot.",
            value: nil, table: nil)
        return String(format: format, locale: locale, delay, name)
    }

    /// What the quote of `item` shows: its author ("You" or the contact) and
    /// the start of the original; nil when `item` is not a reply.
    func quoteLine(for item: Item, bundle: Bundle = .main, locale: Locale = .current) -> QuoteLine? {
        guard let quote = item.quote else { return nil }
        return QuoteLine(quote: quote,
                         author: quote.authorIsMe ? String(localized: "You", bundle: bundle, locale: locale) : name)
    }

    var byteCount: Int { draft.utf8.count }
    var lastMessageId: Int64? { items.last?.id }
    var showsCounter: Bool { byteCount >= Self.counterFrom }
    var canSend: Bool {
        !sending && !removed && byteCount <= Self.maxBytes
            && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func onAppear() async {
        visible = true
        removed = ((try? await core.removed()) ?? nil) != nil
        await loadDraft()
        await reload()
        let changes = (try? await core.keyChanges(since: 0)) ?? []
        keyChanged = !verified && changes.contains { $0.contact == contact }
        await loadDeviceChange()
    }

    private func loadDeviceChange() async {
        let since = UInt64(max(0, now().timeIntervalSince1970 - Self.deviceChangeShownFor))
        let latest = ((try? await core.deviceChanges(since: since)) ?? [])
            .filter { $0.contact == contact && $0.at >= since }.map(\.at).max()
        deviceChangedAt = latest.map { Date(timeIntervalSince1970: TimeInterval($0)) }
        deviceChangedText = deviceChangedLine(bundle: language.bundle, locale: language.locale)
    }

    /// "Léa changed device · 2 d ago", in the app's language; nil without a
    /// recent change.
    func deviceChangedLine(bundle: Bundle = .main, locale: Locale = .current) -> String? {
        guard let deviceChangedAt else { return nil }
        let ago = RequestHistory.relative(deviceChangedAt, now: now(), locale: locale)
        return String(localized: "\(name) changed device · \(ago)", bundle: bundle, locale: locale)
    }

    /// Puts the stored draft in the field, unless something was typed
    /// meanwhile. A removed device keeps no draft.
    private func loadDraft() async {
        guard !removed, draft.isEmpty,
              let stored = (try? await core.draft(contact)) ?? nil else { return }
        lastSaved = stored
        if draft.isEmpty { draft = stored }
    }

    /// Keeps the draft in the core. Silent: a draft too long for a message,
    /// a removed device or a core error saves nothing and says nothing; a
    /// later save tries again. Never while a send runs: the field is empty
    /// then, and the stored text must stay until the send succeeds.
    func saveDraft() async {
        guard !sending else { return }
        await persistDraft()
    }

    private func persistDraft() async {
        guard !removed, byteCount <= Self.maxBytes, draft != lastSaved else { return }
        let text = draft
        if (try? await core.setDraft(contact, text: text)) != nil { lastSaved = text }
    }

    func onDisappear() {
        visible = false
        ttl = nil
        onScreen = []
        visibleBubbles = []
        // What was seen in the last second is still told, not dropped.
        seen.finish()
        expiryTimer?.cancel()
        expiryTimer = nil
    }

    /// The scene became active or left it. Active: erases what is due,
    /// reloads (which arms the timer) and reports what is on screen. Not
    /// active: the timer stops and nothing more is seen.
    func phaseChanged(active: Bool) async {
        self.active = active
        guard active else {
            expiryTimer?.cancel()
            expiryTimer = nil
            return
        }
        await expireDue()
    }

    /// A bubble is now more (or no longer more) than half on screen.
    func bubbleVisibility(_ id: Int64, shown: Bool) {
        if shown { visibleBubbles.insert(id) } else { visibleBubbles.remove(id) }
        if shown { reportSeen() }
    }

    /// Hands the ephemerals on screen, not seen yet, to the tracker: only
    /// with the conversation shown, the app active and its lock down.
    private func reportSeen() {
        guard visible, active, !covered else { return }
        let ids = items.filter { $0.awaitsSeen && visibleBubbles.contains($0.id) }.map(\.id)
        if !ids.isEmpty { seen.saw(ids) }
    }

    /// Tells the core, then reloads: the countdown starts and the next
    /// expiry may come sooner.
    private func markSeen(_ ids: [Int64]) async -> Bool {
        do {
            try await core.markSeen(ids)
        } catch {
            return false
        }
        await reload()
        return true
    }

    /// Erases what is due now, then reloads (and arms the timer again).
    private func expireDue() async {
        _ = try? await core.expireEphemeral()
        await reload()
    }

    /// One timer, to the next expiry, while the conversation is shown and
    /// the app active. Called again after each reload.
    private func armExpiry() async {
        expiryTimer?.cancel()
        expiryTimer = nil
        guard visible, active, let due = (try? await core.nextExpiry()) ?? nil else { return }
        // Another reload may have armed one meanwhile: this one replaces it.
        expiryTimer?.cancel()
        guard visible, active else { expiryTimer = nil; return }
        let left = Double(due) - now().timeIntervalSince1970
        let wait: Duration = left > 0 ? .milliseconds(Int64((left * 1000).rounded(.up))) : Self.pastDueWait
        let sleep = expirySleep
        expiryTimer = Task { [weak self] in
            do { try await sleep(wait) } catch { return }
            guard !Task.isCancelled, let self else { return }
            // Its own reload arms the next one: nothing to cancel here.
            self.expiryTimer = nil
            await self.expireDue()
        }
    }

    /// What a change of the core means here: `.messages` of this contact
    /// reloads whole, `.delivery` patches its rows, `.contacts` refreshes
    /// the header. Nothing else touches the messages.
    func handle(_ change: CoreChange) async {
        switch change {
        case .messages(let c) where c == contact: await reload()
        case .delivery(let c, let ids) where c == contact: await refresh(ids)
        case .contacts: await refreshContact()
        case .expired(let ids) where items.contains(where: { ids.contains($0.id) }): await reload()
        default: break
        }
    }

    private func refreshContact() async {
        if let c = try? await core.contacts().first(where: { $0.fingerprint == contact }) {
            name = c.alias ?? c.displayName
            verified = c.verified
            contactLoaded = true
        }
    }

    func reload() async {
        await refreshContact()
        let messages = (try? await core.messages(with: contact)) ?? []
        show(messages)
        // What arrives while the conversation is on screen is read.
        if visible, let last = items.last(where: { !$0.outgoing }) {
            try? await core.markRead(contact, upTo: last.id)
        }
        reportSeen()
        await armExpiry()
    }

    /// The core's rows become the bubbles, with the send in progress, if
    /// its row is not there yet. No core call: a send shows its row at once.
    private func show(_ messages: [Message]) {
        loaded = true
        // A failed message with a later sent copy was retried the old way
        // (before Lot M, a new row): hide it, even after reopening.
        let resent = messages.filter { $0.failed && $0.outgoing }.filter { f in
            messages.contains { $0.outgoing && !$0.failed && $0.id > f.id && $0.body == f.body }
        }.map(\.id)
        // The core writes the send's row (and says so) before the send
        // returns: from then on that row stands for the bubble, never both.
        if let local = shownAtSend,
           messages.contains(where: { $0.outgoing && $0.id > shownAtSendAfter && $0.body == local.text }) {
            shownAtSend = nil
        }
        items = messages.filter { !resent.contains($0.id) }.map {
            Item(id: $0.id, outgoing: $0.outgoing, text: $0.body,
                 at: Date(timeIntervalSince1970: TimeInterval($0.at)), delivery: $0.delivery,
                 quote: $0.replyTo, reactions: $0.reactions, needsUpdate: $0.needsUpdate,
                 myReactionState: $0.myReactionState, ttl: $0.ttlSecs, seenAt: $0.seenAt, expireAt: $0.expireAt)
        } + [shownAtSend].compactMap { $0 }
        // The row being answered left (deleted): nothing to answer any more.
        if let target = replyingTo, !items.contains(where: { $0.id == target.id }) { replyingTo = nil }
    }

    /// Fresh delivery of the rows `ids` shown here, patched in place (and
    /// announced, §8). An ephemeral named (seen on another of my devices:
    /// its countdown changed) then reloads the conversation, which arms the
    /// expiry timer again.
    func refresh(_ ids: [Int64]) async {
        let shown = ids.filter { id in items.contains { $0.id == id } }
        let ephemeral = items.contains { $0.ttl != nil && shown.contains($0.id) }
        if !shown.isEmpty, let updates = try? await core.deliveriesOf(shown) { apply(updates) }
        if ephemeral { await reload() }
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
            items[i].myReactionState = u.myReactionState
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
        if let text = announcements.take(now: now(), name: name, bundle: language.bundle, locale: language.locale) { announce(text) }
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
        let at = now()
        let replyId = replyingTo?.id
        let delay = ttl
        let shown = Item(id: nextLocalId, outgoing: true, text: text, at: at,
                         delivery: Delivery(state: .pending, sealedAt: UInt64(at.timeIntervalSince1970),
                                            depositedAt: nil, receivedAt: nil, expiredAt: nil, devices: 0,
                                            devicesReceived: 0, devicesLeft: 0, devicesPending: 0),
                         local: true)
        nextLocalId -= 1
        shownAtSendAfter = items.filter { !$0.local }.map(\.id).max() ?? 0
        shownAtSend = shown
        items.append(shown)
        do {
            // Sent: the stored draft goes in the same call. Not before, so
            // a failure keeps it.
            let result = try await core.send(text, to: contact, replyTo: replyId, ttlSecs: delay,
                                             clearingDraft: true)
            if result.draftCleared { lastSaved = "" }
            replyingTo = nil
            ttl = nil
            // The core's row replaces the bubble now, read before the sync
            // the send starts: that sync holds the core through its network
            // round, and any later call waits for it.
            if let rows = result.rows { show(rows) }
            // Not awaited, so the next send need not wait for the sync.
            Task {
                // This send's bubble only: a later send keeps its own.
                if shownAtSend?.id == shown.id { shownAtSend = nil }
                await reload()
            }
        } catch {
            draft = text
            sendError = "Not sent. Try again in a moment."
            // A disappear during the send skipped its save: store it now.
            await persistDraft()
            // The reload drops the bubble.
            shownAtSend = nil
            await reload()
        }
    }

    /// Sends a GIF picked in the picker (spec GIF §9.4), as `send` a text:
    /// to the message being answered and with the delay set, both dropped
    /// once it is queued and kept if it is not. The draft stays as it is.
    /// True once the core queued it; false while another send runs.
    @discardableResult
    func sendGif(_ gif: GifInfo) async -> Bool {
        guard !sending, !removed else {
            sendError = "Not sent. Try again in a moment."
            return false
        }
        sending = true
        defer { sending = false }
        sendError = nil
        notice = nil
        let replyId = replyingTo?.id
        let delay = ttl
        do {
            let rows = try await core.sendGif(gif, to: contact, replyTo: replyId, ttlSecs: delay)
            replyingTo = nil
            ttl = nil
            // Read in the send's own call, before the sync it starts.
            if let rows { show(rows) }
            Task { await reload() }
            return true
        } catch {
            sendError = "Not sent. Try again in a moment."
            return false
        }
    }

    /// "Use GIFs" was not stored (spec GIF §9.2): said where sends fail.
    func gifsNotSaved() { sendError = "Not saved. Try again." }

    /// Starts answering the row `id`; ignored for a local row, a placeholder
    /// or a row not shown.
    func startReply(_ id: Int64) {
        guard let item = items.first(where: { $0.id == id }), item.canReplyOrReact else { return }
        replyingTo = item
    }

    func cancelReply() { replyingTo = nil }

    /// Fewer than 20 emoji of mine on the row `id`.
    func canAdd(on id: Int64) -> Bool {
        guard let item = items.first(where: { $0.id == id }) else { return false }
        return item.reactions.filter(\.mine).count < Self.maxReactions
    }

    /// Adds my `emoji` on the row `id`, or removes it if it is already mine,
    /// then reloads the chips. A refusal reloads and is said in the banner.
    func toggle(_ emoji: String, on id: Int64) async {
        guard let item = items.first(where: { $0.id == id }), item.canReplyOrReact,
              !reacting.contains(id) else { return }
        var mine = item.reactions.filter(\.mine).map(\.emoji)
        if let at = mine.firstIndex(of: emoji) {
            mine.remove(at: at)
        } else {
            guard mine.count < Self.maxReactions else { return }
            mine.append(emoji)
        }
        reacting.insert(id)
        defer { reacting.remove(id) }
        notice = nil
        do {
            try await core.setReactions(id, emojis: mine, contact: contact)
        } catch BarkingError.TooManyEmoji {
            notice = .reactionTooMany
        } catch BarkingError.NotFound {
            notice = .contactRemoved
        } catch {
            notice = .reactionFailed
        }
        await reload()
    }

    /// The row a quote points at, lit for `highlightDuration`; nil when the
    /// original is unavailable or not among the rows.
    @discardableResult
    func jump(to quote: Quote) -> Int64? {
        guard let id = quote.id, items.contains(where: { $0.id == id }) else { return nil }
        highlighted = id
        highlightClear?.cancel()
        highlightClear = Task { [weak self, duration = highlightDuration] in
            try? await Task.sleep(for: duration)
            guard !Task.isCancelled, let self else { return }
            self.highlighted = nil
        }
        return id
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

    /// Sends my reactions on the row `id` to the contact again (a manual
    /// resend), then patches the row. Whatever the error, the banner says the
    /// resend failed (the reaction itself stays saved).
    func retryReaction(_ id: Int64) async {
        guard !retryingReaction.contains(id), items.contains(where: { $0.id == id }) else { return }
        retryingReaction.insert(id)
        defer { retryingReaction.remove(id) }
        notice = nil
        do {
            try await core.retryReactions(id, contact: contact)
        } catch {
            notice = .reactionResendFailed
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

    /// How many of my other devices are linked: the deletion goes to all of
    /// them, and the confirmation's title says "all your devices".
    func otherDevices() async -> Int {
        ((try? await core.myDevices()) ?? []).filter { !$0.thisDevice }.count
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

/// Gathers the ephemerals seen on screen and tells the core at most once a
/// second (spec deletion/ephemeral §5.5): the first sighting opens a
/// one-second window, the next ones join it, and its end reports them all
/// in one call. An id is reported once; a failed report forgets its ids,
/// so the next sighting tries again. Leaving (`finish`) reports what waits
/// at once.
@MainActor
final class SeenTracker {
    static let interval: Duration = .seconds(1)
    /// Tells the core; true when it took them.
    var report: @MainActor ([Int64]) async -> Bool
    var sleep: @Sendable (Duration) async throws -> Void
    private var waiting: [Int64] = []
    private var reported: Set<Int64> = []
    /// The window open now, if any.
    private(set) var flushTask: Task<Void, Never>?
    /// The report made on leaving, apart from the windows: a return to the
    /// conversation opens new ones at once.
    private(set) var leaveTask: Task<Void, Never>?

    init(sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
         report: @escaping @MainActor ([Int64]) async -> Bool = { _ in true }) {
        self.sleep = sleep
        self.report = report
    }

    /// These ids are on screen now.
    func saw(_ ids: [Int64]) {
        for id in ids where !reported.contains(id) && !waiting.contains(id) { waiting.append(id) }
        guard !waiting.isEmpty, flushTask == nil else { return }
        let sleep = self.sleep
        flushTask = Task { [weak self] in
            do { try await sleep(Self.interval) } catch { return }
            await self?.flush()
        }
    }

    private func flush() async {
        let ids = waiting
        waiting = []
        flushTask = nil
        guard !ids.isEmpty else { return }
        reported.formUnion(ids)
        if !(await report(ids)) { reported.subtract(ids) }
    }

    /// The conversation left: what waits in the window is reported now
    /// (leaving within the second must not lose it), then nothing is
    /// remembered.
    func finish() {
        flushTask?.cancel()
        flushTask = nil
        let ids = waiting
        waiting = []
        reported = []
        guard !ids.isEmpty else { return }
        let report = self.report
        leaveTask = Task { _ = await report(ids) }
    }

    /// Tests: waits for the window open now, and the leave report, to report.
    func waitForFlush() async {
        await leaveTask?.value
        await flushTask?.value
    }
}
