import XCTest
@testable import Barking
@testable import BarkingKit

/// A wait the test ends by hand: every `wait` returns once `open` is called
/// (and throws once cancelled before that).
private actor Gate {
    private(set) var waits: [Duration] = []
    private var pending: [CheckedContinuation<Void, Error>] = []

    func wait(_ d: Duration) async throws {
        waits.append(d)
        try await withCheckedThrowingContinuation { pending.append($0) }
    }

    func open() {
        let all = pending
        pending = []
        for c in all { c.resume() }
    }

    func waiting() -> Int { pending.count }
}

/// Disappearing messages on screen (spec iOS deletion/ephemeral §5.3, §5.5):
/// the countdown's label, the seen reports, the expiry timer, the Details.
@MainActor
final class EphemeralDisplayTests: XCTestCase {
    private let fr = (bundle: Bundle.strings(for: Locale(identifier: "fr")), locale: Locale(identifier: "fr"))
    private let en = (bundle: Bundle.strings(for: Locale(identifier: "en")), locale: Locale(identifier: "en"))
    private let t0: UInt64 = 1_800_000_000

    private func make(_ d: FakeDevice, now: UInt64? = nil) -> ConversationModel {
        d.contactList = [Contact(fingerprint: "b", alias: nil, displayName: "Bob", verified: false)]
        let m = ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
        let at = TimeInterval(now ?? t0)
        m.now = { Date(timeIntervalSince1970: at) }
        return m
    }

    private func waitUntil(_ condition: () async -> Bool) async throws {
        for _ in 0..<200 {
            if await condition() { return }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTFail("condition never met")
    }

    // MARK: Countdown

    func testRemainingLabel() {
        let label = { (s: Int) in remainingLabel(seconds: s, bundle: self.en.bundle, locale: self.en.locale) }
        XCTAssertEqual(label(30), "<1 min")
        XCTAssertEqual(label(0), "<1 min")
        XCTAssertEqual(label(-4), "<1 min")
        XCTAssertEqual(label(60), "1 min")
        XCTAssertEqual(label(61), "2 min")
        XCTAssertEqual(label(3599), "60 min")
        XCTAssertEqual(label(3600), "1 h")
        XCTAssertEqual(label(3601), "2 h")
        XCTAssertEqual(label(86_400), "1 d")
        XCTAssertEqual(label(90_000), "2 d")
        XCTAssertEqual(remainingLabel(seconds: 90_000, bundle: fr.bundle, locale: fr.locale), "2\u{00A0}j", "a no-break space, as the picker")
        XCTAssertEqual(remainingLabel(seconds: 30, bundle: fr.bundle, locale: fr.locale), "<1\u{00A0}min")
    }

    /// Before it is seen, the full delay is left: `expireAt` is then only
    /// the 7-day ceiling.
    func testRemainingCountsFromSeenOnly() async {
        let d = FakeDevice()
        d.messageList = ["b": [
            Message(id: 1, outgoing: false, body: "a", at: t0, ttlSecs: 300, expireAt: t0 + 604_800),
            Message(id: 2, outgoing: false, body: "b", at: t0, ttlSecs: 300, seenAt: t0 - 100, expireAt: t0 + 200),
            Message(id: 3, outgoing: false, body: "c", at: t0),
        ]]
        let m = make(d)
        await m.reload()
        let now = Date(timeIntervalSince1970: TimeInterval(t0))
        XCTAssertEqual(m.items.map { $0.remaining(at: now) }, [300, 200, nil])
    }

    /// VoiceOver adds the disappearing part after the bubble's value.
    func testSpokenBubbleSaysItDisappears() async {
        let d = FakeDevice()
        d.messageList = ["b": [Message(id: 2, outgoing: false, body: "b", at: t0, ttlSecs: 300, seenAt: t0,
                                       expireAt: t0 + 240)]]
        let m = make(d)
        await m.reload()
        let item = m.items[0]
        let now = Date(timeIntervalSince1970: TimeInterval(t0))
        XCTAssertTrue(ConversationView.spoken(item, now: now, bundle: en.bundle, locale: en.locale)
            .hasSuffix(", disappearing message, disappears in 4 min"))
        XCTAssertTrue(ConversationView.spoken(item, now: now, bundle: fr.bundle, locale: fr.locale)
            .hasSuffix(", message éphémère, s’efface dans 4\u{00A0}min"))
    }

    // MARK: Seen

    func testSeenTrackerThrottles() async throws {
        let gate = Gate()
        var calls: [[Int64]] = []
        let tracker = SeenTracker(sleep: { try await gate.wait($0) }) { calls.append($0); return true }
        tracker.saw([1])
        tracker.saw([2])
        tracker.saw([3, 1])
        try await waitUntil { await gate.waiting() == 1 }
        XCTAssertEqual(calls, [], "nothing before the second is over")
        let waits = await gate.waits
        XCTAssertEqual(waits, [SeenTracker.interval])
        await gate.open()
        await tracker.waitForFlush()
        XCTAssertEqual(calls, [[1, 2, 3]])
        tracker.saw([2, 3])
        XCTAssertNil(tracker.flushTask, "an id is reported once")
    }

    /// A failed report is tried again at the next sighting.
    func testSeenTrackerForgetsAFailedReport() async throws {
        let gate = Gate()
        var calls: [[Int64]] = []
        var ok = false
        let tracker = SeenTracker(sleep: { try await gate.wait($0) }) { calls.append($0); return ok }
        tracker.saw([1])
        try await waitUntil { await gate.waiting() == 1 }
        await gate.open()
        await tracker.waitForFlush()
        ok = true
        tracker.saw([1])
        try await waitUntil { await gate.waiting() == 1 }
        await gate.open()
        await tracker.waitForFlush()
        XCTAssertEqual(calls, [[1], [1]])
    }

    /// Only visible ephemerals not seen yet are reported, and only while the
    /// app is active and its lock screen is not up.
    func testModelReportsOnlyUnseenVisibleEphemerals() async throws {
        let d = FakeDevice()
        d.messageList = ["b": [
            Message(id: 1, outgoing: false, body: "plain", at: t0),
            Message(id: 2, outgoing: false, body: "new", at: t0, ttlSecs: 300, expireAt: t0 + 604_800),
            Message(id: 3, outgoing: false, body: "seen", at: t0, ttlSecs: 300, seenAt: t0, expireAt: t0 + 300),
            Message(id: 4, outgoing: false, body: "off", at: t0, ttlSecs: 300, expireAt: t0 + 604_800),
        ]]
        let gate = Gate()
        let m = make(d)
        m.seenSleep = { try await gate.wait($0) }
        await m.onAppear()
        for id: Int64 in [1, 2, 3] { m.bubbleVisibility(id, shown: true) }
        m.covered = true
        await m.phaseChanged(active: true)
        try await Task.sleep(for: .milliseconds(20))
        let none = await gate.waiting()
        XCTAssertEqual(none, 0, "nothing is seen under the lock screen")
        m.covered = false
        try await waitUntil { await gate.waiting() == 1 }
        await gate.open()
        await m.seen.waitForFlush()
        XCTAssertEqual(d.seen, [[2]])
    }

    func testNothingIsSeenInTheBackground() async throws {
        let d = FakeDevice()
        d.messageList = ["b": [Message(id: 2, outgoing: false, body: "new", at: t0, ttlSecs: 300,
                                       expireAt: t0 + 604_800)]]
        let gate = Gate()
        let m = make(d)
        m.seenSleep = { try await gate.wait($0) }
        await m.onAppear()
        await m.phaseChanged(active: false)
        m.bubbleVisibility(2, shown: true)
        try await Task.sleep(for: .milliseconds(20))
        let none = await gate.waiting()
        XCTAssertEqual(none, 0)
        await m.phaseChanged(active: true)
        try await waitUntil { await gate.waiting() == 1 }
    }

    // MARK: Timer

    /// Active: expires what is due, reloads, then sleeps until the next
    /// expiry and erases again.
    func testTimerExpiresAtNextExpiryAndReloads() async throws {
        let d = FakeDevice()
        d.messageList = ["b": [Message(id: 2, outgoing: false, body: "bye", at: t0, ttlSecs: 60, seenAt: t0 - 55,
                                       expireAt: t0 + 5)]]
        d.nextExpiryValue = t0 + 5
        let gate = Gate()
        let m = make(d)
        m.expirySleep = { try await gate.wait($0) }
        await m.onAppear()
        await m.phaseChanged(active: true)
        XCTAssertEqual(d.expireCalls, 1, "on becoming active")
        try await waitUntil { await gate.waiting() == 1 }
        let waits = await gate.waits
        XCTAssertEqual(waits, [.seconds(5)])
        XCTAssertEqual(m.items.map(\.id), [2])
        d.messageList = [:]
        d.nextExpiryValue = nil
        d.expiring = [2]
        await gate.open()
        try await waitUntil { m.items.isEmpty }
        XCTAssertEqual(d.expireCalls, 2)
    }

    /// A due time already past waits a second rather than spinning.
    func testPastExpiryWaitsASecond() async throws {
        let d = FakeDevice()
        d.nextExpiryValue = t0 - 3
        let gate = Gate()
        let m = make(d)
        m.expirySleep = { try await gate.wait($0) }
        await m.onAppear()
        await m.phaseChanged(active: true)
        try await waitUntil { await gate.waiting() == 1 }
        let waits = await gate.waits
        XCTAssertEqual(waits, [.seconds(1)])
    }

    func testTimerStopsInTheBackgroundAndOnDisappear() async throws {
        let d = FakeDevice()
        d.nextExpiryValue = t0 + 30
        let gate = Gate()
        let m = make(d)
        m.expirySleep = { try await gate.wait($0) }
        await m.onAppear()
        await m.phaseChanged(active: true)
        try await waitUntil { await gate.waiting() == 1 }
        await m.phaseChanged(active: false)
        XCTAssertNil(m.expiryTimer)
        await m.phaseChanged(active: true)
        try await waitUntil { m.expiryTimer != nil }
        m.onDisappear()
        XCTAssertNil(m.expiryTimer)
    }

    /// A sync that erased rows of this conversation reloads it.
    func testExpiredChangeReloads() async {
        let d = FakeDevice()
        d.messageList = ["b": [Message(id: 2, outgoing: false, body: "bye", at: t0, ttlSecs: 60)]]
        let m = make(d)
        await m.onAppear()
        d.messageList = [:]
        await m.handle(.expired(ids: [99]))
        XCTAssertEqual(m.items.map(\.id), [2], "another conversation's rows")
        await m.handle(.expired(ids: [2]))
        XCTAssertTrue(m.items.isEmpty)
    }

    // MARK: Core

    func testCorePublishesExpiredRows() async throws {
        let d = FakeDevice()
        let core = CoreService(device: d, runner: DirectRunner())
        let changes = await core.changes
        d.expiring = [4, 5]
        let erased = try await core.expireEphemeral()
        XCTAssertEqual(erased, [4, 5])
        d.summary = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: true, error: nil, expired: [6])
        let outcome = await core.sync(reason: .pull)
        XCTAssertEqual(outcome.expired, [6])
        var got: [CoreChange] = []
        for await c in changes {
            if case .expired = c { got.append(c) }
            if got.count == 2 { break }
        }
        XCTAssertEqual(got, [.expired(ids: [4, 5]), .expired(ids: [6])])
        try await core.markSeen([7])
        XCTAssertEqual(d.seen, [[7]])
        d.nextExpiryValue = 42
        let next = try await core.nextExpiry()
        XCTAssertEqual(next, 42)
    }

    // MARK: Details

    func testDetailsShowDelayAndEraseTime() async throws {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "b", alias: nil, displayName: "Bob", verified: false)]
        d.messageList = ["b": [Message(id: 7, outgoing: false, body: "x", at: t0, ttlSecs: 300,
                                       expireAt: t0 + 604_800)]]
        let core = CoreService(device: d, runner: DirectRunner())
        let m = MessageSheetModel(core: core, messageId: 7, contact: "b", contactName: "Bob")
        await m.load()
        let utc = TimeZone(identifier: "UTC")!
        let now = Date(timeIntervalSince1970: TimeInterval(t0))
        var rows = try XCTUnwrap(m.ephemeralDetails(now: now, bundle: en.bundle, locale: en.locale, timeZone: utc))
        XCTAssertEqual(rows.delay, EphemeralDetails.Row(title: "Disappears after", value: "5 min"))
        XCTAssertEqual(rows.erase, EphemeralDetails.Row(title: "Erased at", value: "After reading"))
        rows = try XCTUnwrap(m.ephemeralDetails(now: now, bundle: fr.bundle, locale: fr.locale, timeZone: utc))
        XCTAssertEqual(rows.delay, EphemeralDetails.Row(title: "S’efface après", value: "5\u{00A0}min"))
        XCTAssertEqual(rows.erase, EphemeralDetails.Row(title: "Effacé à", value: "Après lecture"))

        d.messageList = ["b": [Message(id: 7, outgoing: false, body: "x", at: t0, ttlSecs: 300, seenAt: t0,
                                       expireAt: t0 + 300)]]
        await m.load()
        rows = try XCTUnwrap(m.ephemeralDetails(now: now, bundle: en.bundle, locale: en.locale, timeZone: utc))
        var style = Date.FormatStyle(locale: en.locale, timeZone: utc).hour().minute()
        style.timeZone = utc
        XCTAssertEqual(rows.erase.value, Date(timeIntervalSince1970: TimeInterval(t0 + 300)).formatted(style))

        d.messageList = ["b": [Message(id: 7, outgoing: false, body: "x", at: t0)]]
        await m.load()
        XCTAssertNil(m.ephemeralDetails(now: now, bundle: en.bundle, locale: en.locale, timeZone: utc))
    }

    func testSheetClosesWhenItsMessageExpires() async {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "b", alias: nil, displayName: "Bob", verified: false)]
        d.messageList = ["b": [Message(id: 7, outgoing: false, body: "x", at: t0, ttlSecs: 60)]]
        let m = MessageSheetModel(core: CoreService(device: d, runner: DirectRunner()), messageId: 7,
                                  contact: "b", contactName: "Bob")
        await m.load()
        await m.handle(.expired(ids: [8]))
        XCTAssertNil(m.exit)
        await m.handle(.expired(ids: [7]))
        XCTAssertEqual(m.exit, .removedElsewhere)
    }

    // MARK: Leaving and the app-level timer

    /// Leaving within the second still reports what was seen.
    func testSeenTrackerReportsOnLeave() async throws {
        let gate = Gate()
        var calls: [[Int64]] = []
        let tracker = SeenTracker(sleep: { try await gate.wait($0) }) { calls.append($0); return true }
        tracker.saw([1, 2])
        try await waitUntil { await gate.waiting() == 1 }
        tracker.finish()
        await tracker.waitForFlush()
        XCTAssertEqual(calls, [[1, 2]], "at once, without waiting out the window")
    }

    func testLeavingTheConversationMarksSeen() async throws {
        let d = FakeDevice()
        d.messageList = ["b": [Message(id: 2, outgoing: false, body: "new", at: t0, ttlSecs: 300,
                                       expireAt: t0 + 604_800)]]
        let gate = Gate()
        let m = make(d)
        m.seenSleep = { try await gate.wait($0) }
        await m.onAppear()
        await m.phaseChanged(active: true)
        m.bubbleVisibility(2, shown: true)
        try await waitUntil { await gate.waiting() == 1 }
        m.onDisappear()
        await m.seen.waitForFlush()
        XCTAssertEqual(d.seen, [[2]])
    }

    /// Whatever the screen: active, it expires, sleeps to the next expiry,
    /// expires again and re-arms; inactive, nothing waits.
    func testAppExpiryTimer() async throws {
        let gate = Gate()
        var due: UInt64? = t0 + 30
        var expired = 0
        let timer = ExpiryTimer(nextExpiry: { due }, expire: { expired += 1 }, sleep: { try await gate.wait($0) })
        let at = TimeInterval(t0)
        timer.now = { Date(timeIntervalSince1970: at) }
        await timer.arm()
        XCTAssertNil(timer.task, "not armed before the app is active")
        await timer.phaseChanged(active: true)
        XCTAssertEqual(expired, 1)
        try await waitUntil { await gate.waiting() == 1 }
        var waits = await gate.waits
        XCTAssertEqual(waits, [.seconds(30)])
        due = nil
        await gate.open()
        try await waitUntil { expired == 2 }
        try await waitUntil { timer.task == nil }
        due = t0 - 2
        await timer.arm()
        try await waitUntil { await gate.waiting() == 1 }
        waits = await gate.waits
        XCTAssertEqual(waits.last, ExpiryTimer.pastDueWait)
        await timer.phaseChanged(active: false)
        XCTAssertNil(timer.task)
        await timer.arm()
        XCTAssertNil(timer.task, "inactive: nothing waits")
        XCTAssertEqual(expired, 2)
    }
}
