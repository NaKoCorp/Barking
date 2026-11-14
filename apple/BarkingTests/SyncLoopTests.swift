import BarkingKit
import SwiftUI
import XCTest
@testable import Barking

/// The foreground sync loop (spec iOS messaging §4.2): a sync when the app
/// comes to the front, then one every 15 s with a conversation open, 60 s
/// otherwise; nothing in the background.
@MainActor
final class SyncLoopTests: XCTestCase {
    /// Records the syncs and the waits; a wait ends when the test ticks it,
    /// or throws when the loop's task is cancelled.
    private actor Clock {
        private(set) var reasons: [SyncReason] = []
        private(set) var waits: [Duration] = []
        private var waiting: CheckedContinuation<Void, Error>?

        private(set) var events: [String] = []

        func synced(_ r: SyncReason) { reasons.append(r); events.append("sync(\(r))") }
        func applied() { events.append("apply") }

        func wait(_ d: Duration) async throws {
            waits.append(d)
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { waiting = $0 }
            } onCancel: {
                Task { await self.cancelWait() }
            }
        }

        private func cancelWait() {
            waiting?.resume(throwing: CancellationError())
            waiting = nil
        }

        /// Ends the current wait; false when nothing waits.
        @discardableResult
        func tick() -> Bool {
            guard let w = waiting else { return false }
            waiting = nil
            w.resume()
            return true
        }

        var isWaiting: Bool { waiting != nil }
        func waiting(afterSyncs n: Int) -> Bool { reasons.count == n && waiting != nil }
        func waiting(afterWaits n: Int) -> Bool { waits.count == n && waiting != nil }
    }

    private func makeLoop() -> (SyncLoop, Clock) {
        let clock = Clock()
        let loop = SyncLoop(sync: { await clock.synced($0) }, sleep: { try await clock.wait($0) })
        return (loop, clock)
    }

    /// Polls until `condition` holds (the loop runs on its own task). A wall
    /// clock deadline, not a number of polls: on a loaded CI runner a 5 ms
    /// sleep can last much longer, and the loop's task may wait its turn.
    private func until(_ condition: @escaping () async -> Bool, _ message: String,
                       timeout: Duration = .seconds(10),
                       file: StaticString = #filePath, line: UInt = #line) async {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            if await condition() { return }
            try? await Task.sleep(for: .milliseconds(5))
        }
        if await condition() { return }
        XCTFail("timed out: \(message)", file: file, line: line)
    }

    func testFirstActiveSyncsForTheLaunchThenEveryMinute() async {
        let (loop, clock) = makeLoop()
        loop.scenePhaseChanged(to: .active)
        await until({ await clock.isWaiting }, "first wait")
        let firstReasons = await clock.reasons
        XCTAssertEqual(firstReasons, [.launch])
        let firstWaits = await clock.waits
        XCTAssertEqual(firstWaits, [.seconds(60)])
        await clock.tick()
        await until({ await clock.waiting(afterSyncs: 2) }, "timer sync")
        let reasons = await clock.reasons
        XCTAssertEqual(reasons, [.launch, .timer])
        loop.stop()
    }

    func testForegroundAppliesGuardBeforeSync() async {
        let clock = Clock()
        let loop = SyncLoop(sync: { await clock.synced($0) }, sleep: { try await clock.wait($0) },
                            beforeForeground: { await clock.applied() })
        loop.scenePhaseChanged(to: .active)   // launch: the guard runs before its sync too
        await until({ await clock.isWaiting }, "launch wait")
        loop.scenePhaseChanged(to: .background)
        loop.scenePhaseChanged(to: .active)
        await until({ await clock.waiting(afterSyncs: 2) }, "foreground sync")
        let events = await clock.events
        XCTAssertEqual(events, ["apply", "sync(launch)", "apply", "sync(foreground)"])
        loop.stop()
    }

    /// The scene lifecycle never calls `applicationDidEnterBackground`: the
    /// next background refresh is asked for when the scene goes to the background.
    func testBackgroundPhaseSchedulesTheRefreshOnce() async {
        let clock = Clock()
        var scheduled = 0
        let loop = SyncLoop(sync: { await clock.synced($0) }, sleep: { try await clock.wait($0) },
                            onBackground: { scheduled += 1 })
        loop.scenePhaseChanged(to: .active)
        await until({ await clock.isWaiting }, "first wait")
        loop.scenePhaseChanged(to: .inactive)
        XCTAssertEqual(scheduled, 0, "inactive schedules nothing")
        loop.scenePhaseChanged(to: .background)
        XCTAssertEqual(scheduled, 1)
        loop.stop()
    }

    func testAnOpenConversationSyncsEvery15Seconds() async {
        let (loop, clock) = makeLoop()
        loop.conversationOpen = true
        loop.scenePhaseChanged(to: .active)
        await until({ await clock.isWaiting }, "first wait")
        let waits = await clock.waits
        XCTAssertEqual(waits, [.seconds(15)])
        loop.stop()
    }

    /// Opening a conversation during a 60 s wait starts a 15 s one, with no
    /// extra sync; closing it goes back to 60 s.
    func testOpeningAConversationShortensTheWait() async {
        let (loop, clock) = makeLoop()
        loop.scenePhaseChanged(to: .active)
        await until({ await clock.isWaiting }, "first wait")
        loop.conversationOpen = true
        await until({ await clock.waiting(afterWaits: 2) }, "15 s wait")
        loop.conversationOpen = false
        await until({ await clock.waiting(afterWaits: 3) }, "60 s wait")
        let waits = await clock.waits
        XCTAssertEqual(waits, [.seconds(60), .seconds(15), .seconds(60)])
        let reasons = await clock.reasons
        XCTAssertEqual(reasons, [.launch])
        loop.stop()
    }

    /// The background stops it; coming back syncs at once, as a foreground.
    func testBackgroundStopsAndForegroundSyncsAgain() async {
        let (loop, clock) = makeLoop()
        loop.scenePhaseChanged(to: .active)
        await until({ await clock.isWaiting }, "first wait")
        loop.scenePhaseChanged(to: .background)
        XCTAssertFalse(loop.isRunning)
        await until({ await !clock.isWaiting }, "wait cancelled")
        loop.scenePhaseChanged(to: .inactive)
        XCTAssertFalse(loop.isRunning, "inactive starts nothing")
        loop.scenePhaseChanged(to: .active)
        await until({ await clock.waiting(afterSyncs: 2) }, "foreground sync")
        let reasons = await clock.reasons
        XCTAssertEqual(reasons, [.launch, .foreground])
        loop.stop()
    }

    /// Inactive (a call, the app switcher) keeps the loop as it is.
    func testInactiveKeepsTheLoop() async {
        let (loop, clock) = makeLoop()
        loop.scenePhaseChanged(to: .active)
        await until({ await clock.isWaiting }, "first wait")
        loop.scenePhaseChanged(to: .inactive)
        XCTAssertTrue(loop.isRunning)
        loop.scenePhaseChanged(to: .active)
        let reasons = await clock.reasons
        XCTAssertEqual(reasons, [.launch], "active again after inactive: no second sync")
        loop.stop()
    }
}
