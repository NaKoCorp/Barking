import BackgroundTasks
import UserNotifications
import XCTest
@testable import Barking
@testable import BarkingKit

/// The background refresh (spec iOS push §5.6): a full sync, then local
/// notifications for what is new, with the extension's preview and lock rules.
@MainActor
final class BackgroundRefreshTests: XCTestCase {
    private func alice(_ n: Int) -> [NewMessage] {
        (0..<n).map { NewMessage(contact: "fp-alice", name: "Alice", text: "hi \($0)") }
    }

    private func service(_ messages: [NewMessage], preview: PushPreview = .nameAndText,
                         networkUp: Bool = true) -> (CoreService, FakeDevice) {
        let d = FakeDevice()
        d.summary = SyncSummary(itemsReceived: UInt32(messages.count), sent: 0, newMessages: messages,
                                networkUp: networkUp, error: nil)
        d.prefs.preview = preview
        return (CoreService(device: d, runner: DirectRunner()), d)
    }

    private func run(_ core: CoreService?, locked: Bool = false) async -> (Bool, [UNNotificationRequest]) {
        var posted: [UNNotificationRequest] = []
        let ok = await BackgroundRefresh.run(service: core, locked: locked) { posted.append($0) }
        return (ok, posted)
    }

    func testRunWithoutServiceDoesNothing() async {
        let (ok, posted) = await run(nil)
        XCTAssertFalse(ok)
        XCTAssertTrue(posted.isEmpty)
    }

    func testRunPostsOneLocalNotification() async {
        let (core, d) = service(alice(2))
        let (ok, posted) = await run(core)
        XCTAssertTrue(ok)
        XCTAssertEqual(posted.count, 1)
        XCTAssertEqual(posted.first?.content.title, "Alice")
        XCTAssertEqual(posted.first?.content.body, "2 new messages")
        XCTAssertEqual(d.syncCalls, 1)
    }

    func testRunLockedHidesContent() async {
        let (core, _) = service(alice(2))
        let (_, posted) = await run(core, locked: true)
        XCTAssertEqual(posted.count, 1)
        XCTAssertEqual(posted.first?.content.body, "New message")
        XCTAssertEqual(posted.first?.content.title, "")
    }

    func testRunNoNewMessagesPostsNothing() async {
        let (core, _) = service([])
        let (ok, posted) = await run(core)
        XCTAssertTrue(ok)
        XCTAssertTrue(posted.isEmpty)
    }

    func testRequestAsksInOneHour() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let request = BackgroundRefresh.request(now: now)
        XCTAssertEqual(request.identifier, "com.nakocorp.barking.refresh")
        XCTAssertEqual(request.earliestBeginDate, now.addingTimeInterval(3600))
    }
}
