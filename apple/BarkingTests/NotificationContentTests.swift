import UserNotifications
import XCTest
@testable import BarkingKit

final class NotificationContentTests: XCTestCase {
    func msg(_ c: String, _ n: String, _ t: String) -> NewMessage { NewMessage(contact: c, name: n, text: t) }
    func summary(_ m: [NewMessage]) -> SyncSummary {
        SyncSummary(itemsReceived: UInt32(m.count), sent: 0, newMessages: m, networkUp: true, error: nil)
    }
    func original() -> UNMutableNotificationContent {
        let c = UNMutableNotificationContent()
        c.body = "New message"
        return c
    }

    func testOneMessage() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "salut")]), to: c, locked: false), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "salut", "FP1"])
    }

    func testSameContactSeveral() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP1", "Alice", "b")]), to: c, locked: false), "shown")
        XCTAssertEqual([c.title, c.threadIdentifier], ["Alice", "FP1"])
        XCTAssertTrue(c.body.contains("2"), c.body)
    }

    func testSeveralContacts() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP2", "Bob", "b")]), to: c, locked: false)
        XCTAssertEqual(c.threadIdentifier, "")
        XCTAssertEqual(c.title, "")
        XCTAssertTrue(c.body.contains("2"), c.body)
    }

    func testNothingVisibleDeliversOriginal() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([]), to: c, locked: false), "original")
        XCTAssertEqual(c.body, "New message")
    }

    func testNoKeyDeliversOriginal() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(nil, to: c, locked: false), "original")
        XCTAssertEqual(c.body, "New message")
    }

    func testLockedShowsOnlyNewMessage() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Sam", "secret")]), to: c, locked: true), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }

    func testLockedSeveralMessagesShowNoCountEither() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Sam", "a"), msg("FP1", "Sam", "b")]), to: c, locked: true)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }
}
