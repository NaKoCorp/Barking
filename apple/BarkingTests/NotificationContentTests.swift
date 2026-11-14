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
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "salut")]), to: c, preview: .nameAndText, locked: false), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "salut", "FP1"])
    }

    func testSameContactSeveral() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP1", "Alice", "b")]), to: c, preview: .nameAndText, locked: false), "shown")
        XCTAssertEqual([c.title, c.threadIdentifier], ["Alice", "FP1"])
        XCTAssertTrue(c.body.contains("2"), c.body)
    }

    func testSeveralContacts() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP2", "Bob", "b")]), to: c, preview: .nameAndText, locked: false)
        XCTAssertEqual(c.threadIdentifier, "")
        XCTAssertEqual(c.title, "")
        XCTAssertTrue(c.body.contains("2"), c.body)
    }

    func testNothingVisibleDeliversOriginal() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([]), to: c, preview: .nameAndText, locked: false), "original")
        XCTAssertEqual(c.body, "New message")
    }

    func testNoKeyDeliversOriginal() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(nil, to: c, preview: .nameAndText, locked: false), "original")
        XCTAssertEqual(c.body, "New message")
    }

    func testLockedShowsOnlyNewMessage() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Sam", "secret")]), to: c, preview: .nameAndText, locked: true), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }

    func testLockedSeveralMessagesShowNoCountEither() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Sam", "a"), msg("FP1", "Sam", "b")]), to: c, preview: .nameAndText, locked: true)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }

    func testNameOnlyOneMessage() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "secret")]), to: c, preview: .nameOnly, locked: false), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "New message", "FP1"])
    }

    func testNameOnlySeveralOneContact() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP1", "Alice", "b"), msg("FP1", "Alice", "c")]),
                                      to: c, preview: .nameOnly, locked: false)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "3 new messages", "FP1"])
    }

    func testGenericHidesEverything() {
        let c = original()
        c.title = "x"
        c.threadIdentifier = "t"
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "secret")]), to: c, preview: .generic, locked: false), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }

    func testLockedOverridesNameAndText() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "secret")]), to: c, preview: .nameAndText, locked: true), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }

    func testNameOnlySeveralContacts() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP2", "Bob", "b")]), to: c, preview: .nameOnly, locked: false)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "2 new messages", ""])
    }

    func testGenericSeveralMessages() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP2", "Bob", "b")]), to: c, preview: .generic, locked: false)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }
}
