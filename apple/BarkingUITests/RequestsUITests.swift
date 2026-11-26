import XCTest

/// Contact requests in the chats (`-BarkingUITestRequests`): “Alice” in the
/// list, “Bob” hidden and new behind the Invitations entry.
@MainActor
final class RequestsUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    private func launch() -> XCUIApplication {
        let app = XCUIApplication.seeded(extra: ["-BarkingUITestRequests"])
        app.launch()
        return app
    }

    /// The row reads as an invitation, never as a chat. Task 5 adds: a tap
    /// opens the request page and its safety code.
    func testRequestRowShowsTagAndOpens() throws {
        let app = launch()
        let row = app.buttons["chats.request.a11ce000"]
        XCTAssertTrue(row.waitForExistence(timeout: 10), "Alice's request row")
        XCTAssertTrue(row.label.contains("Alice"), row.label)
        XCTAssertTrue(row.label.contains("Invitation"), row.label)
        XCTAssertFalse(app.buttons["chats.request.b0b00000"].exists, "a hidden request stays out of the list")
    }

    /// The entry counts the hidden request and says one is new; the screen
    /// shows it under Hidden; coming back, it is new no more.
    func testInvitationsEntryCountsHidden() throws {
        let app = launch()
        let entry = app.buttons["chats.invitations"]
        XCTAssertTrue(entry.waitForExistence(timeout: 10))
        XCTAssertTrue(entry.label.contains("1"), entry.label)
        XCTAssertTrue((entry.value as? String ?? "").contains("new"), "\(String(describing: entry.value))")
        entry.tap()

        let bob = app.buttons["invitations.row.b0b00000"]
        XCTAssertTrue(bob.waitForExistence(timeout: 5))
        XCTAssertTrue(bob.label.contains("Bob"), bob.label)
        let hidden = app.staticTexts["Hidden"]
        XCTAssertTrue(hidden.exists, "the Hidden section")
        XCTAssertLessThan(hidden.frame.minY, bob.frame.minY, "Bob is under Hidden")
        XCTAssertTrue(app.buttons["invitations.row.a11ce000"].exists, "the visible request is listed too")

        app.navigationBars.buttons.element(boundBy: 0).tap()
        XCTAssertTrue(entry.waitForExistence(timeout: 5))
        XCTAssertTrue(entry.waitUntil({ !(($0.value as? String) ?? "").contains("new") }),
                      "the new dot is gone: \(String(describing: entry.value))")
    }
}
