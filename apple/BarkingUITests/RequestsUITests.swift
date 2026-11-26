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

    /// The row reads as an invitation, never as a chat; a tap opens the
    /// request page and its safety code.
    func testRequestRowShowsTagAndOpens() throws {
        let app = launch()
        let row = app.buttons["chats.request.a11ce000"]
        XCTAssertTrue(row.waitForExistence(timeout: 10), "Alice's request row")
        XCTAssertTrue(row.label.contains("Alice"), row.label)
        XCTAssertTrue(row.label.contains("Invitation"), row.label)
        XCTAssertFalse(app.buttons["chats.request.b0b00000"].exists, "a hidden request stays out of the list")

        row.tap()
        XCTAssertTrue(app.staticTexts["Safety code"].waitForExistence(timeout: 5), "the request page")
        let code = app.descendants(matching: .any)["contact.safetyCode"]
        XCTAssertTrue(code.exists, "the safety code grid")
        XCTAssertTrue(code.label.contains("12345"), code.label)
        XCTAssertTrue(app.buttons["request.accept"].exists)
    }

    /// Accepting replaces the page with the new contact's conversation,
    /// which says it is not verified; back, the request is gone from the list.
    func testAcceptOpensConversation() throws {
        let app = launch()
        let row = app.buttons["chats.request.a11ce000"]
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.tap()
        let accept = app.buttons["request.accept"]
        XCTAssertTrue(accept.waitForExistence(timeout: 5))
        accept.tap()

        XCTAssertTrue(app.descendants(matching: .any)["conversation.unverified"].waitForExistence(timeout: 10),
                      "the conversation's not verified banner")
        XCTAssertFalse(app.buttons["request.accept"].exists, "the request page is gone")
        app.navigationBars.buttons.element(boundBy: 0).tap()
        XCTAssertTrue(app.buttons["chats.invitations"].waitForExistence(timeout: 5), "back on the chats")
        XCTAssertTrue(row.waitUntil({ !$0.exists }), "the request row left the list")
    }

    /// Refusing asks first; confirmed, it goes back to a list without the row.
    func testRefuseAsksConfirmation() throws {
        let app = launch()
        let row = app.buttons["chats.request.a11ce000"]
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.tap()
        let refuse = app.buttons["request.refuse"]
        XCTAssertTrue(refuse.waitForExistence(timeout: 5))
        refuse.tap()

        let confirm = app.buttons["request.refuse.confirm"].firstMatch
        XCTAssertTrue(confirm.waitForExistence(timeout: 5), "a confirmation, not an immediate refusal")
        confirm.tap()

        XCTAssertTrue(app.buttons["chats.invitations"].waitForExistence(timeout: 5), "back on the chats")
        XCTAssertTrue(row.waitUntil({ !$0.exists }), "the request row left the list")
        XCTAssertFalse(app.buttons["request.refuse"].exists)
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

    /// A contact who changed device: its conversation says so in a quiet
    /// line, built in the app's language (§7.7).
    func testChangedDeviceLine() throws {
        let app = XCUIApplication.seeded(extra: ["-BarkingUITestDeviceChanged"])
        app.launch()
        let sam = app.staticTexts["Sam"].firstMatch
        XCTAssertTrue(sam.waitForExistence(timeout: 10))
        sam.tap()
        let line = app.staticTexts["conversation.deviceChanged"]
        XCTAssertTrue(line.waitForExistence(timeout: 10), "the changed-device line")
        XCTAssertTrue(line.label.hasPrefix("Sam changed device · "), line.label)
    }
}
