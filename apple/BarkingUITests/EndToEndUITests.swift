import XCTest

/// Against a real local barking-node and a barking-cli identity, on the
/// simulator only. Skipped unless the runner gets
/// TEST_RUNNER_BARKING_E2E_CARD (the CLI's card) and
/// TEST_RUNNER_BARKING_E2E_NODE (`<id>@127.0.0.1:4433`). Between the two
/// steps the CLI adds the app's card (`dev-card.txt` in the app group
/// container), sends a message and syncs; after step 2 it syncs again and
/// should list the app's reply.
@MainActor
final class EndToEndUITests: XCTestCase {
    private var env: [String: String] { ProcessInfo.processInfo.environment }

    override func setUpWithError() throws {
        continueAfterFailure = false
        try XCTSkipIf(env["BARKING_E2E_CARD"] == nil, "end-to-end environment not set")
    }

    /// Step 1: onboarding, the CLI as a contact, the local relay, a first sync.
    func test1Setup() throws {
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestOpenCard", env["BARKING_E2E_CARD"]!])
        app.launch()
        try onboard(app)
        XCTAssertTrue(app.staticTexts["Alice"].waitForExistence(timeout: 10))
        app.buttons["Add"].tap()
        app.tabBars.buttons["Network"].tap()
        app.buttons["+ Add a relay"].tap()
        let node = env["BARKING_E2E_NODE"]!.split(separator: "@").map(String.init)
        let id = app.textFields["Identifier"]
        XCTAssertTrue(id.waitForExistence(timeout: 5))
        id.tap()
        id.typeText(node[0])
        let addr = app.textFields["ip:port"]
        addr.tap()
        addr.typeText(node[1])
        app.navigationBars.buttons["Add"].tap()
        XCTAssertTrue(app.staticTexts["added by hand"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Not synced yet"].exists)
        app.buttons["Sync now"].tap()
        XCTAssertTrue(app.staticTexts["Reachable"].waitForExistence(timeout: 20))
        snap(app, "network-reachable")
    }

    /// Step 2, after the CLI wrote first: the message arrives, the reply leaves.
    func test2ReceiveAndReply() throws {
        let app = XCUIApplication()
        app.launch()
        app.tabBars.buttons["Network"].tap()
        app.buttons["Sync now"].tap()
        XCTAssertTrue(app.staticTexts["Reachable"].waitForExistence(timeout: 20))
        app.tabBars.buttons["Chats"].tap()
        openChat(app, "Alice")
        XCTAssertTrue(app.staticTexts["hello from the Mac"].waitForExistence(timeout: 30))
        // The route badge of the received message opens its path, which
        // names the local node by its 8-character short id.
        let badge = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Internet")).firstMatch
        XCTAssertTrue(badge.waitForExistence(timeout: 10), "no route badge on the received message")
        badge.tap()
        let shortId = String(env["BARKING_E2E_NODE"]!.split(separator: "@")[0].prefix(8))
        let relay = app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", shortId)).firstMatch
        XCTAssertTrue(relay.waitForExistence(timeout: 10), "the path does not show the node \(shortId)")
        snap(app, "path-received")
        app.navigationBars.buttons.firstMatch.tap()
        let field = app.textFields["Message"]
        field.tap()
        field.typeText("hello from iPhone")
        app.buttons["Send"].tap()
        XCTAssertTrue(app.staticTexts["hello from iPhone"].waitForExistence(timeout: 5))
        let sent = app.descendants(matching: .any).matching(NSPredicate(format: "label IN %@", ["sent", "delivered"]))
        XCTAssertTrue(sent.firstMatch.waitForExistence(timeout: 30))
        snap(app, "conversation")
    }

    private func snap(_ app: XCUIApplication, _ name: String) {
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
    }
}

/// Taps the chats row of `name` (VoiceOver merges the row into one button).
@MainActor
func openChat(_ app: XCUIApplication, _ name: String) {
    let row = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", name)).firstMatch
    if !row.waitForExistence(timeout: 10) { print("TREE>>>\n\(app.debugDescription)\n<<<TREE") }
    XCTAssertTrue(row.exists, "no chat row for \(name)")
    row.tap()
}
