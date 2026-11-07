import XCTest

/// Delivery states on screen (spec Lot M §10, "App, interface"): the
/// `deliveries` seed sends four real messages to Sam and the app shows them
/// Not delivered, Received on 1 of 2 devices, On the network and Pending
/// (§6.8). Deletions and retries reach the real core; nothing needs the network.
@MainActor
final class DeliveryUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    // MARK: Helpers

    /// The app on Sam's conversation, the four messages shown.
    private func openDeliveries(file: StaticString = #filePath, line: UInt = #line) -> XCUIApplication {
        let app = XCUIApplication.seeded("deliveries")
        app.launch()
        openSamChat(app, file: file, line: line)
        XCTAssertTrue(bubble(app, Seeded.pending).waitForExistence(timeout: 10), "the seeded messages", file: file, line: line)
        return app
    }

    private func bubble(_ app: XCUIApplication, _ text: String) -> XCUIElement {
        app.staticTexts[text].firstMatch
    }

    private func value(_ e: XCUIElement) -> String { e.value as? String ?? "" }

    /// An element whose label contains `text` (combined rows, timeline steps).
    private func any(_ app: XCUIApplication, containing text: String) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", text)).firstMatch
    }

    private func buttons(_ app: XCUIApplication, _ label: String) -> Int {
        app.buttons.matching(NSPredicate(format: "label == %@", label)).count
    }

    /// Opens the long-press menu of a bubble; returns once its items show.
    private func menu(_ app: XCUIApplication, of text: String) {
        bubble(app, text).press(forDuration: 1.0)
        XCTAssertTrue(app.buttons["Details"].waitForExistence(timeout: 5), "the menu of \(text)")
    }

    /// Closes the menu by a tap beside it.
    private func closeMenu(_ app: XCUIApplication) {
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.04, dy: 0.5)).tap()
        XCTAssertTrue(app.buttons["Details"].waitUntil({ !$0.exists }, timeout: 5), "the menu closes")
    }

    /// Deletes a bubble from its menu after checking the confirmation's text.
    private func deleteFromMenu(_ app: XCUIApplication, _ text: String, says message: String, button: String,
                                file: StaticString = #filePath, line: UInt = #line) {
        menu(app, of: text)
        app.buttons["Delete"].firstMatch.tap()
        XCTAssertTrue(app.staticTexts[message].waitForExistence(timeout: 5), "confirmation of \(text)", file: file, line: line)
        // §14.1: a message that left is never said not to arrive.
        if !message.contains("won’t receive") {
            XCTAssertEqual(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "won’t receive")).count, 0,
                           "\(text) left: no \"won’t receive\"", file: file, line: line)
        }
        app.buttons[button].firstMatch.tap()
        XCTAssertTrue(bubble(app, text).waitUntil({ !$0.exists }), "the bubble of \(text) leaves", file: file, line: line)
    }

    // MARK: Conversation (§6.3)

    /// Each bubble speaks its state as its value (§7.1, §8), and only the
    /// not delivered one has a Retry under it.
    func testEachBubbleSpeaksItsState() throws {
        let app = openDeliveries()
        XCTAssertTrue(value(bubble(app, Seeded.pending)).hasPrefix("Pending since "), value(bubble(app, Seeded.pending)))
        XCTAssertTrue(value(bubble(app, Seeded.onNetwork)).hasPrefix("On the network since "),
                      value(bubble(app, Seeded.onNetwork)))
        let received = value(bubble(app, Seeded.received))
        XCTAssertTrue(received.hasPrefix("Received at ") && received.hasSuffix(", on 1 of 2 devices"), received)
        let failed = value(bubble(app, Seeded.notDelivered))
        XCTAssertTrue(failed.hasPrefix("Not delivered. Expired at "), failed)
        XCTAssertEqual(buttons(app, "Retry"), 1, "Retry only under the not delivered message")
    }

    /// The long press: Copy, Details, Delete; Retry first only on the not
    /// delivered message (§6.3).
    func testLongPressMenu() throws {
        let app = openDeliveries()
        menu(app, of: Seeded.onNetwork)
        XCTAssertTrue(app.buttons["Copy"].exists)
        XCTAssertTrue(app.buttons["Delete"].exists)
        let retries = buttons(app, "Retry")
        closeMenu(app)
        menu(app, of: Seeded.notDelivered)
        XCTAssertTrue(app.buttons["Copy"].exists)
        XCTAssertEqual(buttons(app, "Retry"), retries + 1, "Retry is in the menu of the not delivered message")
        closeMenu(app)
    }

    /// Retry under a not delivered bubble sends it again: pending, no Retry left.
    func testRetryUnderTheNotDeliveredBubble() throws {
        let app = openDeliveries()
        app.buttons["Retry"].firstMatch.tap()
        let b = bubble(app, Seeded.notDelivered)
        XCTAssertTrue(b.waitUntil({ ($0.value as? String ?? "").hasPrefix("Pending since ") }), value(b))
        XCTAssertTrue(app.buttons["Retry"].waitUntil({ !$0.exists }), "no Retry left")
    }

    /// A pending message: "won't receive" is true, it goes (§7.4); messages
    /// that left say so instead (§14.1).
    func testDeleteConfirmationsSayTheTruth() throws {
        let app = openDeliveries()
        deleteFromMenu(app, Seeded.pending, says: "It hasn’t left this iPhone. Sam won’t receive it.",
                       button: "Delete and cancel")
        deleteFromMenu(app, Seeded.onNetwork, says: "It’s already on the network: Sam will still receive it.",
                       button: "Delete")
        deleteFromMenu(app, Seeded.received, says: "Sam already received it and keeps it.", button: "Delete")
        deleteFromMenu(app, Seeded.notDelivered, says: "No device of theirs ever received it.", button: "Delete")
    }

    // MARK: Message sheet (§6.4)

    /// Received on 1 of 2: the legend, the relay by its id, the two devices.
    func testSheetOfAMessageReceivedOnOneOfTwoDevices() throws {
        let app = openDeliveries()
        bubble(app, Seeded.received).tap()
        XCTAssertTrue(any(app, containing: "Current state: Received.").waitForExistence(timeout: 5), "the legend")
        XCTAssertTrue(any(app, containing: "Deposited on relay K7QX2M4A").exists, "the relay")
        XCTAssertTrue(any(app, containing: "Received on 1 of 2").exists, "1 of 2 devices")
        XCTAssertTrue(app.staticTexts["Sam’s devices"].exists)
        XCTAssertTrue(any(app, containing: "iPad").exists && any(app, containing: "iPhone").exists, "a row per device")
        XCTAssertFalse(app.buttons["sheet.retry"].exists)
        app.buttons["Close"].tap()
        XCTAssertTrue(app.buttons["Close"].waitUntil({ !$0.exists }))
    }

    /// Not delivered: the reason, then Retry, which turns it pending.
    func testSheetOfANotDeliveredMessageRetries() throws {
        let app = openDeliveries()
        bubble(app, Seeded.notDelivered).tap()
        XCTAssertTrue(any(app, containing: "Current state: Not delivered.").waitForExistence(timeout: 5), "the legend")
        XCTAssertTrue(any(app, containing: "It never left this iPhone.").exists, "the reason")
        let retry = app.buttons["sheet.retry"]
        XCTAssertTrue(retry.exists)
        retry.tap()
        XCTAssertTrue(any(app, containing: "Current state: Pending.").waitForExistence(timeout: 5), "pending again")
        XCTAssertFalse(retry.exists)
    }

    // MARK: Deliveries (§6.5)

    /// Four groups; "Retry all" moves the not delivered row to Pending; a row
    /// opens the sheet and speaks its state.
    func testDeliveriesGroupsAndARowThatMoves() throws {
        let app = openDeliveries()
        let header = app.buttons["conversation.deliveries"]
        XCTAssertTrue(header.waitUntil({ $0.exists && $0.isEnabled }))
        header.tap()
        for title in ["Not delivered · 1", "Pending · 1", "On the network · 1", "Received · 1"] {
            XCTAssertTrue(app.staticTexts[title].waitForExistence(timeout: 5), title)
        }
        let row = app.buttons[Seeded.notDelivered]
        XCTAssertTrue(value(row).hasPrefix("Not delivered."), value(row))
        app.buttons["Retry all"].tap()
        XCTAssertTrue(app.staticTexts["Pending · 2"].waitForExistence(timeout: 5), "the row moved to Pending")
        XCTAssertFalse(app.staticTexts["Not delivered · 1"].exists)
        XCTAssertTrue(row.waitUntil({ ($0.value as? String ?? "").hasPrefix("Pending since ") }), value(row))
        let received = app.buttons[Seeded.received]
        XCTAssertTrue(value(received).hasSuffix("on 1 of 2 devices"), value(received))
        received.tap()
        XCTAssertTrue(any(app, containing: "Current state: Received.").waitForExistence(timeout: 5), "its sheet")
    }

    // MARK: Pending (§6.6)

    /// "N packets pending" on the Network screen, once loaded: the row reads
    /// "Nothing pending" until the screen has read the count.
    private func networkCount(_ app: XCUIApplication) -> Int {
        let row = app.buttons["network.pending"]
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        XCTAssertTrue(row.waitUntil({ (Int($0.label.prefix { $0.isNumber }) ?? 0) > 0 }), "count not loaded: \(row.label)")
        return Int(row.label.prefix { $0.isNumber }) ?? 0
    }

    /// The packets the Pending screen lists: both section titles.
    private func screenCount(_ app: XCUIApplication) -> Int {
        func n(_ prefix: String) -> Int {
            let t = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", prefix)).firstMatch
            guard t.exists else { return 0 }
            return Int(t.label.split(separator: "·").last?.filter(\.isNumber) ?? "") ?? 0
        }
        return n("Your messages ·") + n("Sync ·")
    }

    /// Back to Network, its count against the screen, then Pending again.
    private func assertCountsAgree(_ app: XCUIApplication, _ step: String,
                                   file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "Sync ·")).firstMatch
            .waitForExistence(timeout: 5), step, file: file, line: line)
        let screen = screenCount(app)
        app.navigationBars.buttons.firstMatch.tap()
        let row = app.buttons["network.pending"]
        XCTAssertTrue(row.waitUntil({ Int($0.label.prefix { $0.isNumber }) == screen }),
                      "\(step): Network says \"\(row.label)\", the screen \(screen)", file: file, line: line)
        row.tap()
        XCTAssertTrue(app.navigationBars["Pending"].waitForExistence(timeout: 5), file: file, line: line)
    }

    /// Network row → Pending → Select → Delete (1) → Cancel all; the Network
    /// count matches the screen after each step (§14.4).
    func testPendingSelectionThenCancelAll() throws {
        let app = openDeliveries()
        // Two pending messages: the seeded one and the not delivered one, retried.
        app.buttons["Retry"].firstMatch.tap()
        XCTAssertTrue(bubble(app, Seeded.notDelivered).waitUntil({ ($0.value as? String ?? "").hasPrefix("Pending since ") }))
        app.navigationBars.buttons.firstMatch.tap()
        XCTAssertTrue(app.tabBars.buttons["Network"].waitForExistence(timeout: 5))
        app.tabBars.buttons["Network"].tap()
        let before = networkCount(app)
        app.buttons["network.pending"].tap()
        XCTAssertTrue(app.navigationBars["Pending"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Sam, \(Seeded.pending)"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Sam, \(Seeded.notDelivered)"].exists)
        XCTAssertEqual(screenCount(app), before, "Network and Pending agree")
        assertCountsAgree(app, "opened")

        // Selection: "Cancel all" hides, "Delete (n)" follows, "Done" ends it.
        app.buttons["pending.select"].tap()
        XCTAssertEqual(app.buttons["pending.select"].label, "Done")
        XCTAssertFalse(app.buttons["pending.cancelAll"].exists, "Cancel all is hidden while selecting")
        let delete = app.buttons["pending.deleteSelected"]
        XCTAssertTrue(delete.waitForExistence(timeout: 5))
        XCTAssertFalse(delete.isEnabled, "nothing selected")
        app.buttons["Sam, \(Seeded.notDelivered)"].tap()
        XCTAssertTrue(delete.waitUntil({ $0.label == "Delete (1)" && $0.isEnabled }), delete.label)
        delete.tap()
        XCTAssertTrue(app.staticTexts["Delete 1 message?"].waitForExistence(timeout: 5))
        app.buttons["Delete 1"].tap()
        XCTAssertTrue(app.buttons["Sam, \(Seeded.notDelivered)"].waitUntil({ !$0.exists }))
        // The deletion ends the selection.
        XCTAssertTrue(app.buttons["pending.select"].waitUntil({ $0.label == "Select" }), app.buttons["pending.select"].label)
        assertCountsAgree(app, "after Delete (1)")

        // Cancel all: only the messages; the sync packets stay.
        let cancelAll = app.buttons["pending.cancelAll"]
        XCTAssertTrue(cancelAll.waitForExistence(timeout: 5))
        XCTAssertTrue(cancelAll.label.hasPrefix("Cancel all · 1"), cancelAll.label)
        cancelAll.tap()
        XCTAssertTrue(app.staticTexts["Cancel 1 message?"].waitForExistence(timeout: 5))
        app.buttons["Delete and cancel"].tap()
        XCTAssertTrue(app.staticTexts["None of your messages are waiting."].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["pending.cancelAll"].exists)
        assertCountsAgree(app, "after Cancel all")
    }

    /// A swipe deletes a message after its confirmation; the sync rows are
    /// text, with nothing to swipe.
    func testPendingSwipeAndReadOnlySync() throws {
        let app = XCUIApplication.seeded("deliveries")
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Network"].waitForExistence(timeout: 10))
        app.tabBars.buttons["Network"].tap()
        XCTAssertTrue(app.buttons["network.pending"].waitForExistence(timeout: 10))
        app.buttons["network.pending"].tap()
        let sync = any(app, containing: "Your card, for your contacts")
        XCTAssertTrue(sync.waitForExistence(timeout: 5), "the sync section")
        // The launch sync found no network (this world has none): said here,
        // without a pull (§6.6).
        XCTAssertTrue(any(app, containing: "Unreachable · nothing is lost").waitForExistence(timeout: 10),
                      "the offline line after the launch sync")
        XCTAssertFalse(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Your card")).firstMatch.exists,
                       "a sync row is not a button")
        sync.swipeLeft()
        XCTAssertFalse(app.buttons["Delete"].waitForExistence(timeout: 1), "no swipe on a sync row")
        let row = app.buttons["Sam, \(Seeded.pending)"]
        XCTAssertTrue(row.exists)
        XCTAssertTrue(value(row).contains("ago") && value(row).contains("expires in"), value(row))
        row.swipeLeft()
        let swipeDelete = app.buttons["Delete"]
        XCTAssertTrue(swipeDelete.waitForExistence(timeout: 5))
        swipeDelete.tap()
        XCTAssertTrue(app.staticTexts["It hasn’t left this iPhone. Sam won’t receive it."].waitForExistence(timeout: 5))
        app.buttons["Delete and cancel"].tap()
        XCTAssertTrue(app.staticTexts["None of your messages are waiting."].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["pending.select"].exists, "nothing to select")
    }

    /// Nothing waits: the Network row says so and still opens the empty state.
    func testPendingEmptyState() throws {
        let app = XCUIApplication.seeded(card: nil)
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Network"].waitForExistence(timeout: 10))
        app.tabBars.buttons["Network"].tap()
        let row = app.buttons["network.pending"]
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        XCTAssertEqual(row.label, "Nothing pending")
        row.tap()
        XCTAssertTrue(any(app, containing: "Nothing pending. Everything has gone out.").waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["pending.select"].exists)
        XCTAssertFalse(app.buttons["pending.cancelAll"].exists)
    }
}
