import XCTest

/// Settings › GIFs and its warning sheet (spec GIF §9.2, §9.3): the switch
/// only turns on after "Use GIFs"; anything else leaves GIFs off.
private enum SheetMetrics {
    /// From the sheet title up to the sheet's grabber, in points.
    static let grabber: CGFloat = 24
}

@MainActor
final class GifUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    private func launch(extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication.seeded(card: nil, extra: extra)
        app.launch()
        return app
    }

    private func gifRow(_ app: XCUIApplication) -> XCUIElement {
        app.tabBars.buttons["Settings"].tap()
        let row = app.buttons["settings.gifs"]
        XCTAssertTrue(row.waitForExistence(timeout: 10), "no GIFs row")
        return row
    }

    /// Opens Settings › GIFs and returns its switch.
    private func openGifs(_ app: XCUIApplication) -> XCUIElement {
        gifRow(app).tap()
        let toggle = app.switches["gifs.use"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 10), "no GIF switch")
        return toggle
    }

    /// Taps the switch itself (its right end) and waits for the sheet.
    private func openSheet(_ app: XCUIApplication, _ toggle: XCUIElement) -> XCUIElement {
        let sheet = app.descendants(matching: .any)["gifWarning"]
        for _ in 0..<3 where !sheet.exists {
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
            _ = sheet.waitForExistence(timeout: 5)
        }
        XCTAssertTrue(sheet.exists, "the switch did not open the warning")
        return sheet
    }

    func testGifRowShowsOff() {
        let app = launch()
        let row = gifRow(app)
        XCTAssertTrue(row.label.contains("GIFs"), row.label)
        XCTAssertTrue(row.label.contains("Off"), row.label)
    }

    func testToggleOpensWarningAndNotNowKeepsOff() {
        let app = launch()
        let toggle = openGifs(app)
        XCTAssertEqual(toggle.value as? String, "0")
        let sheet = openSheet(app, toggle)
        XCTAssertTrue(app.staticTexts["Use GIFs from Klipy?"].exists)
        app.buttons["gifWarning.notNow"].tap()
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5), "Not now did not close the sheet")
        XCTAssertEqual(toggle.value as? String, "0")
    }

    func testSwipeDownKeepsOff() {
        let app = launch()
        let toggle = openGifs(app)
        let sheet = openSheet(app, toggle)
        // From the sheet's top edge (its grabber), not inside the text, which scrolls.
        let window = app.windows.firstMatch
        let top = sheet.frame.minY - SheetMetrics.grabber
        let start = window.coordinate(withNormalizedOffset: .zero)
            .withOffset(CGVector(dx: window.frame.midX, dy: top))
        start.press(forDuration: 0.1, thenDragTo: start.withOffset(CGVector(dx: 0, dy: window.frame.height - top)))
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5), "a swipe did not close the sheet")
        XCTAssertEqual(toggle.value as? String, "0")
        XCTAssertFalse(app.switches["gifs.autoLoad"].exists)
    }

    func testUseGifsTurnsOn() {
        let app = launch()
        let toggle = openGifs(app)
        let sheet = openSheet(app, toggle)
        app.buttons["gifWarning.use"].tap()
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5))
        XCTAssertTrue(toggle.waitUntil({ $0.value as? String == "1" }, timeout: 5), "the switch stayed off")
        XCTAssertTrue(app.switches["gifs.autoLoad"].waitForExistence(timeout: 5), "no auto-play switch once on")
        XCTAssertEqual(app.switches["gifs.autoLoad"].value as? String, "0", "auto-play is off by default")
        app.navigationBars.buttons.firstMatch.tap()
        let row = app.buttons["settings.gifs"]
        XCTAssertTrue(row.waitUntil({ $0.label.contains("On · Klipy sees your IP address") }, timeout: 5), row.label)
    }

    func testWarningShowsLinkedDevicesLine() {
        let app = launch(extra: ["-BarkingUITestLinkedDevices", "2"])
        let toggle = openGifs(app)
        _ = openSheet(app, toggle)
        let line = app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@",
                                                          "Applies to your 2 linked devices")).firstMatch
        XCTAssertTrue(line.waitForExistence(timeout: 5), "no linked devices line")
    }

    /// Without another device, the line is not there.
    func testWarningWithoutLinkedDevicesHasNoLine() {
        let app = launch()
        let toggle = openGifs(app)
        _ = openSheet(app, toggle)
        let line = app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "Applies to your")).firstMatch
        XCTAssertFalse(line.exists)
    }

    // MARK: Conversation (spec GIF §9.1, §9.4)

    /// A ready identity with a conversation with Sam (the seed's messages).
    private func launchWithSam(extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication.seeded("deliveries", extra: extra)
        app.launch()
        return app
    }

    /// Opens Sam's conversation and returns the GIF button.
    private func gifButton(_ app: XCUIApplication) -> XCUIElement {
        openSamChat(app)
        let button = app.buttons["composer.gif"]
        XCTAssertTrue(button.waitForExistence(timeout: 5), "no GIF button")
        return button
    }

    /// Turns GIFs on from the conversation: the warning, then "Use GIFs".
    private func enableFromConversation(_ app: XCUIApplication) -> XCUIElement {
        gifButton(app).tap()
        let sheet = app.descendants(matching: .any)["gifWarning"]
        XCTAssertTrue(sheet.waitForExistence(timeout: 5), "the GIF button did not open the warning")
        app.buttons["gifWarning.use"].tap()
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5), "the warning stayed")
        let picker = app.descendants(matching: .any)["gifPicker"]
        XCTAssertTrue(picker.waitForExistence(timeout: 10), "the picker did not open")
        return picker
    }

    /// The same button whether GIFs are on or off, named "GIF".
    func testGifButtonAlwaysVisible() {
        let app = launchWithSam()
        let button = gifButton(app)
        XCTAssertEqual(button.label, "GIF")
        XCTAssertTrue(button.isHittable)
    }

    func testGifButtonWhenOffOpensWarning() {
        let app = launchWithSam(extra: ["-BarkingUITestGifResults"])
        gifButton(app).tap()
        XCTAssertTrue(app.descendants(matching: .any)["gifWarning"].waitForExistence(timeout: 5),
                      "the GIF button did not open the warning")
        XCTAssertTrue(app.staticTexts["Use GIFs from Klipy?"].exists)
        app.buttons["gifWarning.notNow"].tap()
        XCTAssertFalse(app.descendants(matching: .any)["gifPicker"].waitForExistence(timeout: 2),
                       "Not now opened the picker")
    }

    /// "Use GIFs" closes the warning and opens the picker in place: still
    /// the conversation, no other tab. With animations, as a user sees it.
    func testEnableFromConversationOpensPicker() {
        let app = launchWithSam(extra: ["-BarkingUITestGifResults", "-BarkingUITestKeepAnimations"])
        _ = enableFromConversation(app)
        XCTAssertTrue(app.textFields["Search KLIPY"].waitForExistence(timeout: 5), "no search field")
        XCTAssertTrue(app.buttons["gifPicker.result.0"].waitForExistence(timeout: 5), "no trending")
        XCTAssertTrue(app.textFields["Message"].exists, "left the conversation")
        XCTAssertFalse(app.tabBars.buttons["Settings"].isHittable, "another tab")
    }

    /// A tap on a result sends it: the picker closes and my GIF shows.
    func testTapResultSends() {
        let app = launchWithSam(extra: ["-BarkingUITestGifResults"])
        let picker = enableFromConversation(app)
        let first = app.buttons["gifPicker.result.0"]
        XCTAssertTrue(first.waitForExistence(timeout: 5), "no result")
        first.tap()
        XCTAssertTrue(picker.waitForNonExistence(timeout: 5), "the picker stayed")
        // My GIF's bubble: auto-play is off, so it waits for a tap.
        let bubble = app.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier BEGINSWITH %@ AND label == %@", "gifBubble.", "GIF")).firstMatch
        XCTAssertTrue(bubble.waitForExistence(timeout: 5), "no GIF bubble")
        // The value: the caption shown ("Tap to load"), then the state.
        XCTAssertTrue(bubble.waitUntil({ ($0.value as? String ?? "").contains("Pending since") }),
                      "not my sent GIF: \(bubble.value ?? "nil")")
    }

    // MARK: Received GIFs (spec GIF §7, §6.7)

    /// Sam's conversation with three received GIFs (`-BarkingUITestFakeGifs`).
    private func launchWithGifs(extra: [String] = []) -> XCUIApplication {
        launchWithSam(extra: ["-BarkingUITestFakeGifs"] + extra)
    }

    /// The GIF bubbles in a state (`gifBubble.<state>`).
    private func bubbles(_ app: XCUIApplication, _ state: String) -> XCUIElementQuery {
        app.descendants(matching: .any).matching(identifier: "gifBubble.\(state)")
    }

    /// Turns GIFs on in Settings › GIFs, then opens Sam's conversation.
    private func enableInSettingsThenOpenSam(_ app: XCUIApplication) {
        let toggle = openGifs(app)
        _ = openSheet(app, toggle)
        app.buttons["gifWarning.use"].tap()
        XCTAssertTrue(toggle.waitUntil({ $0.value as? String == "1" }, timeout: 5), "GIFs stayed off")
        app.tabBars.buttons["Chats"].tap()
        openSamChat(app)
    }

    /// GIFs off (the default): three neutral bubbles, "GIF · from Klipy,
    /// off" (their state), and Klipy is never asked: Transparency, which
    /// counts each media request of this test device, has no Klipy line.
    func testReceivedGifWhenOffMakesNoRequest() {
        let app = launchWithGifs()
        openSamChat(app)
        let off = bubbles(app, "off")
        XCTAssertTrue(off.firstMatch.waitForExistence(timeout: 5), "no GIF bubble off")
        XCTAssertEqual(off.count, 3)
        XCTAssertEqual(off.firstMatch.label, "GIF")
        // The caption shown, read as the bubble's value.
        XCTAssertTrue((off.firstMatch.value as? String ?? "").hasPrefix("GIF · from Klipy, off"),
                      "caption: \(off.firstMatch.value ?? "nil")")
        XCTAssertEqual(bubbles(app, "loading").count, 0)
        app.navigationBars.buttons.firstMatch.tap()
        app.tabBars.buttons["Settings"].tap()
        let row = app.buttons["settings.transparency"]
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.tap()
        XCTAssertTrue(app.descendants(matching: .any)["transparency.data"].waitForExistence(timeout: 10))
        let line = app.staticTexts["transparency.gifs.day"]
        for _ in 0..<4 where !line.exists { app.swipeUp() }
        XCTAssertFalse(line.waitForExistence(timeout: 2), "a request was made: \(line.label)")
        XCTAssertFalse(app.descendants(matching: .any)["transparency.who.gifs"].exists, "Klipy listed while off")
    }

    /// A tap on a GIF that is off opens the warning (never anything else);
    /// once on, that GIF loads and the picker stays closed.
    func testTapOffBubbleOpensWarning() {
        let app = launchWithGifs()
        openSamChat(app)
        let off = bubbles(app, "off").firstMatch
        XCTAssertTrue(off.waitForExistence(timeout: 5), "no GIF bubble off")
        off.tap()
        let sheet = app.descendants(matching: .any)["gifWarning"]
        XCTAssertTrue(sheet.waitForExistence(timeout: 5), "the bubble did not open the warning")
        app.buttons["gifWarning.use"].tap()
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5), "the warning stayed")
        XCTAssertTrue(bubbles(app, "loaded").firstMatch.waitForExistence(timeout: 10), "the GIF did not load")
        XCTAssertFalse(app.descendants(matching: .any)["gifPicker"].exists, "the picker opened")
        XCTAssertEqual(bubbles(app, "loaded").count, 1, "more than the GIF tapped loaded")
        XCTAssertEqual(bubbles(app, "tapToLoad").count, 2)
        // Loaded, a tap opens the message, as for any bubble.
        bubbles(app, "loaded").firstMatch.tap()
        XCTAssertTrue(app.buttons["sheet.delete"].waitForExistence(timeout: 5), "the message did not open")
    }

    /// Auto-play off: one "Play GIFs automatically ›" for the conversation,
    /// under the first GIF; it opens Settings › GIFs over the conversation.
    func testAutoPlayHintOnlyUnderFirstGif() {
        let app = launchWithGifs()
        enableInSettingsThenOpenSam(app)
        let tap = bubbles(app, "tapToLoad")
        XCTAssertTrue(tap.firstMatch.waitForExistence(timeout: 5), "no GIF bubble to load")
        XCTAssertEqual(tap.count, 3)
        let hint = app.buttons.matching(identifier: "gif.autoPlayHint")
        XCTAssertTrue(hint.firstMatch.waitForExistence(timeout: 5), "no auto-play line")
        XCTAssertEqual(hint.count, 1)
        XCTAssertEqual(hint.firstMatch.label, "Play GIFs automatically ›")
        hint.firstMatch.tap()
        let auto = app.switches["gifs.autoLoad"]
        XCTAssertTrue(auto.waitForExistence(timeout: 5), "Settings › GIFs did not open")
        XCTAssertTrue(app.textFields["Message"].exists, "left the conversation")
        app.buttons["gifSettings.close"].tap()
        XCTAssertTrue(auto.waitForNonExistence(timeout: 5), "the sheet stayed")
        XCTAssertTrue(app.textFields["Message"].isHittable, "not back in the conversation")
    }

    /// Transparency once GIFs are on: Klipy in "Who sees what", and the
    /// day's line counting every call.
    func testTransparencyShowsKlipyWhenOn() {
        let app = launch(extra: ["-BarkingUITestGifUsage"])
        let toggle = openGifs(app)
        _ = openSheet(app, toggle)
        app.buttons["gifWarning.use"].tap()
        XCTAssertTrue(toggle.waitUntil({ $0.value as? String == "1" }, timeout: 5), "GIFs stayed off")
        let link = app.buttons["gifs.transparency"]
        XCTAssertTrue(link.waitForExistence(timeout: 5))
        link.tap()
        let line = app.staticTexts["transparency.gifs.day"]
        XCTAssertTrue(app.descendants(matching: .any)["transparency.data"].waitForExistence(timeout: 10))
        for _ in 0..<6 where !line.exists { app.swipeUp() }
        XCTAssertTrue(line.waitForExistence(timeout: 5), "no Klipy line")
        XCTAssertEqual(line.label, "Klipy contacted 3 times · 2 searches, 0 previews, 1 GIF shown")
        let who = app.descendants(matching: .any)["transparency.who.gifs"]
        for _ in 0..<6 where !who.exists { app.swipeDown() }
        XCTAssertTrue(who.exists, "Klipy is not in Who sees what")
    }
}
