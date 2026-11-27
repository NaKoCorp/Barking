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
}
