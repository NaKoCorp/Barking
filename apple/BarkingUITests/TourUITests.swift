import XCTest

/// Screenshots of every screen, for comparing with the mockup. Skipped
/// unless TEST_RUNNER_BARKING_TOUR is set.
@MainActor
final class TourUITests: XCTestCase {
    func testTour() throws {
        try XCTSkipIf(ProcessInfo.processInfo.environment["BARKING_TOUR"] == nil)
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestOpenCard", samCard])
        app.launch()
        snap(app, "01-welcome")
        app.buttons["Create my identity"].firstMatch.tap()
        let name = app.textFields["Your name, as contacts see it"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        name.tap(); name.typeText("Alice")
        app.buttons["Create my identity"].firstMatch.tap()
        XCTAssertTrue(app.staticTexts["Your recovery phrase"].waitForExistence(timeout: 10))
        snap(app, "02-phrase")
        app.terminate()
        // A fake route on the real message, for the path screen.
        let again = XCUIApplication.fresh(extra: ["-BarkingUITestOpenCard", samCard, "-BarkingUITestFakeRoute"])
        again.launch()
        try onboard(again)
        _ = again.staticTexts["Sam"].waitForExistence(timeout: 10)
        snap(again, "03-add-contact")
        if again.buttons["Add"].exists { again.buttons["Add"].tap() }
        sleep(1)
        snap(again, "04-chats")
        again.staticTexts["Sam"].firstMatch.tap()
        let field = again.textFields["Message"]
        if field.waitForExistence(timeout: 5) {
            field.tap(); field.typeText("hello Sam"); again.buttons["Send"].tap()
            again.keyboards.buttons.firstMatch.tap()
        }
        sleep(1)
        snap(again, "05-conversation")
        let path = again.buttons["conversation.path"]
        if path.waitForExistence(timeout: 5) {
            path.tap()
            _ = again.staticTexts["Internet · 1 relay"].waitForExistence(timeout: 5)
            sleep(1)
            snap(again, "06-path")
            again.navigationBars.buttons.firstMatch.tap()
        }
        again.navigationBars.buttons.firstMatch.tap()
        again.tabBars.buttons["Network"].tap(); sleep(1)
        snap(again, "07-network")
        again.tabBars.buttons["Settings"].tap(); sleep(1)
        snap(again, "08-settings")
        again.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Linked devices")).firstMatch.tap(); sleep(1)
        snap(again, "09-devices")
    }

    private func snap(_ app: XCUIApplication, _ name: String) {
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
    }
}
