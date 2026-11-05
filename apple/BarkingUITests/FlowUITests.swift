import XCTest

@MainActor
final class OnboardingUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    func testCreateIdentityAndConfirmPhrase() throws {
        let app = XCUIApplication.fresh()
        app.launch()
        try onboard(app)
        XCTAssertFalse(app.staticTexts["Recovery phrase not confirmed"].exists)
    }

    func testLaterKeepsTheBanner() throws {
        let app = XCUIApplication.fresh()
        app.launch()
        try onboard(app, confirm: false)
        XCTAssertTrue(app.staticTexts["Recovery phrase not confirmed"].exists)
    }
}

@MainActor
final class ChatUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    func testAddContactByLinkAndSend() throws {
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestOpenCard", samCard])
        app.launch()
        try onboard(app)
        // The card link opened at launch waits for the identity, then shows.
        XCTAssertTrue(app.staticTexts["Sam"].waitForExistence(timeout: 10))
        app.buttons["Add"].tap()
        app.staticTexts["Sam"].firstMatch.tap()
        let field = app.textFields["Message"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        field.typeText("hello Sam")
        app.buttons["Send"].tap()
        XCTAssertTrue(app.staticTexts["hello Sam"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["queued"].exists || app.staticTexts["sent"].exists
                      || app.otherElements["queued"].exists)
    }
}

@MainActor
final class SettingsUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    /// Review Focus 4: switching language mid-flow keeps the state.
    func testLanguageSwitchKeepsState() throws {
        let app = XCUIApplication.fresh()
        app.launch()
        app.buttons["Français"].tap()
        XCTAssertTrue(app.buttons["Créer mon identité"].waitForExistence(timeout: 5))
        app.buttons["Créer mon identité"].tap()
        XCTAssertTrue(app.textFields["Votre nom, tel que vos contacts le voient"].waitForExistence(timeout: 5))
        app.navigationBars.buttons.firstMatch.tap()
        app.buttons["English"].tap()
        XCTAssertTrue(app.buttons["Create my identity"].waitForExistence(timeout: 5))
    }
}

@MainActor
final class AccessibilityUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    /// Review Focus 5: the largest text size keeps the main buttons whole.
    func testXXLargeTextKeepsButtonsReadable() throws {
        let app = XCUIApplication.fresh(extra: ["-UIPreferredContentSizeCategoryName",
                                                "UICTContentSizeCategoryAccessibilityXXL"])
        app.launch()
        let window = app.windows.firstMatch.frame
        for title in ["Create my identity", "Recover with 24 words"] {
            let b = app.buttons[title].firstMatch
            XCTAssertTrue(b.waitForExistence(timeout: 5), title)
            XCTAssertTrue(window.contains(b.frame), "\(title) off screen: \(b.frame)")
        }
    }

    func testStatusesHaveVoiceOverLabels() throws {
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestOpenCard", samCard])
        app.launch()
        try onboard(app)
        XCTAssertTrue(app.staticTexts["Sam"].waitForExistence(timeout: 10))
        app.buttons["Add"].tap()
        app.staticTexts["Sam"].firstMatch.tap()
        let field = app.textFields["Message"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        field.typeText("status check")
        app.buttons["Send"].tap()
        let labelled = app.descendants(matching: .any).matching(
            NSPredicate(format: "label IN %@", ["queued", "sent", "delivered", "not sent"]))
        XCTAssertTrue(labelled.firstMatch.waitForExistence(timeout: 5))
    }
}
