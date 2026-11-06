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

    /// A field's footer is its VoiceOver hint, not a second element read
    /// again after the field (UI review B3 carry).
    func testFieldFooterIsReadOnce() throws {
        let app = XCUIApplication.fresh()
        app.launch()
        app.buttons["Create my identity"].firstMatch.tap()
        XCTAssertTrue(app.textFields["create.name"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["Your name travels in your contact card. No phone number, no email."].exists)
        XCTAssertFalse(app.staticTexts["Shown on your other devices, and to your contacts in your card."].exists)
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

    /// The header icon opens the path of the last message (a real message
    /// on a fake route: no network in UI tests).
    func testPathScreenShowsTheRoute() throws {
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestOpenCard", samCard, "-BarkingUITestFakeRoute"])
        app.launch()
        try onboard(app)
        XCTAssertTrue(app.staticTexts["Sam"].waitForExistence(timeout: 10))
        app.buttons["Add"].tap()
        app.staticTexts["Sam"].firstMatch.tap()
        let field = app.textFields["Message"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        field.typeText("hello Sam")
        app.buttons["Send"].tap()
        XCTAssertTrue(app.staticTexts["hello Sam"].waitForExistence(timeout: 5))
        app.buttons["conversation.path"].tap()
        // Each stop is one VoiceOver sentence: name, step, time, what it
        // could see, without the "·" separators (UI review U-36).
        let stop = { (name: String) in
            app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", name)).firstMatch
        }
        XCTAssertTrue(stop("Internet relay, K7QX2M4A, deposited").waitForExistence(timeout: 5))
        XCTAssertTrue(stop("Sam's phone, receipt received").exists)
        XCTAssertTrue(app.staticTexts["Internet · 1 relay"].exists)
    }
}

@MainActor
final class SettingsUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    /// The phone's language, with no in-app picker.
    func testFollowsThePhoneLanguage() throws {
        let app = XCUIApplication.fresh(language: "fr")
        app.launch()
        XCTAssertTrue(app.buttons["Créer mon identité"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["Français"].exists)
        XCTAssertFalse(app.buttons["English"].exists)
    }

    /// The theme picked on the welcome screen survives a relaunch.
    func testAppearanceChosenOnWelcomeIsKept() throws {
        let app = XCUIApplication.fresh()
        app.launch()
        let dark = app.buttons["appearance.dark"]
        XCTAssertTrue(dark.waitForExistence(timeout: 5))
        dark.tap()
        XCTAssertTrue(dark.isSelected)
        app.terminate()
        let again = XCUIApplication()
        again.launchArguments = ["-AppleLanguages", "(en)"]
        again.launch()
        XCTAssertTrue(again.buttons["appearance.dark"].waitForExistence(timeout: 5))
        XCTAssertTrue(again.buttons["appearance.dark"].isSelected)
        again.buttons["appearance.system"].tap()
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

@MainActor
final class DevicesUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    /// Settings › Transparency: where the data is, and the journal with its
    /// security filter (a new identity has logged nothing, so the filter
    /// only has to switch).
    func testTransparencyShowsWhereTheDataIs() throws {
        let app = XCUIApplication.fresh()
        app.launch()
        try onboard(app)
        app.tabBars.buttons["Settings"].tap()
        let row = app.buttons["settings.transparency"]
        XCTAssertTrue(row.waitForExistence(timeout: 5))
        row.tap()
        XCTAssertTrue(app.staticTexts["Nothing in clear on the nodes"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Journal and paths"].exists)
        // BarkingSegmented: a container of selectable buttons (UI review B2).
        let filter = app.descendants(matching: .any)["transparency.filter"]
        XCTAssertTrue(filter.exists)
        XCTAssertTrue(filter.buttons["Everything"].isSelected)
        filter.buttons["Keys and devices"].tap()
        XCTAssertTrue(filter.buttons["Keys and devices"].isSelected)
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "Keys and devices: key changes")).firstMatch.exists)
    }

    /// The administrator alone: "Disconnect this device" is the wipe, with
    /// its warning, and leads back to the welcome screen.
    func testDisconnectingTheOnlyDeviceErasesIt() throws {
        let app = XCUIApplication.fresh()
        app.launch()
        try onboard(app)
        app.tabBars.buttons["Settings"].tap()
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Linked devices")).firstMatch.tap()
        let disconnect = app.buttons["devices.disconnect"]
        XCTAssertTrue(disconnect.waitForExistence(timeout: 5))
        disconnect.tap()
        let warning = app.staticTexts.matching(NSPredicate(
            format: "label BEGINSWITH %@ AND label ENDSWITH %@",
            "Everything on this iPhone will be erased. Your contacts will not be told.",
            "you will need the 24-word phrase.")).firstMatch
        XCTAssertTrue(warning.waitForExistence(timeout: 5))
        app.buttons["Erase"].tap()
        XCTAssertTrue(app.buttons["Create my identity"].waitForExistence(timeout: 10))

        // Nothing is left: a relaunch (without the test reset) is a fresh install.
        app.terminate()
        let again = XCUIApplication()
        again.launchArguments = ["-AppleLanguages", "(en)"]
        again.launch()
        XCTAssertTrue(again.buttons["Create my identity"].waitForExistence(timeout: 10))
    }
}

@MainActor
final class PhraseExportUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    /// The PDF needs a strong password; the suggestion unlocks the button.
    func testEncryptedPDFNeedsAStrongPassword() throws {
        let app = XCUIApplication.fresh()
        app.launch()
        app.buttons["Create my identity"].firstMatch.tap()
        let name = app.textFields["create.name"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        name.tap()
        name.typeText("Alice")
        app.buttons["Create my identity"].firstMatch.tap()
        let pdf = app.buttons["Encrypted PDF"]
        XCTAssertTrue(pdf.waitForExistence(timeout: 10))
        pdf.tap()
        let field = app.secureTextFields["pdf.password"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        field.typeText("password1234")
        let confirm = app.secureTextFields["pdf.confirm"]
        confirm.tap()
        confirm.typeText("password1234")
        // The error line is the field's VoiceOver hint (read once, UI review
        // B3), which XCUITest cannot read; the gate is what this checks.
        XCTAssertFalse(app.buttons["pdf.create"].isEnabled)
        app.buttons["pdf.suggest"].tap()
        XCTAssertTrue(app.buttons["pdf.create"].isEnabled)
        app.buttons["pdf.create"].tap()
        // The system share sheet opens on the file.
        XCTAssertTrue(app.otherElements["ActivityListView"].waitForExistence(timeout: 10)
                      || app.navigationBars["UIActivityContentView"].waitForExistence(timeout: 2))
    }
}

@MainActor
final class SecurityUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    private func openSecurity(_ app: XCUIApplication) {
        app.tabBars.buttons["Settings"].tap()
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Security")).firstMatch.tap()
    }

    /// The switch sits at the trailing edge of its row.
    private func turnOn(_ toggle: XCUIElement) {
        toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
        let on = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == '1'"), object: toggle)
        XCTAssertEqual(XCTWaiter().wait(for: [on], timeout: 5), .completed)
    }

    /// UI review B3: a tap does nothing, a 2 s hold opens the confirmation.
    func testEraseNeedsATwoSecondHold() throws {
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestNoAutoUnlock"])
        app.launch()
        try onboard(app)
        openSecurity(app)
        let erase = app.buttons["security.erase"]
        XCTAssertTrue(erase.waitForExistence(timeout: 5))
        erase.tap()
        XCTAssertFalse(app.buttons["Erase"].waitForExistence(timeout: 1))
        // Half the hold is not enough either: the threshold is 2 s.
        erase.press(forDuration: 1.0)
        XCTAssertFalse(app.buttons["Erase"].waitForExistence(timeout: 1))
        erase.press(forDuration: 2.1)
        XCTAssertTrue(app.buttons["Erase"].waitForExistence(timeout: 3))
    }

    func testEmergencyWipeReturnsToWelcome() throws {
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestNoAutoUnlock"])
        app.launch()
        try onboard(app)
        openSecurity(app)
        let erase = app.buttons["security.erase"]
        XCTAssertTrue(erase.waitForExistence(timeout: 5))
        // A tap is not enough.
        erase.tap()
        XCTAssertFalse(app.buttons["Erase"].waitForExistence(timeout: 1))
        erase.press(forDuration: 2.1)
        let warning = app.staticTexts.matching(NSPredicate(
            format: "label BEGINSWITH %@", "Everything on this iPhone will be erased.")).firstMatch
        XCTAssertTrue(warning.waitForExistence(timeout: 5))
        app.buttons["Erase"].tap()
        XCTAssertTrue(app.buttons["Create my identity"].waitForExistence(timeout: 10))
    }

    func testLockCoversTheAppAndUnlocks() throws {
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestNoAutoUnlock"])
        app.launch()
        try onboard(app)
        openSecurity(app)
        let toggle = app.switches["security.lock"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 5))
        turnOn(toggle)
        XCTAssertEqual(toggle.value as? String, "1")
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.staticTexts["Barking is locked"].waitForExistence(timeout: 10))
        app.buttons["Unlock"].tap()
        XCTAssertTrue(app.switches["security.lock"].waitForExistence(timeout: 10))
    }

    /// No Face ID on the way: the lock screen erases on its own.
    func testEmergencyWipeFromTheLockScreen() throws {
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestNoAutoUnlock"])
        app.launch()
        try onboard(app)
        openSecurity(app)
        let toggle = app.switches["security.lock"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 5))
        turnOn(toggle)
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.staticTexts["Barking is locked"].waitForExistence(timeout: 10))
        app.buttons["lock.erase"].press(forDuration: 2.1)
        app.buttons["Erase"].tap()
        XCTAssertTrue(app.buttons["Create my identity"].waitForExistence(timeout: 10))
    }

    /// A sheet open above the root stays under the cover, out of reach.
    func testLockCoversASheetOpenAboveTheRoot() throws {
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestNoAutoUnlock"])
        app.launch()
        try onboard(app)
        openSecurity(app)
        let toggle = app.switches["security.lock"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 5))
        turnOn(toggle)
        app.tabBars.buttons["Chats"].tap()
        app.buttons["New message"].tap()
        let sheetButton = app.buttons["Close"].firstMatch
        XCTAssertTrue(sheetButton.waitForExistence(timeout: 5))
        XCTAssertTrue(sheetButton.isHittable)
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.staticTexts["Barking is locked"].waitForExistence(timeout: 10))
        XCTAssertFalse(sheetButton.isHittable, "the sheet must be under the cover")
        XCTAssertTrue(app.buttons["Unlock"].isHittable)
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = "10-lock"
        shot.lifetime = .keepAlways
        add(shot)
    }

    /// The lock screen asks for the owner by itself; "Unlock" is the retry.
    func testLockScreenAsksForTheOwnerOnItsOwn() throws {
        let app = XCUIApplication.fresh()
        app.launch()
        try onboard(app)
        openSecurity(app)
        let toggle = app.switches["security.lock"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 5))
        turnOn(toggle)
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.switches["security.lock"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.staticTexts["Barking is locked"].exists)
    }
}

@MainActor
final class SafetyCodeUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    /// Onboards, adds Sam from a link and opens Sam's safety code.
    private func openSafetyCode() throws -> XCUIApplication {
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestOpenCard", samCard])
        app.launch()
        try onboard(app)
        XCTAssertTrue(app.staticTexts["Sam"].waitForExistence(timeout: 10))
        app.buttons["Add"].tap()
        app.staticTexts["Sam"].firstMatch.tap()
        XCTAssertTrue(app.textFields["Message"].waitForExistence(timeout: 5))
        app.staticTexts["Sam"].firstMatch.tap()
        XCTAssertTrue(app.buttons["The numbers match"].waitForExistence(timeout: 5))
        return app
    }

    /// U-21: a match says "Verified", then goes back to the conversation.
    func testMatchSaysVerifiedThenGoesBack() throws {
        let app = try openSafetyCode()
        app.buttons["The numbers match"].tap()
        XCTAssertTrue(app.staticTexts["Verified"].waitForExistence(timeout: 3))
        XCTAssertTrue(app.textFields["Message"].waitForExistence(timeout: 5))
    }

    /// U-21: a mismatch opens a sheet that says what to do, in true words.
    func testMismatchOpensTheAdvice() throws {
        let app = try openSafetyCode()
        app.buttons["They don't match"].tap()
        XCTAssertTrue(app.staticTexts["Don't send anything sensitive yet. Compare again in person or on a call you trust."]
            .waitForExistence(timeout: 3))
        app.buttons["Close"].tap()
        // The banner keeps the advice (one VoiceOver element: title, then advice).
        let banner = app.descendants(matching: .any).matching(NSPredicate(
            format: "label BEGINSWITH %@ AND label CONTAINS %@", "The numbers do not match", "Don't send anything sensitive yet.")).firstMatch
        XCTAssertTrue(banner.waitForExistence(timeout: 3))
        XCTAssertFalse(app.buttons["Close"].exists)
    }

    /// U-2: Delete is an outlined danger button in its own zone, and asks first.
    func testDeleteIsInTheDangerZone() throws {
        let app = try openSafetyCode()
        let delete = app.buttons["contact.delete"]
        for _ in 0..<5 where !delete.isHittable { app.swipeUp() }
        XCTAssertTrue(delete.isHittable)
        delete.tap()
        XCTAssertTrue(app.buttons["Delete"].waitForExistence(timeout: 3))
    }
}
