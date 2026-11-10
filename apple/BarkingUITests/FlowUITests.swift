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

    /// UI review B5 (U-32): the galaxy's dots never show over Welcome's
    /// header, text or buttons, at the default size and at AX3.
    func testWelcomeDotsStayOffTheText() throws {
        // Two launches and six screenshot scans with the animations on: ~28 s alone,
        // past the plan's 60 s when three parallel simulators saturate the CPU.
        executionTimeAllowance = 180
        // The dots move: animations stay on, as the test looks at them.
        let app = XCUIApplication.fresh(extra: ["-BarkingUITestKeepAnimations"])
        app.launch()
        assertNoDotOverWelcomeText(app)
        app.terminate()
        let large = XCUIApplication.fresh(extra: ["-BarkingUITestKeepAnimations",
                                                  "-UIPreferredContentSizeCategoryName",
                                                  "UICTContentSizeCategoryAccessibilityXL"])
        large.launch()
        assertNoDotOverWelcomeText(large, shots: 2)
    }

    /// Review B4 #1: VoiceOver hears the word typed in a Recover tile.
    func testRecoverTileSaysItsWord() throws {
        let app = XCUIApplication.fresh()
        app.launch()
        app.buttons["Recover with 24 words"].firstMatch.tap()
        let tile = app.textFields["recover.word.1"]
        XCTAssertTrue(tile.waitForExistence(timeout: 5))
        tile.tap()
        tile.typeText("abandon")
        XCTAssertTrue((tile.value as? String ?? "").contains("abandon"), "value: \(tile.value ?? "nil")")
        let second = app.textFields["recover.word.2"]
        second.tap()
        second.typeText("zzzz")
        let value = second.value as? String ?? ""
        XCTAssertTrue(value.contains("zzzz") && value.contains("Not in the word list"), "value: \(value)")
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
        // This test is the add: the app starts on the chats with no contact.
        let app = XCUIApplication.seeded(card: nil, extra: ["-BarkingUITestOpenCard", samCard])
        app.launch()
        XCTAssertTrue(app.staticTexts["Sam"].waitForExistence(timeout: 10))
        app.buttons["Add"].tap()
        // The safety code comes next; Later opens the conversation, which
        // warns that Sam is not verified.
        let later = app.buttons["addContact.later"]
        XCTAssertTrue(later.waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["The numbers match"].exists)
        later.tap()
        let field = app.textFields["Message"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        XCTAssertTrue(app.descendants(matching: .any)["conversation.unverified"].waitForExistence(timeout: 5))
        field.tap()
        field.typeText("hello Sam")
        app.buttons["Send"].tap()
        let bubble = app.staticTexts["hello Sam"]
        XCTAssertTrue(bubble.waitForExistence(timeout: 5))
        // The state is the bubble's VoiceOver value (spec Lot M §8): no
        // network in UI tests, so it waits here.
        let value = bubble.value as? String ?? ""
        XCTAssertTrue(value.hasPrefix("Pending since") || value.hasPrefix("On the network since"), "value: \(value)")
    }

    /// A bubble shows when it sits above the composer, inside the screen.
    private func shows(_ bubble: XCUIElement, above field: XCUIElement) -> Bool {
        bubble.exists && bubble.frame.minY >= 0 && bubble.frame.maxY <= field.frame.minY + 1
    }

    /// At the bottom of a long conversation: the keyboard keeps the last
    /// message in view, and a send shows the new one without moving what was
    /// already in view away.
    func testSendAtTheBottomKeepsTheHistoryInPlace() throws {
        let app = XCUIApplication.seeded("history")
        app.launch()
        let field = openSamChat(app)
        let last = app.staticTexts["History message 40"]
        XCTAssertTrue(last.waitForExistence(timeout: 5))
        XCTAssertTrue(shows(last, above: field), "the conversation opens on its last message")
        field.tap()
        XCTAssertTrue(app.keyboards.firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(last.waitUntil({ _ in self.shows(last, above: field) }), "the keyboard hides the last message")
        field.typeText("one more")
        app.buttons["Send"].tap()
        let sent = app.staticTexts["one more"]
        XCTAssertTrue(sent.waitUntil({ _ in self.shows(sent, above: field) }), "the sent message is not in view")
        // Settled: the core's row has replaced the shown one.
        XCTAssertTrue(sent.waitUntil({ ($0.value as? String ?? "").hasPrefix("Pending since") }))
        XCTAssertTrue(shows(sent, above: field), "the sent message left the view")
        XCTAssertTrue(shows(last, above: field), "the history moved")
    }

    /// Scrolled up in the history, a send brings the new message into view.
    func testSendFromHigherUpShowsTheNewMessage() throws {
        let app = XCUIApplication.seeded("history")
        app.launch()
        let field = openSamChat(app)
        XCTAssertTrue(app.staticTexts["History message 40"].waitForExistence(timeout: 5))
        for _ in 0..<4 { app.swipeDown() }
        XCTAssertFalse(shows(app.staticTexts["History message 40"], above: field), "still at the bottom")
        field.tap()
        field.typeText("from above")
        app.buttons["Send"].tap()
        let sent = app.staticTexts["from above"]
        XCTAssertTrue(sent.waitUntil({ _ in self.shows(sent, above: field) }), "the sent message is not in view")
    }

    /// Right after the add, a match in the sheet marks Sam verified, closes
    /// the sheet and opens the conversation without the unverified warning.
    func testMatchRightAfterAddingVerifies() throws {
        let app = XCUIApplication.seeded(card: nil, extra: ["-BarkingUITestOpenCard", samCard])
        app.launch()
        XCTAssertTrue(app.staticTexts["Sam"].waitForExistence(timeout: 10))
        app.buttons["Add"].tap()
        let match = app.buttons["The numbers match"]
        XCTAssertTrue(match.waitForExistence(timeout: 5))
        for _ in 0..<6 where !match.isHittable { app.swipeUp() }
        match.tap()
        XCTAssertTrue(app.textFields["Message"].waitForExistence(timeout: 8))
        XCTAssertFalse(app.descendants(matching: .any)["conversation.unverified"].exists)
    }

    /// Spec Lot M §6.4: a tap on a sent bubble opens its sheet; its delete
    /// asks first (§7.4), then the sheet closes and the bubble leaves. (The
    /// dialog's "Keep" is not exposed: iOS 26 hides the cancel action of an
    /// iPhone confirmation dialog.)
    func testBubbleOpensTheMessageSheet() throws {
        let app = XCUIApplication.seeded()
        app.launch()
        let field = openSamChat(app)
        field.tap()
        field.typeText("sheet test")
        app.buttons["Send"].tap()
        let bubble = app.staticTexts["sheet test"]
        XCTAssertTrue(bubble.waitForExistence(timeout: 5))
        bubble.tap()
        let sealed = app.descendants(matching: .any).matching(
            NSPredicate(format: "label BEGINSWITH %@", "Sealed and saved on this iPhone")).firstMatch
        XCTAssertTrue(sealed.waitForExistence(timeout: 5), "the sheet shows the timeline")
        let delete = app.buttons["sheet.delete"]
        XCTAssertTrue(delete.waitForExistence(timeout: 3))
        delete.tap()
        // No network in UI tests: still on this iPhone, so the pending case (§7.4).
        let text = app.staticTexts["It hasn’t left this iPhone. Sam won’t receive it."]
        XCTAssertTrue(text.waitForExistence(timeout: 3), "the deletion asks first, with the pending text")
        let confirm = app.buttons["Delete and cancel"]
        XCTAssertTrue(confirm.exists)
        confirm.tap()
        XCTAssertTrue(delete.waitUntil({ !$0.exists }), "the sheet closes")
        XCTAssertTrue(bubble.waitUntil({ !$0.exists }), "the bubble leaves")
    }

    /// A tap on a received bubble opens its sheet, with the message's way
    /// ("Delivery" section) in place of a state (spec Lot M §6.4). The
    /// received message and its route are faked: no second device in UI tests.
    func testReceivedBubbleSheetShowsThePath() throws {
        let app = XCUIApplication.seeded(extra: ["-BarkingUITestFakeReceived", "-BarkingUITestFakeRoute"])
        app.launch()
        _ = openSamChat(app)
        let bubble = app.staticTexts["hi from Sam"]
        XCTAssertTrue(bubble.waitForExistence(timeout: 5))
        bubble.tap()
        XCTAssertTrue(app.staticTexts["Delivery"].waitForExistence(timeout: 5), "the path section")
        let relay = app.descendants(matching: .any).matching(
            NSPredicate(format: "label CONTAINS %@", "K7QX2M4A")).firstMatch
        XCTAssertTrue(relay.waitForExistence(timeout: 5), "the stop of the relay it came through")
        XCTAssertTrue(app.buttons["sheet.delete"].exists)
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
    /// Welcome scrolls at accessibility sizes (UI review B5), so a button
    /// may be a swipe away, never cut.
    func testXXLargeTextKeepsButtonsReadable() throws {
        let app = XCUIApplication.fresh(extra: ["-UIPreferredContentSizeCategoryName",
                                                "UICTContentSizeCategoryAccessibilityXXL"])
        app.launch()
        let window = app.windows.firstMatch.frame
        for title in ["Create my identity", "Recover with 24 words"] {
            let b = app.buttons[title].firstMatch
            XCTAssertTrue(b.waitForExistence(timeout: 5), title)
            for _ in 0..<4 where !window.contains(b.frame) { app.swipeUp() }
            XCTAssertTrue(window.contains(b.frame), "\(title) off screen: \(b.frame)")
        }
    }

    func testStatusesHaveVoiceOverLabels() throws {
        let app = XCUIApplication.seeded()
        app.launch()
        let field = openSamChat(app)
        field.tap()
        field.typeText("status check")
        app.buttons["Send"].tap()
        // One element per bubble: the text as label, the state as value.
        let bubble = app.staticTexts["status check"]
        XCTAssertTrue(bubble.waitForExistence(timeout: 5))
        let value = bubble.value as? String ?? ""
        XCTAssertTrue(value.hasPrefix("Pending since") || value.hasPrefix("On the network since"), "value: \(value)")
    }
}

@MainActor
final class DevicesUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    /// Settings › Transparency: where the data is, and the journal with its
    /// security filter (the seeded identity has only added a contact, so the
    /// journal has little to show and the filter only has to switch).
    func testTransparencyShowsWhereTheDataIs() throws {
        let app = XCUIApplication.seeded(card: nil)
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Settings"].waitForExistence(timeout: 10))
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
        let app = XCUIApplication.seeded(card: nil)
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Settings"].waitForExistence(timeout: 10))
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
        // Return ends the entry and lowers the keyboard: with it up, the
        // pinned "Create the PDF" button covers the second field (CI).
        field.focusAndType("password1234\n", in: app)
        let confirm = app.secureTextFields["pdf.confirm"]
        XCTAssertTrue(confirm.waitForExistence(timeout: 5))
        confirm.focusAndType("password1234", in: app)
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

    private func openSecurity(_ app: XCUIApplication, file: StaticString = #filePath, line: UInt = #line) {
        app.tabBars.buttons["Settings"].tap()
        let row = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Security")).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 10), "no Security row", file: file, line: line)
        row.tap()
    }

    /// The switch sits at the trailing edge of its row. A tap that lands
    /// while the screen is still settling (slow CI) is tried again.
    private func turnOn(_ toggle: XCUIElement, file: StaticString = #filePath, line: UInt = #line) {
        for _ in 0..<3 where !(toggle.value as? String == "1") {
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
            toggle.waitUntil({ $0.value as? String == "1" }, timeout: 5)
        }
        XCTAssertEqual(toggle.value as? String, "1", "the switch did not turn on", file: file, line: line)
    }

    /// UI review B3: a tap does nothing, a 2 s hold opens the confirmation.
    func testEraseNeedsATwoSecondHold() throws {
        let app = XCUIApplication.seeded(card: nil, extra: ["-BarkingUITestNoAutoUnlock"])
        app.launch()
        XCTAssertTrue(app.buttons["New message"].waitForExistence(timeout: 10))
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
        let app = XCUIApplication.seeded(card: nil, extra: ["-BarkingUITestNoAutoUnlock"])
        app.launch()
        XCTAssertTrue(app.buttons["New message"].waitForExistence(timeout: 10))
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
        let app = XCUIApplication.seeded(card: nil, extra: ["-BarkingUITestNoAutoUnlock"])
        app.launch()
        XCTAssertTrue(app.buttons["New message"].waitForExistence(timeout: 10))
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
        let app = XCUIApplication.seeded(card: nil, extra: ["-BarkingUITestNoAutoUnlock"])
        app.launch()
        XCTAssertTrue(app.buttons["New message"].waitForExistence(timeout: 10))
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
        let app = XCUIApplication.seeded(card: nil, extra: ["-BarkingUITestNoAutoUnlock"])
        app.launch()
        XCTAssertTrue(app.buttons["New message"].waitForExistence(timeout: 10))
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
        let app = XCUIApplication.seeded(card: nil)
        app.launch()
        XCTAssertTrue(app.buttons["New message"].waitForExistence(timeout: 10))
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

    /// Opens Sam's safety code (Sam is seeded).
    private func openSafetyCode() throws -> XCUIApplication {
        let app = XCUIApplication.seeded()
        app.launch()
        openSamChat(app)
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
