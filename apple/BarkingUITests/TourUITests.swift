import XCTest

/// Screenshots of every screen, for UI review. Skipped unless
/// TEST_RUNNER_BARKING_TOUR is set; TEST_RUNNER_BARKING_TOUR_LANG=fr runs the
/// same tour in French (labels below, identifiers where they exist), and
/// TEST_RUNNER_BARKING_TOUR_SIZE (a UIContentSizeCategory raw value, such as
/// UICTContentSizeCategoryAccessibilityL) at another text size. The two
/// destructive confirmations are snapped too ("dialog-…", unnumbered, so the
/// screen numbers stay those of shots/index.md); they are always cancelled.
/// So are the safety-code mismatch sheet and the verified state (UI review
/// B3), taken after the numbered safety-code screens.
@MainActor
final class TourUITests: XCTestCase {
    /// The tour is one long test: the UI plan's per-test allowance does not apply.
    override func setUp() {
        super.setUp()
        executionTimeAllowance = 900
    }

    private struct Labels {
        let create, phraseTitle, cont, confirm, later, add, message, send: String
        let chats, network, settings, linked, identity, security, recover, link, pdf, linkNew, close, cancel: String
        let lockedTitle, deleteContact, erase, immediately, match, mismatch, sync: String

        static let en = Labels(
            create: "Create my identity",
            phraseTitle: "Your recovery phrase", cont: "Continue", confirm: "Confirm", later: "Later",
            add: "Add", message: "Message", send: "Send", chats: "Chats", network: "Network",
            settings: "Settings", linked: "Linked devices", identity: "My identity", security: "Security",
            recover: "Recover with 24 words", link: "Link to an existing device", pdf: "Encrypted PDF",
            linkNew: "Link a new device", close: "Close", cancel: "Cancel", lockedTitle: "Barking is locked",
            deleteContact: "Delete this contact", erase: "Erase", immediately: "Immediately",
            match: "The numbers match", mismatch: "They don't match", sync: "Sync now")
        static let fr = Labels(
            create: "Créer mon identité",
            phraseTitle: "Votre phrase de récupération", cont: "Continuer", confirm: "Confirmer", later: "Plus tard",
            add: "Ajouter", message: "Message", send: "Envoyer", chats: "Discussions", network: "Réseau",
            settings: "Réglages", linked: "Appareils liés", identity: "Mon identité", security: "Sécurité",
            recover: "Restaurer avec 24 mots", link: "Lier à un appareil existant", pdf: "PDF chiffré",
            linkNew: "Lier un nouvel appareil", close: "Fermer", cancel: "Annuler", lockedTitle: "Barking est verrouillé",
            deleteContact: "Supprimer ce contact", erase: "Effacer", immediately: "Immédiatement",
            match: "Les chiffres sont identiques", mismatch: "Ils ne correspondent pas", sync: "Synchroniser")
    }

    private var step = 0

    func testTour() throws {
        let env = ProcessInfo.processInfo.environment
        try XCTSkipIf(env["BARKING_TOUR"] == nil)
        let lang = env["BARKING_TOUR_LANG"] ?? "en"
        let L = lang == "fr" ? Labels.fr : Labels.en
        let size = env["BARKING_TOUR_SIZE"].flatMap { $0.isEmpty ? nil : ["-UIPreferredContentSizeCategoryName", $0] } ?? []
        let app = XCUIApplication.fresh(language: lang, extra: [
            "-BarkingUITestOpenCard", samCard, "-BarkingUITestFakeRoute", "-BarkingUITestNoAutoUnlock"] + size)
        app.launch()
        let back = { app.navigationBars.buttons.firstMatch.tap() }
        // Cancels a confirmation dialog: its Cancel button, else a tap at
        // `outside` (a static text away from the popover), never the
        // destructive action.
        let dismissDialog = { (outside: CGFloat) in
            let cancel = app.buttons[L.cancel].firstMatch
            if cancel.exists && cancel.isHittable { cancel.tap() }
            // Near the leading edge: at AX sizes the popover covers the middle.
            else { app.coordinate(withNormalizedOffset: CGVector(dx: 0.04, dy: outside)).tap() }
            // The dialog is gone once its Cancel button is.
            app.buttons[L.cancel].firstMatch.waitUntil({ !$0.exists }, timeout: 3)
        }
        let row = { (prefix: String) in
            app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", prefix)).firstMatch
        }

        // UI review B5 (U-32): no dot over the text, in every pass.
        assertNoDotOverWelcomeText(app)
        snap(app, "welcome")
        // Onboarding side branches: first screens of recover and link.
        app.buttons[L.recover].firstMatch.tap()
        _ = app.textFields["recover.word.1"].waitForExistence(timeout: 10)
        snap(app, "recover-24-words"); back()
        app.buttons[L.link].firstMatch.tap()
        _ = app.textFields["link.deviceName"].waitForExistence(timeout: 10)
        snap(app, "link-to-existing-device"); back()
        // Create.
        app.buttons[L.create].firstMatch.tap()
        let name = app.textFields["create.name"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        snap(app, "create-identity-empty")
        name.tap(); name.typeText("Alice")
        snap(app, "create-identity-filled")
        app.buttons[L.create].firstMatch.tap()
        XCTAssertTrue(app.staticTexts[L.phraseTitle].waitForExistence(timeout: 10))
        snap(app, "phrase")
        var words: [Int: String] = [:]
        for i in 1...24 {
            let w = app.staticTexts.matching(identifier: "phrase.word.\(i)").firstMatch
            if w.exists { words[i] = w.label }
        }
        // Encrypted PDF password sheet.
        let pdf = app.buttons[L.pdf]
        if pdf.waitForExistence(timeout: 5) {
            pdf.tap()
            let pw = app.secureTextFields["pdf.password"]
            if pw.waitForExistence(timeout: 5) {
                // Return ends the entry and lowers the keyboard: with it up, the
                // pinned "Create the PDF" button covers the second field (CI).
                pw.focusAndType("password1234\n", in: app)
                let c = app.secureTextFields["pdf.confirm"]
                XCTAssertTrue(c.waitForExistence(timeout: 5))
                // At accessibility sizes the second field sits under the CTA bar while
                // still reported hittable. (At xxxLarge it is in view, and a swipe would hide it.)
                if size.contains(where: { $0.contains("Accessibility") }) {
                    app.scrollViews.containing(.secureTextField, identifier: "pdf.confirm").firstMatch.swipeUp()
                    c.waitUntilStill()
                }
                c.focusAndType("password1234", in: app)
                snap(app, "pdf-password-sheet-weak")
                app.buttons["pdf.suggest"].tap()
                app.buttons["pdf.create"].waitUntil({ $0.isEnabled })
                snap(app, "pdf-password-sheet-suggested")
            }
            if app.buttons[L.cancel].exists { app.buttons[L.cancel].tap() } else { app.swipeDown() }
            // Back on the phrase once the sheet's fields are gone.
            app.secureTextFields["pdf.password"].waitUntil({ !$0.exists })
        }
        let wrote = app.descendants(matching: .any)["phrase.wroteItDown"]
        while !wrote.isHittable { app.swipeUp() }
        wrote.tap()
        app.buttons[L.cont].tap()
        XCTAssertTrue(app.staticTexts.matching(identifier: "quiz.question.0").firstMatch.waitForExistence(timeout: 5))
        snap(app, "phrase-confirmation-quiz")
        // A wrong pick shows the error state of the quiz.
        let label0 = app.staticTexts.matching(identifier: "quiz.question.0").firstMatch
        let n0 = Int(label0.value as? String ?? "") ?? 0
        let wrongs = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'quiz.0.' AND NOT identifier == %@", "quiz.0.\(words[n0] ?? "")"))
        if wrongs.count > 0 {
            wrongs.element(boundBy: 0).tap()
            for q in 1..<3 {
                let l = app.staticTexts.matching(identifier: "quiz.question.\(q)").firstMatch
                let n = Int(l.value as? String ?? "") ?? 0
                app.buttons["quiz.\(q).\(words[n] ?? "")"].tap()
            }
            app.buttons[L.confirm].tap()
            _ = app.descendants(matching: .any)["quiz.error"].waitForExistence(timeout: 10)
            snap(app, "phrase-confirmation-wrong-word")
        }
        // Skip: the chats keep the "not confirmed" banner.
        if app.buttons[L.later].exists { app.buttons[L.later].tap() }
        // The card opened at launch shows its Add button once the chats are up.
        _ = app.buttons[L.add].waitForExistence(timeout: 10)
        snap(app, "add-contact-from-link")
        if app.buttons[L.add].exists { app.buttons[L.add].tap() }
        // The sheet goes on to Sam's safety code; Later opens the
        // conversation, with its unverified warning.
        let later = app.buttons["addContact.later"]
        if later.waitForExistence(timeout: 10) {
            snap(app, "add-contact-safety-code")
            later.tap()
        }
        let field = app.textFields[L.message]
        if field.waitForExistence(timeout: 5) {
            snap(app, "conversation-unverified-banner")
            back()
        }
        _ = app.staticTexts["Sam"].waitForExistence(timeout: 10)
        snap(app, "chats-phrase-not-confirmed-banner")
        // Conversation with a few messages and the route badge.
        app.staticTexts["Sam"].firstMatch.tap()
        if field.waitForExistence(timeout: 5) {
            for text in ["hello Sam", "Are you there?", "Meet at the market at six."] {
                field.tap(); field.typeText(text); app.buttons[L.send].tap()
                _ = app.staticTexts[text].waitForExistence(timeout: 10)
            }
            if app.keyboards.count > 0 {
                app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.3)).tap()
                app.keyboards.firstMatch.waitUntil({ !$0.exists })
            }
        }
        snap(app, "conversation")
        // Safety code: header of the conversation (one button, UI review B4).
        let header = app.buttons["conversation.header"].exists ? app.buttons["conversation.header"]
            : app.staticTexts["Sam"].firstMatch
        var popped = false
        if header.exists {
            header.tap()
            let code = app.descendants(matching: .any)["contact.safetyCode"].firstMatch
            _ = code.waitForExistence(timeout: 10)
            snap(app, "safety-code")
            // Review final #1: the groups never wrap, so at any text size the
            // code stays inside the screen (it would overflow, not wrap).
            if code.exists {
                let screen = app.windows.firstMatch.frame
                XCTAssertGreaterThanOrEqual(code.frame.minX, screen.minX, "safety code overflows")
                XCTAssertLessThanOrEqual(code.frame.maxX, screen.maxX, "safety code overflows")
            } else {
                XCTFail("safety code not found")
            }
            app.swipeUp()
            code.waitUntilStill()
            snap(app, "safety-code-devices")
            // The danger zone is at the bottom: at AX sizes, several screens down.
            let delete = app.buttons["contact.delete"]
            for _ in 0..<6 where delete.exists && !delete.isHittable { app.swipeUp() }
            if delete.exists && delete.isHittable {
                delete.tap()
                _ = app.buttons[L.cancel].firstMatch.waitForExistence(timeout: 3)
                snap(app, "dialog-delete-contact", numbered: false)
                dismissDialog(0.42)
            }
            // UI review B3: the mismatch sheet, then a match (said, then back).
            let mismatch = app.buttons[L.mismatch]
            for _ in 0..<8 where mismatch.exists && !mismatch.isHittable { app.swipeDown() }
            if mismatch.exists && mismatch.isHittable {
                mismatch.tap()
                _ = app.buttons[L.close].firstMatch.waitForExistence(timeout: 5)
                snap(app, "sheet-mismatch", numbered: false)
                if app.buttons[L.close].firstMatch.exists { app.buttons[L.close].firstMatch.tap() } else { app.swipeDown() }
                app.buttons[L.close].firstMatch.waitUntil({ !$0.exists }, timeout: 5)
                snap(app, "safety-code-mismatched", numbered: false)
            }
            let match = app.buttons[L.match]
            if match.exists && match.isHittable {
                match.tap()
                snap(app, "safety-code-verified", numbered: false)
                // It goes back to the conversation on its own.
                popped = app.textFields[L.message].waitForExistence(timeout: 6)
            }
            if !popped { back() }
        }
        // Back to the chats: the conversation hides the tab bar (UI review
        // B4), so go back until it shows, whatever the safety code left.
        for _ in 0..<3 where !app.tabBars.buttons[L.network].exists {
            back()
            _ = app.tabBars.buttons[L.network].waitForExistence(timeout: 3)
        }
        app.tabBars.buttons[L.network].tap()
        _ = app.buttons[L.sync].waitForExistence(timeout: 10)
        snap(app, "network")
        // UI review B4: the line Sync now leaves (unnumbered).
        let sync = app.buttons[L.sync]
        if sync.exists {
            sync.tap()
            _ = app.descendants(matching: .any)["network.result"].waitForExistence(timeout: 15)
            snap(app, "network-synced", numbered: false)
        }
        app.tabBars.buttons[L.settings].tap()
        _ = app.buttons["settings.transparency"].waitForExistence(timeout: 10)
        snap(app, "settings")
        row(L.linked).tap()
        let linkNew = app.buttons[L.linkNew]
        _ = linkNew.waitForExistence(timeout: 10)
        snap(app, "linked-devices")
        if linkNew.exists {
            linkNew.tap()
            _ = app.images["link.code"].waitForExistence(timeout: 10)
            snap(app, "link-a-new-device-sheet")
            if app.buttons[L.close].firstMatch.exists { app.buttons[L.close].firstMatch.tap() } else { app.swipeDown() }
            app.buttons[L.close].firstMatch.waitUntil({ !$0.exists }, timeout: 5)
        }
        back()
        row(L.identity).tap()
        let edit = app.descendants(matching: .any)["identity.edit"]
        _ = edit.waitForExistence(timeout: 10)
        snap(app, "my-identity")
        app.swipeUp()
        edit.waitUntilStill()
        snap(app, "my-identity-code")
        back()
        app.buttons["settings.transparency"].tap()
        _ = app.descendants(matching: .any)["transparency.data"].waitForExistence(timeout: 10)
        snap(app, "transparency")
        back()
        row(L.security).tap()
        _ = app.switches["security.lock"].waitForExistence(timeout: 10)
        snap(app, "security")
        let erase = app.buttons["security.erase"]
        if erase.waitForExistence(timeout: 3) {
            erase.press(forDuration: 2.1)
            if app.buttons[L.erase].waitForExistence(timeout: 3) {
                snap(app, "dialog-erase", numbered: false)
                dismissDialog(0.75)
            }
        }
        let toggle = app.switches["security.lock"]
        if toggle.waitForExistence(timeout: 5) {
            // At AX sizes the erase control sits below the fold: back to the top.
            for _ in 0..<3 where !toggle.isHittable { app.swipeDown() }
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
            toggle.waitUntil({ ($0.value as? String) == "1" })
            snap(app, "security-lock-on")
            // The delay is a menu (UI review B2): open it, snap it, keep the value.
            let delay = app.buttons["security.delay"]
            if delay.waitForExistence(timeout: 3) {
                delay.tap()
                _ = app.buttons[L.immediately].firstMatch.waitForExistence(timeout: 5)
                snap(app, "menu-lock-delay", numbered: false)
                let same = app.buttons[L.immediately].firstMatch
                if same.exists && same.isHittable { same.tap() } else { dismissDialog(0.15) }
                // The menu is closed once the switch is reachable again.
                toggle.waitUntil({ $0.isHittable })
            }
            XCUIDevice.shared.press(.home)
            app.activate()
            let unlock = app.buttons["lock.unlock"]
            if unlock.waitForExistence(timeout: 10) {
                unlock.waitUntil({ $0.isHittable })
                snap(app, "lock-screen")
            }
        }
    }

    /// Delivery states (spec Lot M §10, "Visite"), from the `deliveries`
    /// seed: the conversation with the four states, the message sheet
    /// (received on 1 of 2 devices, and not delivered),
    /// "Pending" and two confirmations, always dismissed. Unnumbered
    /// ("delivery-…"): the numbers stay those of shots/index.md.
    func testTourDeliveries() throws {
        let env = ProcessInfo.processInfo.environment
        try XCTSkipIf(env["BARKING_TOUR"] == nil)
        let lang = env["BARKING_TOUR_LANG"] ?? "en"
        let fr = lang == "fr"
        let L = fr ? Labels.fr : Labels.en
        let size = env["BARKING_TOUR_SIZE"].flatMap { $0.isEmpty ? nil : ["-UIPreferredContentSizeCategoryName", $0] } ?? []
        let body = fr ? Seeded.french
            : (notDelivered: Seeded.notDelivered, received: Seeded.received, onNetwork: Seeded.onNetwork, pending: Seeded.pending)
        let app = XCUIApplication.seeded("deliveries", language: lang, extra: ["-BarkingUITestNoAutoUnlock"] + size)
        app.launch()
        let close = { (marker: XCUIElement) in
            app.buttons[L.close].firstMatch.tap()
            marker.waitUntil({ !$0.exists }, timeout: 5)
        }
        // Cancels a dialog: its Cancel button, else (iOS 26 popovers have none)
        // a tap beside it. That tap lands near the back button and may also
        // pop the screen; `backIfPushed` copes with it.
        let dismissDialog = { (button: XCUIElement) in
            let cancel = app.buttons[L.cancel].firstMatch
            if cancel.exists && cancel.isHittable { cancel.tap() }
            else { app.coordinate(withNormalizedOffset: CGVector(dx: 0.04, dy: 0.12)).tap() }
            button.waitUntil({ !$0.exists }, timeout: 5)
        }
        // Back to the root, unless the dialog's dismissal already went there.
        let backIfPushed = {
            let button = app.navigationBars.buttons.firstMatch
            if button.waitForExistence(timeout: 2) { button.tap() }
        }

        let sam = app.staticTexts["Sam"].firstMatch
        XCTAssertTrue(sam.waitForExistence(timeout: 10))
        sam.tap()
        let pending = app.staticTexts[body.pending].firstMatch
        XCTAssertTrue(pending.waitForExistence(timeout: 10))
        pending.waitUntilStill()
        snap(app, "delivery-conversation", numbered: false)

        // The sheet of a message received on 1 of its 2 devices, then its devices.
        app.staticTexts[body.received].firstMatch.tap()
        let timeline = app.descendants(matching: .any)["sheet.timeline"]
        XCTAssertTrue(timeline.waitForExistence(timeout: 10))
        let delete = app.buttons["sheet.delete"]
        snap(app, "delivery-sheet-received", numbered: false)
        for _ in 0..<6 where !delete.isHittable { app.swipeUp() }
        delete.waitUntilStill()
        snap(app, "delivery-sheet-received-devices", numbered: false)
        close(timeline)

        // Not delivered: the reason and Retry.
        app.staticTexts[body.notDelivered].firstMatch.tap()
        XCTAssertTrue(app.buttons["sheet.retry"].waitForExistence(timeout: 10))
        snap(app, "delivery-sheet-not-delivered", numbered: false)
        close(app.buttons["sheet.retry"])

        // The confirmation of a pending message.
        pending.press(forDuration: 1.0)
        let menuDelete = app.buttons[fr ? "Supprimer" : "Delete"].firstMatch
        if menuDelete.waitForExistence(timeout: 5) {
            menuDelete.tap()
            let confirm = app.buttons[fr ? "Supprimer et annuler" : "Delete and cancel"].firstMatch
            if confirm.waitForExistence(timeout: 5) {
                snap(app, "delivery-dialog-delete-pending", numbered: false)
                dismissDialog(confirm)
            }
        }

        // Pending, from the Network row: then selecting, then Cancel all's dialog.
        backIfPushed()
        XCTAssertTrue(app.tabBars.buttons[L.network].waitForExistence(timeout: 5))
        app.tabBars.buttons[L.network].tap()
        let row = app.buttons["network.pending"]
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.tap()
        let cancelAll = app.buttons["pending.cancelAll"]
        // At accessibility sizes "Cancel all" is below the fold, not yet in the list.
        let first = app.buttons.matching(NSPredicate(format: "label ENDSWITH %@", body.pending)).firstMatch
        XCTAssertTrue(first.waitForExistence(timeout: 10))
        snap(app, "delivery-pending", numbered: false)
        app.buttons["pending.select"].tap()
        let selected = app.buttons.matching(NSPredicate(format: "label ENDSWITH %@", body.pending)).firstMatch
        if selected.waitForExistence(timeout: 5) { selected.tap() }
        app.buttons["pending.deleteSelected"].waitUntil({ $0.isEnabled })
        snap(app, "delivery-pending-selecting", numbered: false)
        app.buttons["pending.select"].tap()
        app.buttons["pending.deleteSelected"].waitUntil({ !$0.exists })
        for _ in 0..<6 where !(cancelAll.exists && cancelAll.isHittable) { app.swipeUp() }
        XCTAssertTrue(cancelAll.waitUntilStill())
        if size.contains(where: { $0.contains("Accessibility") }) {
            snap(app, "delivery-pending-cancel-all", numbered: false)
        }
        cancelAll.tap()
        let confirmAll = app.buttons[fr ? "Supprimer et annuler" : "Delete and cancel"].firstMatch
        if confirmAll.waitForExistence(timeout: 5) {
            snap(app, "delivery-dialog-cancel-all", numbered: false)
            dismissDialog(confirmAll)
        }
    }

    /// Contact requests (Task 9 design pass), in light and dark, unnumbered
    /// ("requests-…-light|dark"): the add's confirmation with its switch,
    /// the safety code with the sent invitation ("Possible in 24 h"), the
    /// changed-device line, the chats with a request and the Invitations
    /// entry, the Invitations screen, the request page (top and actions),
    /// Settings › Notifications, then the add's two notices (too large,
    /// too soon), each from its own launch.
    func testTourRequests() throws {
        let env = ProcessInfo.processInfo.environment
        try XCTSkipIf(env["BARKING_TOUR"] == nil)
        let lang = env["BARKING_TOUR_LANG"] ?? "en"
        let L = lang == "fr" ? Labels.fr : Labels.en
        let size = env["BARKING_TOUR_SIZE"].flatMap { $0.isEmpty ? nil : ["-UIPreferredContentSizeCategoryName", $0] } ?? []
        for scheme in ["light", "dark"] {
            requestsPass(lang: lang, L: L, size: size, scheme: scheme)
            for notice in ["tooLarge", "tooSoon"] {
                addNotice(notice, lang: lang, L: L, size: size, scheme: scheme)
            }
            for status in ["unanswered", "accepted"] {
                contactInvitation(status, lang: lang, size: size, scheme: scheme)
            }
        }
    }

    /// Sam's page with its invitation unanswered (Resend open) or accepted.
    private func contactInvitation(_ status: String, lang: String, size: [String], scheme: String) {
        let app = XCUIApplication.seeded(language: lang, extra: [
            "-BarkingUITestNoAutoUnlock", "-barking.appearance", scheme,
            "-BarkingUITestInviteStatus", status] + size)
        app.launch()
        let sam = app.staticTexts["Sam"].firstMatch
        XCTAssertTrue(sam.waitForExistence(timeout: 10))
        sam.tap()
        let header = app.buttons["conversation.header"]
        XCTAssertTrue(header.waitForExistence(timeout: 10))
        header.tap()
        let state = app.staticTexts["contact.invite.state"]
        XCTAssertTrue(state.waitForExistence(timeout: 10), "the invitation section")
        let resend = app.buttons["contact.invite.resend"]
        let last = status == "accepted" ? state : resend
        // Up to the lower part of the screen: "isHittable" alone stops at the bottom edge.
        let screen = app.windows.firstMatch.frame
        for _ in 0..<10 where !(last.isHittable && last.frame.maxY < screen.minY + screen.height * 0.8) {
            app.swipeUp(velocity: .slow)
        }
        last.waitUntilStill()
        snap(app, "requests-contact-\(status)-\(scheme)", numbered: false)
        app.terminate()
    }

    private func requestsLaunch(lang: String, size: [String], scheme: String, extra: [String]) -> XCUIApplication {
        // The appearance is the app's own setting, read from the arguments domain.
        let app = XCUIApplication.seeded(card: nil, language: lang, extra: [
            "-BarkingUITestOpenCard", samCard, "-BarkingUITestNoAutoUnlock",
            "-barking.appearance", scheme] + extra + size)
        app.launch()
        return app
    }

    private func requestsPass(lang: String, L: Labels, size: [String], scheme: String) {
        let app = requestsLaunch(lang: lang, size: size, scheme: scheme,
                                 extra: ["-BarkingUITestRequests", "-BarkingUITestDeviceChanged"])
        let back = { app.navigationBars.buttons.firstMatch.tap() }
        // The add's confirmation, its invitation switch in view.
        let toggle = app.switches["add.invite"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 10))
        for _ in 0..<4 where !toggle.isHittable { app.swipeUp() }
        toggle.waitUntilStill()
        snap(app, "requests-add-invitation-\(scheme)", numbered: false)
        let add = app.buttons[L.add].firstMatch
        for _ in 0..<4 where !add.isHittable { app.swipeDown() }
        add.tap()
        // Sam's safety code: the invitation went, the resend waits a day.
        let resend = app.buttons["contact.invite.resend"]
        XCTAssertTrue(resend.waitForExistence(timeout: 10))
        for _ in 0..<6 where !resend.isHittable { app.swipeUp() }
        resend.waitUntilStill()
        snap(app, "requests-contact-invitation-\(scheme)", numbered: false)
        app.buttons["addContact.later"].tap()
        // The conversation: Sam changed device two days ago.
        let line = app.staticTexts["conversation.deviceChanged"]
        XCTAssertTrue(line.waitForExistence(timeout: 10), "the changed-device line")
        snap(app, "requests-conversation-device-changed-\(scheme)", numbered: false)
        back()
        // The chats: Alice's request among them, Bob behind the entry.
        let row = app.buttons["chats.request.a11ce000"]
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        snap(app, "requests-chats-\(scheme)", numbered: false)
        app.buttons["chats.invitations"].tap()
        let bob = app.buttons["invitations.row.b0b00000"]
        XCTAssertTrue(bob.waitForExistence(timeout: 10))
        snap(app, "requests-invitations-\(scheme)", numbered: false)
        // Bob's page: hidden, resent, his name clashes with a contact's.
        bob.tap()
        XCTAssertTrue(app.descendants(matching: .any)["request.clash"].firstMatch.waitForExistence(timeout: 10))
        snap(app, "requests-request-hidden-clash-\(scheme)", numbered: false)
        let show = app.buttons["request.hide"]
        // Up to the lower part of the screen: "isHittable" alone stops at the bottom edge.
        let screen = app.windows.firstMatch.frame
        for _ in 0..<10 where !(show.isHittable && show.frame.maxY < screen.minY + screen.height * 0.8) {
            app.swipeUp(velocity: .slow)
        }
        show.waitUntilStill()
        snap(app, "requests-request-hidden-actions-\(scheme)", numbered: false)
        back()
        XCTAssertTrue(bob.waitForExistence(timeout: 10))
        back()
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.tap()
        let accept = app.buttons["request.accept"]
        XCTAssertTrue(accept.waitForExistence(timeout: 10))
        snap(app, "requests-request-\(scheme)", numbered: false)
        let block = app.buttons["request.block"]
        for _ in 0..<8 where !block.isHittable { app.swipeUp() }
        block.waitUntilStill()
        snap(app, "requests-request-actions-\(scheme)", numbered: false)
        back()
        // Settings › Notifications: the invitations switch.
        XCTAssertTrue(app.tabBars.buttons[L.settings].waitForExistence(timeout: 10))
        app.tabBars.buttons[L.settings].tap()
        let notifications = app.buttons["settings.notifications"]
        XCTAssertTrue(notifications.waitForExistence(timeout: 10))
        notifications.tap()
        let invites = app.switches["notifications.invites"]
        XCTAssertTrue(invites.waitForExistence(timeout: 10))
        for _ in 0..<4 where !invites.isHittable { app.swipeUp() }
        invites.waitUntilStill()
        snap(app, "requests-settings-notifications-\(scheme)", numbered: false)
        app.terminate()
    }

    /// The add whose invitation could not go: the too-large banner or the
    /// too-soon line, on the safety code that follows.
    private func addNotice(_ notice: String, lang: String, L: Labels, size: [String], scheme: String) {
        let app = requestsLaunch(lang: lang, size: size, scheme: scheme, extra: ["-BarkingUITestInvite", notice])
        let add = app.buttons[L.add].firstMatch
        XCTAssertTrue(add.waitForExistence(timeout: 10))
        add.tap()
        let id = notice == "tooLarge" ? "contact.inviteTooLarge" : "contact.inviteTooSoon"
        let shown = app.descendants(matching: .any)[id].firstMatch
        XCTAssertTrue(shown.waitForExistence(timeout: 10), "the \(notice) notice")
        shown.waitUntilStill()
        snap(app, "requests-add-\(notice)-\(scheme)", numbered: false)
        app.terminate()
    }

    private func snap(_ app: XCUIApplication, _ name: String, numbered: Bool = true) {
        if numbered { step += 1 }
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = numbered ? String(format: "%02d-%@", step, name) : name
        shot.lifetime = .keepAlways
        add(shot)
    }
}
