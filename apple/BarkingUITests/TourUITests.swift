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
    private struct Labels {
        let create, phraseTitle, cont, confirm, later, add, message, send: String
        let chats, network, settings, linked, identity, security, recover, link, pdf, linkNew, close, cancel: String
        let lockedTitle, deleteContact, erase, immediately, match, mismatch: String

        static let en = Labels(
            create: "Create my identity",
            phraseTitle: "Your recovery phrase", cont: "Continue", confirm: "Confirm", later: "Later",
            add: "Add", message: "Message", send: "Send", chats: "Chats", network: "Network",
            settings: "Settings", linked: "Linked devices", identity: "My identity", security: "Security",
            recover: "Recover with 24 words", link: "Link to an existing device", pdf: "Encrypted PDF",
            linkNew: "Link a new device", close: "Close", cancel: "Cancel", lockedTitle: "Barking is locked",
            deleteContact: "Delete this contact", erase: "Erase", immediately: "Immediately",
            match: "The numbers match", mismatch: "They don't match")
        static let fr = Labels(
            create: "Créer mon identité",
            phraseTitle: "Votre phrase de récupération", cont: "Continuer", confirm: "Confirmer", later: "Plus tard",
            add: "Ajouter", message: "Message", send: "Envoyer", chats: "Discussions", network: "Réseau",
            settings: "Réglages", linked: "Appareils liés", identity: "Mon identité", security: "Sécurité",
            recover: "Restaurer avec 24 mots", link: "Lier à un appareil existant", pdf: "PDF chiffré",
            linkNew: "Lier un nouvel appareil", close: "Fermer", cancel: "Annuler", lockedTitle: "Barking est verrouillé",
            deleteContact: "Supprimer ce contact", erase: "Effacer", immediately: "Immédiatement",
            match: "Les chiffres sont identiques", mismatch: "Ils ne correspondent pas")
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
            sleep(1)
        }
        let row = { (prefix: String) in
            app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", prefix)).firstMatch
        }

        snap(app, "welcome")
        // Onboarding side branches: first screens of recover and link.
        app.buttons[L.recover].firstMatch.tap(); sleep(1)
        snap(app, "recover-24-words"); back()
        app.buttons[L.link].firstMatch.tap(); sleep(1)
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
                pw.tap(); pw.typeText("password1234")
                let c = app.secureTextFields["pdf.confirm"]
                // At AX sizes the second field is below the fold, under the CTA bar.
                if !size.isEmpty { app.swipeUp(); sleep(1) }
                c.tap(); c.typeText("password1234")
                snap(app, "pdf-password-sheet-weak")
                app.buttons["pdf.suggest"].tap(); sleep(1)
                snap(app, "pdf-password-sheet-suggested")
            }
            if app.buttons[L.cancel].exists { app.buttons[L.cancel].tap() } else { app.swipeDown() }
            sleep(1)
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
            app.buttons[L.confirm].tap(); sleep(1)
            snap(app, "phrase-confirmation-wrong-word")
        }
        // Skip: the chats keep the "not confirmed" banner.
        if app.buttons[L.later].exists { app.buttons[L.later].tap() }
        _ = app.staticTexts["Sam"].waitForExistence(timeout: 10)
        sleep(1)
        snap(app, "add-contact-from-link")
        if app.buttons[L.add].exists { app.buttons[L.add].tap() }
        sleep(1)
        snap(app, "chats-phrase-not-confirmed-banner")
        // Conversation with a few messages and the route badge.
        app.staticTexts["Sam"].firstMatch.tap()
        let field = app.textFields[L.message]
        if field.waitForExistence(timeout: 5) {
            for text in ["hello Sam", "Are you there?", "Meet at the market at six."] {
                field.tap(); field.typeText(text); app.buttons[L.send].tap(); sleep(1)
            }
            if app.keyboards.count > 0 { app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.3)).tap() }
        }
        sleep(1)
        snap(app, "conversation")
        let path = app.buttons["conversation.path"]
        if path.waitForExistence(timeout: 5) {
            path.tap(); sleep(2)
            snap(app, "message-path")
            back()
        }
        // Safety code: header of the conversation.
        let header = app.staticTexts["Sam"].firstMatch
        var popped = false
        if header.exists {
            header.tap(); sleep(2)
            snap(app, "safety-code")
            app.swipeUp(); sleep(1)
            snap(app, "safety-code-devices")
            // The danger zone is at the bottom: at AX sizes, several screens down.
            let delete = app.buttons["contact.delete"]
            for _ in 0..<6 where delete.exists && !delete.isHittable { app.swipeUp() }
            if delete.exists && delete.isHittable {
                delete.tap(); sleep(1)
                snap(app, "dialog-delete-contact", numbered: false)
                dismissDialog(0.42)
            }
            // UI review B3: the mismatch sheet, then a match (said, then back).
            let mismatch = app.buttons[L.mismatch]
            for _ in 0..<8 where mismatch.exists && !mismatch.isHittable { app.swipeDown() }
            if mismatch.exists && mismatch.isHittable {
                mismatch.tap(); sleep(1)
                snap(app, "sheet-mismatch", numbered: false)
                if app.buttons[L.close].firstMatch.exists { app.buttons[L.close].firstMatch.tap() } else { app.swipeDown() }
                sleep(1)
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
        back()
        app.tabBars.buttons[L.network].tap(); sleep(1)
        snap(app, "network")
        app.tabBars.buttons[L.settings].tap(); sleep(1)
        snap(app, "settings")
        row(L.linked).tap(); sleep(1)
        snap(app, "linked-devices")
        let linkNew = app.buttons[L.linkNew]
        if linkNew.waitForExistence(timeout: 3) {
            linkNew.tap(); sleep(3)
            snap(app, "link-a-new-device-sheet")
            if app.buttons[L.close].firstMatch.exists { app.buttons[L.close].firstMatch.tap() } else { app.swipeDown() }
            sleep(1)
        }
        back()
        row(L.identity).tap(); sleep(2)
        snap(app, "my-identity")
        app.swipeUp(); sleep(1)
        snap(app, "my-identity-code")
        back()
        app.buttons["settings.transparency"].tap(); sleep(2)
        snap(app, "transparency")
        back()
        row(L.security).tap(); sleep(1)
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
            sleep(1)
            snap(app, "security-lock-on")
            // The delay is a menu (UI review B2): open it, snap it, keep the value.
            let delay = app.buttons["security.delay"]
            if delay.waitForExistence(timeout: 3) {
                delay.tap(); sleep(1)
                snap(app, "menu-lock-delay", numbered: false)
                let same = app.buttons[L.immediately].firstMatch
                if same.exists && same.isHittable { same.tap() } else { dismissDialog(0.15) }
                sleep(1)
            }
            XCUIDevice.shared.press(.home)
            app.activate()
            if app.buttons["lock.unlock"].waitForExistence(timeout: 10) {
                sleep(1)
                snap(app, "lock-screen")
            }
        }
    }

    private func snap(_ app: XCUIApplication, _ name: String, numbered: Bool = true) {
        if numbered { step += 1 }
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = numbered ? String(format: "%02d-%@", step, name) : name
        shot.lifetime = .keepAlways
        add(shot)
    }
}
