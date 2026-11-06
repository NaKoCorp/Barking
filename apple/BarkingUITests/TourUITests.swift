import XCTest

/// Screenshots of every screen, for UI review. Skipped unless
/// TEST_RUNNER_BARKING_TOUR is set; TEST_RUNNER_BARKING_TOUR_LANG=fr runs the
/// same tour in French (labels below, identifiers where they exist).
@MainActor
final class TourUITests: XCTestCase {
    private struct Labels {
        let create, namePlaceholder, phraseTitle, cont, confirm, later, add, message, send: String
        let chats, network, settings, linked, identity, security, recover, link, pdf, linkNew, close, cancel: String
        let lockedTitle: String

        static let en = Labels(
            create: "Create my identity", namePlaceholder: "Your name, as contacts see it",
            phraseTitle: "Your recovery phrase", cont: "Continue", confirm: "Confirm", later: "Later",
            add: "Add", message: "Message", send: "Send", chats: "Chats", network: "Network",
            settings: "Settings", linked: "Linked devices", identity: "My identity", security: "Security",
            recover: "Recover with 24 words", link: "Link to an existing device", pdf: "Encrypted PDF",
            linkNew: "Link a new device", close: "Close", cancel: "Cancel", lockedTitle: "Barking is locked")
        static let fr = Labels(
            create: "Créer mon identité", namePlaceholder: "Votre nom, tel que vos contacts le voient",
            phraseTitle: "Votre phrase de récupération", cont: "Continuer", confirm: "Confirmer", later: "Plus tard",
            add: "Ajouter", message: "Message", send: "Envoyer", chats: "Discussions", network: "Réseau",
            settings: "Réglages", linked: "Appareils liés", identity: "Mon identité", security: "Sécurité",
            recover: "Restaurer avec 24 mots", link: "Lier à un appareil existant", pdf: "PDF chiffré",
            linkNew: "Lier un nouvel appareil", close: "Fermer", cancel: "Annuler", lockedTitle: "Barking est verrouillé")
    }

    private var step = 0

    func testTour() throws {
        let env = ProcessInfo.processInfo.environment
        try XCTSkipIf(env["BARKING_TOUR"] == nil)
        let lang = env["BARKING_TOUR_LANG"] ?? "en"
        let L = lang == "fr" ? Labels.fr : Labels.en
        let app = XCUIApplication.fresh(language: lang, extra: [
            "-BarkingUITestOpenCard", samCard, "-BarkingUITestFakeRoute", "-BarkingUITestNoAutoUnlock"])
        app.launch()
        let back = { app.navigationBars.buttons.firstMatch.tap() }
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
        let name = app.textFields[L.namePlaceholder]
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
        if header.exists {
            header.tap(); sleep(2)
            snap(app, "safety-code")
            app.swipeUp(); sleep(1)
            snap(app, "safety-code-devices")
            back()
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
        let toggle = app.switches["security.lock"]
        if toggle.waitForExistence(timeout: 5) {
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
            sleep(1)
            snap(app, "security-lock-on")
            XCUIDevice.shared.press(.home)
            app.activate()
            if app.buttons["lock.unlock"].waitForExistence(timeout: 10) {
                sleep(1)
                snap(app, "lock-screen")
            }
        }
    }

    private func snap(_ app: XCUIApplication, _ name: String) {
        step += 1
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = String(format: "%02d-%@", step, name)
        shot.lifetime = .keepAlways
        add(shot)
    }
}
