import XCTest

extension XCUIApplication {
    /// A fresh install state (database, key and flags removed by the app).
    static func fresh(language: String = "en", extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-BarkingUITestReset", "-AppleLanguages", "(\(language))"] + extra
        return app
    }
}

/// Creates an identity through the onboarding and lands on the chats.
@MainActor
func onboard(_ app: XCUIApplication, confirm: Bool = true) throws {
    app.buttons["Create my identity"].firstMatch.tap()
    let name = app.textFields["Your name, as contacts see it"]
    XCTAssertTrue(name.waitForExistence(timeout: 5))
    name.tap()
    name.typeText("Alice")
    app.buttons["Create my identity"].firstMatch.tap()
    XCTAssertTrue(app.staticTexts["Your recovery phrase"].waitForExistence(timeout: 10))
    var words: [Int: String] = [:]
    for i in 1...24 {
        let index = app.staticTexts.matching(identifier: "phrase.word.\(i)").firstMatch
        if index.exists { words[i] = index.label }
    }
    XCTAssertEqual(words.count, 24)
    let wrote = app.descendants(matching: .any)["phrase.wroteItDown"]
    while !wrote.isHittable { app.swipeUp() }
    wrote.tap()
    app.buttons["Continue"].tap()
    if confirm {
        for q in 0..<3 {
            let label = app.staticTexts.matching(identifier: "quiz.question.\(q)").firstMatch
            XCTAssertTrue(label.waitForExistence(timeout: 5))
            let n = Int(label.value as? String ?? "") ?? 0
            app.buttons["quiz.\(q).\(words[n] ?? "")"].tap()
        }
        app.buttons["Confirm"].tap()
    } else {
        app.buttons["Later"].tap()
    }
    XCTAssertTrue(app.navigationBars["Chats"].waitForExistence(timeout: 10))
}
