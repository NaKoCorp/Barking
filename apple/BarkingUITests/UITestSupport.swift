import UIKit
import XCTest

extension XCUIApplication {
    /// A fresh install state (database, key and flags removed by the app).
    static func fresh(language: String = "en", extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-BarkingUITestReset", "-AppleLanguages", "(\(language))"] + noAnimations(extra) + extra
        return app
    }

    /// A ready identity made by the app at launch (Alice, with Sam as a
    /// contact when `card` is given), starting on the chats: no onboarding.
    static func seeded(_ scenario: String = "ready", card: String? = samCard, language: String = "en",
                       extra: [String] = []) -> XCUIApplication {
        var seed = ["-BarkingUITestSeed", scenario]
        if let card { seed += ["-BarkingUITestSeedCard", card] }
        return fresh(language: language, extra: seed + extra)
    }

    /// Animations are off unless the test keeps them (`-BarkingUITestKeepAnimations`).
    private static func noAnimations(_ extra: [String]) -> [String] {
        extra.contains("-BarkingUITestKeepAnimations") ? [] : ["-BarkingUITestNoAnimations"]
    }
}

extension XCUIElement {
    /// Polls `predicate` on this element until it holds or `timeout` runs out.
    /// The run loop keeps turning between polls, so this is not a fixed pause.
    @discardableResult
    func waitUntil(_ predicate: @escaping (XCUIElement) -> Bool, timeout: TimeInterval = 10) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if predicate(self) { return true }
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
        return predicate(self)
    }
}

extension XCUIElement {
    /// Waits until the element's frame has stopped moving: a scroll that has
    /// settled, so the screenshot that follows is of the final position.
    /// False when the element is missing or never settles.
    @discardableResult
    func waitUntilStill(timeout: TimeInterval = 5) -> Bool {
        guard waitForExistence(timeout: timeout) else { return false }
        let deadline = Date().addingTimeInterval(timeout)
        var last = frame
        var calm = 0
        while Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
            guard exists else { return false }
            let now = frame
            calm = now == last ? calm + 1 : 0
            last = now
            if calm >= 3 { return true }
        }
        return false
    }
}

extension XCUIElement {
    var hasKeyboardFocus: Bool { (value(forKey: "hasKeyboardFocus") as? Bool) ?? false }

    /// Scrolls the field out from under the keyboard's call-to-action bar,
    /// taps it until it holds the keyboard, then types. With the software
    /// keyboard up (CI has no hardware keyboard), a field low in a form can
    /// sit under the pinned button, which then takes the tap.
    func focusAndType(_ text: String, in app: XCUIApplication,
                      file: StaticString = #filePath, line: UInt = #line) {
        // The scroll view holding this field: under a sheet, the first one
        // in the app may be the screen behind it.
        let scroll = app.scrollViews.containing(elementType, identifier: identifier).firstMatch
        for _ in 0..<3 where !hasKeyboardFocus {
            for _ in 0..<3 where !isHittable { (scroll.exists ? scroll : app).swipeUp() }
            tap()
            waitUntil({ $0.hasKeyboardFocus }, timeout: 3)
        }
        XCTAssertTrue(hasKeyboardFocus, "\(self) never got the keyboard", file: file, line: line)
        typeText(text)
    }
}

/// From the chats of a seeded app, opens the conversation with Sam and
/// returns its message field.
@MainActor
@discardableResult
func openSamChat(_ app: XCUIApplication, file: StaticString = #filePath, line: UInt = #line) -> XCUIElement {
    let sam = app.staticTexts["Sam"].firstMatch
    XCTAssertTrue(sam.waitForExistence(timeout: 10), "Sam is not in the chats", file: file, line: line)
    sam.tap()
    let field = app.textFields["Message"]
    XCTAssertTrue(field.waitForExistence(timeout: 5), "no message field", file: file, line: line)
    return field
}

/// Creates an identity through the onboarding and lands on the chats.
@MainActor
func onboard(_ app: XCUIApplication, confirm: Bool = true) throws {
    app.buttons["Create my identity"].firstMatch.tap()
    let name = app.textFields["create.name"]
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
    XCTAssertTrue(app.buttons["New message"].waitForExistence(timeout: 10))
}

/// UI review B5 (U-32): no galaxy dot shows over Welcome's header, text or
/// buttons. Takes `shots` screenshots `gap` seconds apart and counts, inside
/// those rectangles, the pixels of the dot colours that no Welcome text
/// uses: BLE blue and LoRa yellow (both themes). Wi-Fi green is the dark ✓
/// colour and the net purple is close to the accent, so they are not
/// counted; the four dots share one mask, so two are enough.
@MainActor
func assertNoDotOverWelcomeText(_ app: XCUIApplication, shots: Int = 3, gap: UInt32 = 2,
                                file: StaticString = #filePath, line: UInt = #line) {
    let header = app.descendants(matching: .any)["welcome.header"]
    let text = app.descendants(matching: .any)["welcome.text"]
    XCTAssertTrue(text.waitForExistence(timeout: 5), "no welcome.text", file: file, line: line)
    let colours = [(0x5A, 0xB0, 0xFF), (0xD9, 0xA9, 0x20), (0xF2, 0xC9, 0x4C)]
    for i in 0..<shots {
        if i > 0 { sleep(gap) }
        let window = app.windows.firstMatch.frame
        // Full width: the dots may cross a line anywhere along it.
        let image = XCUIScreen.main.screenshot().image
        var hits = dotPixels(in: image, rects: [CGRect(x: 0, y: text.frame.minY, width: window.width,
                                                       height: window.maxY - text.frame.minY)], colours: colours)
        // The header's rooster has a LoRa-yellow beak: only blue counts there.
        if header.exists {
            hits += dotPixels(in: image, rects: [CGRect(x: 0, y: header.frame.minY, width: window.width,
                                                        height: header.frame.height)], colours: [colours[0]])
        }
        XCTAssertLessThan(hits, 6, "a galaxy dot crosses the Welcome text (\(hits) px, shot \(i))", file: file, line: line)
    }
}

/// Pixels in `rects` (points) within 10 of one of `colours`.
private func dotPixels(in image: UIImage, rects: [CGRect], colours: [(Int, Int, Int)]) -> Int {
    guard let cg = image.cgImage else { return 0 }
    let w = cg.width, h = cg.height
    var data = [UInt8](repeating: 0, count: w * h * 4)
    guard let ctx = CGContext(data: &data, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                              space: CGColorSpaceCreateDeviceRGB(),
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return 0 }
    ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))
    let scale = CGFloat(w) / image.size.width
    var hits = 0
    for r in rects {
        let px = CGRect(x: r.minX * scale, y: r.minY * scale, width: r.width * scale, height: r.height * scale)
            .intersection(CGRect(x: 0, y: 0, width: w, height: h))
        guard !px.isNull else { continue }
        for y in Int(px.minY)..<Int(px.maxY) {
            for x in Int(px.minX)..<Int(px.maxX) {
                let o = (y * w + x) * 4
                let (pr, pg, pb) = (Int(data[o]), Int(data[o + 1]), Int(data[o + 2]))
                if colours.contains(where: { abs($0.0 - pr) <= 10 && abs($0.1 - pg) <= 10 && abs($0.2 - pb) <= 10 }) {
                    hits += 1
                }
            }
        }
    }
    return hits
}
