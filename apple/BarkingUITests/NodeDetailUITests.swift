import XCTest

/// A node's detail (node transparency spec §7.2 to §7.4) on the fixed
/// relays of `-BarkingUITestNodes`: the table and its verdict, the ⓘ
/// sheets, an old node, blocking with the guard-rail, and unblocking.
@MainActor
final class NodeDetailUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    private func openNetwork(language: String = "en", extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication.seeded(language: language, extra: ["-BarkingUITestNodes"] + extra)
        app.launch()
        let tab = app.tabBars.buttons[language == "fr" ? "Réseau" : "Network"]
        XCTAssertTrue(tab.waitForExistence(timeout: 10))
        tab.tap()
        return app
    }

    /// The row whose spoken label starts with `prefix` ("France, OVH SAS").
    private func row(_ app: XCUIApplication, _ prefix: String) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", prefix)).firstMatch
    }

    private func open(_ app: XCUIApplication, _ prefix: String) {
        let r = row(app, prefix)
        XCTAssertTrue(r.waitForExistence(timeout: 10), prefix)
        r.tap()
    }

    /// Scrolls until `element` can be tapped.
    private func reveal(_ element: XCUIElement, in app: XCUIApplication) {
        for _ in 0..<8 where !(element.exists && element.isHittable) { app.swipeUp(velocity: .slow) }
    }

    /// The verified node: its table agrees, every row is one element with
    /// its sentence, an ⓘ opens a plain explanation, no percentage.
    func testNodeDetailAndExplanations() throws {
        let app = openNetwork()
        open(app, "France, OVH SAS")
        let verdict = app.descendants(matching: .any)["node.verdict"]
        XCTAssertTrue(verdict.waitForExistence(timeout: 10))
        XCTAssertTrue(verdict.label.contains("Matches what this iPhone sees"), verdict.label)
        XCTAssertTrue(app.descendants(matching: .any)["node.version"].label.contains("0.5.0 · protocol 5"))
        let reliability = app.buttons["node.reliability"]
        reveal(reliability, in: app)
        // Value, then the sentence always shown under it (§7.3).
        XCTAssertTrue(reliability.label.contains("good"), reliability.label)
        XCTAssertTrue(reliability.label.contains("This relay has been answering your iPhone well lately."))
        reliability.tap()
        XCTAssertTrue(app.staticTexts["How Barking judges a relay"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "your iPhone alone"))
            .firstMatch.exists)
        app.buttons["explain.close"].tap()
        XCTAssertTrue(app.staticTexts["How Barking judges a relay"].waitUntil({ !$0.exists }))
        for element in app.descendants(matching: .any).allElementsBoundByIndex where element.label.contains("%") {
            XCTFail("percentage in \(element.label)")
        }
        // A default node can be removed.
        let remove = app.buttons["node.remove"]
        reveal(remove, in: app)
        XCTAssertTrue(remove.exists)
    }

    /// The node that doesn't match: an amber banner naming both countries,
    /// and, as it never answers, the cached detail with "unreachable". It
    /// was found on the network: no "Remove".
    func testMismatchAndUnreachable() throws {
        let app = openNetwork()
        open(app, "Netherlands, Hetzner")
        let banner = app.descendants(matching: .any)["node.mismatch"]
        XCTAssertTrue(banner.waitForExistence(timeout: 10))
        XCTAssertTrue(banner.label.contains("Declared Netherlands · observed Germany"), banner.label)
        XCTAssertTrue(app.descendants(matching: .any)["node.unreachable"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.descendants(matching: .any)["node.version"].exists, "the cached report stays")
        let block = app.buttons["node.block"]
        reveal(block, in: app)
        XCTAssertTrue(block.exists)
        XCTAssertFalse(app.buttons["node.remove"].exists)
    }

    /// A node older than 0.5 tells nothing of itself.
    func testOldNodeSaysNotShared() throws {
        let app = openNetwork()
        open(app, "Germany, netcup")
        let line = app.descendants(matching: .any)["node.notShared"]
        XCTAssertTrue(line.waitForExistence(timeout: 10))
        XCTAssertTrue(line.label.contains("not shared · node version older than 0.5"), line.label)
    }

    /// Block: the confirmation with the guard-rail, "Blocked", back to the
    /// list, which no longer shows it and counts one more blocked node.
    func testBlockedNodeLeavesListAfterBlock() throws {
        let app = openNetwork()
        open(app, "France, OVH SAS")
        let block = app.buttons["node.block"]
        XCTAssertTrue(block.waitForExistence(timeout: 10))
        reveal(block, in: app)
        block.tap()
        let warning = app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@",
                                                           "Only 2 usable nodes would be left")).firstMatch
        XCTAssertTrue(warning.waitForExistence(timeout: 5), "the guard-rail (§6.4)")
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@",
                                                           "Barking stops talking to it at once.")).firstMatch.exists)
        app.buttons["Block"].firstMatch.tap()
        let blocked = app.buttons["network.blocked"]
        XCTAssertTrue(blocked.waitForExistence(timeout: 10), "back to the list")
        XCTAssertTrue(row(app, "France, OVH SAS").waitUntil({ !$0.exists }), "the blocked node left the list")
        XCTAssertTrue(blocked.waitUntil({ $0.label.contains("(2)") }), blocked.label)
    }

    /// Unblock from the list: the node leaves it (it comes back only by the
    /// usual ways, never by itself).
    func testUnblockFromBlockedList() throws {
        let app = openNetwork()
        let blocked = app.buttons["network.blocked"]
        reveal(blocked, in: app)
        XCTAssertTrue(blocked.waitForExistence(timeout: 10))
        blocked.tap()
        XCTAssertTrue(app.navigationBars["Blocked nodes"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "Example Hosting · US"))
            .firstMatch.exists, "the origin known when blocked")
        let unblock = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH %@", "blockedNode.unblock"))
            .firstMatch
        XCTAssertTrue(unblock.exists)
        unblock.tap()
        XCTAssertTrue(app.staticTexts["blockedNodes.empty"].waitForExistence(timeout: 5))
        app.navigationBars.buttons.element(boundBy: 0).tap()
        XCTAssertTrue(app.buttons["network.blocked"].waitUntil({ !$0.exists }), "no blocked node left")
    }

    /// Settings › Licences credits the IP base the verdict comes from (§6.3).
    func testLicensesCreditTheIPBase() throws {
        let app = openNetwork()
        app.tabBars.buttons["Settings"].tap()
        let row = app.buttons["settings.licenses"]
        for _ in 0..<6 where !(row.exists && row.isHittable) { app.swipeUp(velocity: .slow) }
        row.tap()
        let ipdb = app.descendants(matching: .any)["licenses.ipdb"]
        XCTAssertTrue(ipdb.waitForExistence(timeout: 5))
        XCTAssertTrue(ipdb.label.contains("IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"), ipdb.label)
        XCTAssertTrue(app.descendants(matching: .any)["licenses.font"].label.contains("SIL Open Font License 1.1"))
    }

    /// Screenshots for review (`TEST_RUNNER_BARKING_NODE_SHOTS` = a folder
    /// on the Mac; `..._SIZE` = a content size category; `..._NAME` = a
    /// prefix). French; skipped otherwise.
    func testNodeDetailShots() throws {
        let env = ProcessInfo.processInfo.environment
        guard let dir = env["BARKING_NODE_SHOTS"], !dir.isEmpty else { throw XCTSkip("no shots folder") }
        let size = env["BARKING_NODE_SHOTS_SIZE"].flatMap { $0.isEmpty ? nil : ["-UIPreferredContentSizeCategoryName", $0] } ?? []
        let name = env["BARKING_NODE_SHOTS_NAME"] ?? "shot"
        let app = openNetwork(language: "fr", extra: size)
        func save(_ label: String) throws {
            let url = URL(fileURLWithPath: dir).appendingPathComponent("task10-\(name)-\(label).png")
            try app.screenshot().pngRepresentation.write(to: url)
        }
        /// Every screen of the detail, top to the danger zone.
        func shootDetail(_ prefix: String, _ label: String) throws {
            open(app, prefix)
            XCTAssertTrue(app.descendants(matching: .any)["node.origin"].waitForExistence(timeout: 10))
            // Let the refresh come back (or fail) before the first shot.
            _ = app.descendants(matching: .any)["node.asking"].waitUntil({ !$0.exists }, timeout: 5)
            let block = app.buttons["node.block"]
            var n = 1
            try save("\(label)-\(n)")
            while n < 10 && !(block.exists && block.isHittable) {
                app.swipeUp(velocity: .slow)
                n += 1
                try save("\(label)-\(n)")
            }
            app.navigationBars.buttons.element(boundBy: 0).tap()
        }
        try shootDetail("France, OVH SAS", "matches")
        try shootDetail("Pays-Bas, Hetzner", "mismatch")
        try shootDetail("Allemagne, netcup", "old")
        // An ⓘ sheet, the block confirmation, then the blocked list.
        open(app, "France, OVH SAS")
        let reliability = app.buttons["node.reliability"]
        reveal(reliability, in: app)
        reliability.tap()
        XCTAssertTrue(app.buttons["explain.close"].waitForExistence(timeout: 5))
        try save("explain")
        app.buttons["explain.close"].tap()
        let block = app.buttons["node.block"]
        reveal(block, in: app)
        block.tap()
        XCTAssertTrue(app.buttons["Bloquer"].firstMatch.waitForExistence(timeout: 5))
        try save("block-confirm")
        app.buttons["Bloquer"].firstMatch.tap()
        let blocked = app.buttons["network.blocked"]
        XCTAssertTrue(blocked.waitForExistence(timeout: 10))
        reveal(blocked, in: app)
        blocked.tap()
        XCTAssertTrue(app.navigationBars["Nœuds bloqués"].waitForExistence(timeout: 5))
        try save("blocked")
    }
}
