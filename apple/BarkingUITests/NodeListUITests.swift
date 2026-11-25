import XCTest

/// The "Internet relays" list (node transparency spec §7.1) on the fixed
/// relays of `-BarkingUITestNodes`: rows without a percentage, one
/// VoiceOver element each, the other nodes behind a row, and "Restore the
/// default nodes" with its confirmation.
@MainActor
final class NodeListUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    private func openNetwork(language: String = "en", extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication.seeded(language: language, extra: ["-BarkingUITestNodes"] + extra)
        app.launch()
        let tab = app.tabBars.buttons[language == "fr" ? "Réseau" : "Network"]
        XCTAssertTrue(tab.waitForExistence(timeout: 10))
        tab.tap()
        return app
    }

    func testNodeList() throws {
        let app = openNetwork()
        let ovh = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "France, OVH SAS")).firstMatch
        XCTAssertTrue(ovh.waitForExistence(timeout: 10), "the verified node")
        XCTAssertTrue(ovh.label.contains("reliability good"), ovh.label)
        XCTAssertTrue(ovh.label.contains("3 subscriptions"), ovh.label)
        // One element per row: no second button reads its parts.
        XCTAssertEqual(app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "OVH SAS")).count, 1)
        let avoided = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "doesn't match")).firstMatch
        XCTAssertTrue(avoided.exists, "the node whose origin doesn't match")
        XCTAssertTrue(avoided.label.contains("avoided until"), avoided.label)
        // No percentage anywhere on the screen.
        for element in app.descendants(matching: .any).allElementsBoundByIndex where element.label.contains("%") {
            XCTFail("percentage in \(element.label)")
        }

        app.buttons["network.others"].tap()
        XCTAssertTrue(app.navigationBars["Other known nodes"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "64 ms")).firstMatch.exists)
        app.navigationBars.buttons.element(boundBy: 0).tap()

        XCTAssertTrue(app.buttons["network.blocked"].exists)
        let reset = app.buttons["network.reset"]
        XCTAssertTrue(reset.waitForExistence(timeout: 5))
        reset.tap()
        XCTAssertTrue(app.alerts.staticTexts["Restore the default nodes?"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.alerts.staticTexts.matching(NSPredicate(format: "label CONTAINS %@",
                                                                  "Blocked nodes stay blocked.")).firstMatch.exists)
        app.alerts.buttons["network.reset.confirm"].firstMatch.tap()
        XCTAssertTrue(reset.waitUntil({ !$0.exists }), "the link leaves once nothing is left to restore")
    }

    /// Opened while the launch sync still runs (six seconds here): the
    /// known relays show at once, the sync shows as running, and once it
    /// fails the tab says so.
    func testNetworkDuringTheLaunchSync() throws {
        let app = openNetwork(extra: ["-BarkingUITestSlowSync"])
        let ovh = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "France, OVH SAS")).firstMatch
        XCTAssertTrue(ovh.waitForExistence(timeout: 2), "the known relays wait for the sync")
        XCTAssertFalse(says(app, "No relay yet").exists)
        XCTAssertTrue(says(app, "Checking").exists, "the running sync is not shown")
        let result = app.descendants(matching: .any)["network.result"]
        XCTAssertTrue(result.waitForExistence(timeout: 15), "the failed sync is not said")
        XCTAssertTrue(result.label.contains("Still unreachable"), result.label)
        XCTAssertTrue(says(app, "Unreachable").exists)
        XCTAssertTrue(ovh.exists, "the relays stay after the sync")
    }

    private func says(_ app: XCUIApplication, _ text: String) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", text)).firstMatch
    }

    /// Screenshots of the list for review (`TEST_RUNNER_BARKING_NODE_SHOTS`
    /// = a folder on the Mac; `..._SIZE` = a content size category). Skipped
    /// otherwise.
    func testNodeListShots() throws {
        let env = ProcessInfo.processInfo.environment
        guard let dir = env["BARKING_NODE_SHOTS"], !dir.isEmpty else { throw XCTSkip("no shots folder") }
        let size = env["BARKING_NODE_SHOTS_SIZE"].flatMap { $0.isEmpty ? nil : ["-UIPreferredContentSizeCategoryName", $0] } ?? []
        let name = env["BARKING_NODE_SHOTS_NAME"] ?? "shot"
        let app = openNetwork(language: "fr", extra: size)
        let card = app.buttons["network.others"]
        XCTAssertTrue(app.staticTexts["Relais Internet"].waitForExistence(timeout: 10))
        var n = 0
        func save() throws {
            n += 1
            let url = URL(fileURLWithPath: dir).appendingPathComponent("task9-\(name)-\(n).png")
            try app.screenshot().pngRepresentation.write(to: url)
        }
        // A screen at a time, down to the help line under the card.
        let help = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "Les relais gardent")).firstMatch
        try save()
        for _ in 0..<8 where !(help.exists && help.isHittable && card.isHittable) {
            app.swipeUp(velocity: .slow)
            try save()
        }
        XCTAssertTrue(card.isHittable)
        card.tap()
        XCTAssertTrue(app.navigationBars["Autres nœuds connus"].waitForExistence(timeout: 5))
        try save()
    }
}
