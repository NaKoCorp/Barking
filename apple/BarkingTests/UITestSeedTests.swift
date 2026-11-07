import XCTest
@testable import Barking
@testable import BarkingKit

/// The launch seed UI tests use instead of walking the onboarding. Every
/// test ends by erasing the identity: the unit tests share one app container.
@MainActor
final class UITestSeedTests: XCTestCase {
    // Same card as BarkingUITests/Fixtures.swift (the targets share no files).
    private let samCardForTests = "barking1:A1NhbSngcBhfnN_7CUjVsBU_mOyCxuGsgNEgn9WUkitXdumC6quz1wYBKeBwGF-c3_sJSNWwFT-Y7ILG4ayA0SCf1ZSSK1d26YKjqflhDheqKctNGB7thMl_ut4HIWKiUCMIKS9kAzQ4utAcoJ1e6fmZ0UtfP0F3sSrpG8YU3wNOfn3HLRnkt3cfB2ZpeHR1cmXqq7PXBs3tLKmmt3krL9ZYAfJHDhI3LJcfIupdsJN_QOYzQKsaO-Q1l-cNMbebWCbUsBwAXKfcJO33HODf9qyuw8qztgynB6V-0NrHNeZMCsExpZBC2v5E4srTCEdvA0JBIsIR99bP0dY9OTl4kFXSmrNWeHF-jfDmKw-BQS7dyrM9zMwPQKu-3m2LJ6Pu5jJZXGAhdvNioEBZ7Hz-orHNxnT_efUvJek6ANkRGAfCPbqMSR5TlayraUHmFNju5IdBof0nBwGjqflhDheqKctNGB7thMl_ut4HIWKiUCMIKS9kAzQ4utAcoJ1e6fmZ0UtfP0F3sSrpG8YU3wNOfn3HLRnkt3cfzq_95AT06BjmIRVee23cFJODvIS1DXQp693v48Lm-gtdm_zUYOKv7YsDoAn0aC3tU2MH1SqOFg5U2AKmwZTX1WV8Irv4mX2cOEyNq7SXZFIoBVWZGmFyBW6q55ZkkRXqRZFoRyuMOg-bCAuE8oT6IV936a1alozWVJf2WqHptBMu02sFoXaAnI5EUH7bV5LH-GPBs5ATKBI_d2IXsoWEbH7nfHgour3SaaeSdIWGlMIJ3LTTp1gEpzYuiQKfsJu0zGgdWEilW02hc8nvho2nogXaaDoiWYyw-GWVC7mht2dwpGGexoRDQAbVsotb0XHFDFORMqs4RmxhvF9csnVtUA09JiJwkaxyppt4d2jErALs9JclYbUyRUkP5g2rq53t5zb8OZqEBBMMFm0QRVooayD5McQCCRLa6MpsWhRB58mrt4_esc5Y96Xm0sBithC1kQGHxMdEl3a1kIcwMMxeFIBsfKYR6mT3CGR6h7OMYhDY9GhGd8jiAmsfq0XKEpdalyd-pUyZyEABhR6T9IX7YqD9QHK3ObvmmM6GdJQV13bLqAJBxZRHOpFVRWml1WPkJ1N9iT0JiFK0FyWzsj7dl8HVBiBCA7b-qziEFx0F6EShkZx0gbzEOQGT4BQ2N7Sq4bay-6_CIL-BhgFcBLxElqPD1GvTAExdcsfG1rwEqKvIN8OWhDlG3G6GBXlfSU_RHBb0qycBRjT2ShKl5qy2IA2HuxxhuIxKKrTCaWGtunCsiS7KfIJuCC7WQJgV9apvw4B2nKe1kydpa7D-tjhYFnAVwVt_bMhBgEh32cNW2Z4nVqbjdVe5fJ0y4wcu9nmtnLUzkrsVK3G7fEtW6Gfet54-1JYtBidpMapbALxFoFmkEEpIhnHxpXqGgGPibMpcZq-Z7KSJJHeqFVJtxZvMNTLYw5f9S1O-Kah93FFasxM_lsgzxQ1aiwSdq5cdh7mJwlqTyA24JINyczGau1GvADDhWyKO52dtCn_n5hmqRwANR1S7tMK2LG_PFByORXV5aAihXGZyCZpQqcZfe6q6WEP_m0nAYUL73GDcFT_4Ecmu4sbX5ZaxwqLkC8qo643FYomGWCJhXGmWSrEP_GNB1r78WQVYVFgasZWW8MtyEgNW4GtlWb1gJFXysXCqQ5y3o3lk0U7sPLF8wB1U7H7zYIr7VAqgXHiruscrWXv5e73KnDVrhyg5FZj2ZxV1WVQZg1SVaJ_v14WKtGkpSzODpA4AirXqrJZOwM6G0k6g-K41Y4K5SyLg-aJEpmfw20GZRKpnTF6vN6W2nEI29JV_WByrZJKg_G1ju5nrmBq5ESfsdKAuS32Ux2GJkyOYh3Mo0gCOaYXJs5v2wxVk64ga4Jv_c2_91DBng2481EP0NXlT01VzyCqYwpzy2bdmCIzurIG8uAO7kAdyU8ewQAeJHHHyYZkXIK5BUIbTTDKD54yr95SuMIzG84U7G4d3UZp7sFBBFwfSRQ_6kEtmdlRNDEC55B2iG7Cl6xz16lYI1hsk-WKXKI12JSUzoAKJWA2ac1QWijTQAz-7povPVQEf5mCp1DSm8XCNl8RCaXN0DA3gS5hIU7pBZVqqg1q5SwUhqgVkOWiFqlfnLY8TKrb-DOGCXVPlxkm_lvOoCgATzoJmjiHtfE55ZSZ0-XdYBuSYcHOFn03numg6HBQ_L0WEnO4cbfsRCcK2caCcnLPkATybg2rmdAdm0PxatzAAgqFSbq5VNH5G-nhJbfHiSKVf6K_l6L17HudNwy2_TozuRnhC-yO3gSpMp47AyZaM0B7OXFPunDdiHs06gvMbAA"

    override func setUp() async throws { eraseIdentity() }
    override func tearDown() async throws { eraseIdentity() }

    private func eraseIdentity() {
        try? DeviceFactory.resetIdentity()
        for key in [OnboardingModel.confirmedKey, "barking.appearance", UITestDeliveries.Seed.key] {
            UserDefaults.standard.removeObject(forKey: key)
        }
    }

    func testReadyCreatesAConfirmedIdentityWithSam() throws {
        try UITestSeed.apply(["-BarkingUITestReset", "-BarkingUITestSeed", "ready", "-BarkingUITestSeedCard", samCardForTests])
        XCTAssertTrue(UserDefaults.standard.bool(forKey: OnboardingModel.confirmedKey))
        let device = try XCTUnwrap(DeviceFactory.openExisting(lockTimeoutMs: 1_000))
        XCTAssertEqual(try device.displayName(), "Alice")
        XCTAssertEqual(try device.contacts().map(\.alias), ["Sam"])
    }

    func testReadyWithoutCardHasNoContact() throws {
        try UITestSeed.apply(["-BarkingUITestReset", "-BarkingUITestSeed", "ready"])
        XCTAssertTrue(UserDefaults.standard.bool(forKey: OnboardingModel.confirmedKey))
        let device = try XCTUnwrap(DeviceFactory.openExisting(lockTimeoutMs: 1_000))
        XCTAssertTrue(try device.contacts().isEmpty)
    }

    func testNoSeedArgumentDoesNothing() throws {
        try UITestSeed.apply(["-BarkingUITestReset"])
        XCTAssertNil(try DeviceFactory.openExisting(lockTimeoutMs: 1_000))
    }

    func testUnknownScenarioThrows() {
        XCTAssertThrowsError(try UITestSeed.apply(["-BarkingUITestSeed", "nope"])) {
            XCTAssertEqual($0 as? UITestSeed.Error, .unknownScenario("nope"))
        }
    }

    func testDeliveriesWithoutCardThrows() {
        XCTAssertThrowsError(try UITestSeed.apply(["-BarkingUITestReset", "-BarkingUITestSeed", "deliveries"])) {
            XCTAssertEqual($0 as? UITestSeed.Error, .missingCard("deliveries"))
        }
    }

    // MARK: The deliveries scenario (spec Lot M §6.8)

    private let deliveriesArgs = ["-BarkingUITestReset", "-BarkingUITestSeed", "deliveries"]

    /// The seeded device seen through the decorator, and Sam.
    private func seededDeliveries() throws -> (device: any DeviceHandle, sam: String, ids: [Int64]) {
        let args = deliveriesArgs + ["-BarkingUITestSeedCard", samCardForTests]
        try UITestSeed.apply(args)
        let real = try XCTUnwrap(DeviceFactory.openExisting(lockTimeoutMs: 1_000))
        let device = UITestDeliveries.wrap(real, arguments: args)
        XCTAssertTrue(device is UITestDeliveries)
        let seed = try XCTUnwrap(UITestDeliveries.Seed.load())
        return (device, seed.contact, seed.ids)
    }

    func testDeliveriesForcesTheFourStatesEverywhere() throws {
        let (device, sam, ids) = try seededDeliveries()
        XCTAssertEqual(ids.count, 4)
        let sent = try device.messagesWith(contact: sam)
        XCTAssertEqual(sent.map(\.body), UITestDeliveries.bodies())
        XCTAssertEqual(sent.map { $0.delivery?.state }, [.notDelivered, .received, .onNetwork, .pending])
        let received = try XCTUnwrap(sent[1].delivery)
        XCTAssertEqual([received.devicesReceived, received.devices], [1, 2])
        XCTAssertEqual(try device.deliveriesOf(ids: ids).map { $0.delivery?.state },
                       [.notDelivered, .received, .onNetwork, .pending])
        let sheet = try XCTUnwrap(device.messageDelivery(messageId: ids[1]))
        XCTAssertEqual(sheet.devices.map(\.state), [.received, .onNetwork])
        XCTAssertEqual(sheet.relays.map(\.node), [UITestDeliveries.relay])
        XCTAssertEqual(try device.deliveryCounts(contact: sam),
                       DeliveryCounts(pending: 1, onNetwork: 1, received: 1, notDelivered: 1))
        XCTAssertEqual(try device.deliveryPage(contact: sam, state: .received, limit: 50, offset: 0).map(\.messageId),
                       [ids[1]])
        // "Pending" shows the pending one only, and the Network count is its total.
        let pending = try device.pendingPackets()
        XCTAssertEqual(pending.messages.map(\.messageId), [ids[3]])
        XCTAssertFalse(pending.sync.isEmpty)
        XCTAssertEqual(pending.packets, UInt32(pending.messages.reduce(0) { $0 + $1.packets }
                                              + pending.sync.reduce(0) { $0 + $1.packets }))
        XCTAssertEqual(try device.pendingCount(), pending.packets)
        // No network in this world: a sync says so at once.
        XCTAssertFalse(try device.sync(deadlineMs: 8_000).networkUp)
    }

    func testDeliveriesRetryShowsTheRealStateAndCancelAllKeepsTheOthers() throws {
        let (device, sam, ids) = try seededDeliveries()
        try device.retryMessage(messageId: ids[0])
        XCTAssertEqual(try device.deliveriesOf(ids: [ids[0]]).first?.delivery?.state, .pending)
        XCTAssertEqual(try device.deliveryCounts(contact: sam).notDelivered, 0)
        XCTAssertEqual(try device.pendingPackets().messages.map(\.messageId).sorted(), [ids[0], ids[3]])
        let outcome = try device.cancelAllPending()
        XCTAssertEqual(outcome.deleted, 2)
        XCTAssertEqual(try device.messagesWith(contact: sam).map(\.id), [ids[1], ids[2]])
        let left = try device.pendingPackets()
        XCTAssertTrue(left.messages.isEmpty)
        XCTAssertEqual(try device.pendingCount(), left.packets)
    }

    func testNoDecoratorWithoutItsArguments() throws {
        try UITestSeed.apply(["-BarkingUITestReset", "-BarkingUITestSeed", "ready", "-BarkingUITestSeedCard", samCardForTests])
        let real = try XCTUnwrap(DeviceFactory.openExisting(lockTimeoutMs: 1_000))
        XCTAssertTrue(UITestDeliveries.wrap(real, arguments: ["-BarkingUITestSeed", "ready"]) === real)
        let fake = UITestDeliveries.wrap(real, arguments: ["-BarkingUITestFakeReceived"])
        let sam = try XCTUnwrap(real.contacts().first?.fingerprint)
        XCTAssertEqual(try fake.messagesWith(contact: sam).map(\.body), ["hi from Sam"])
    }

    // MARK: Guards on the UI test sources

    private func uiTestSources() throws -> [(name: String, text: String)] {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("BarkingUITests")
        guard let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) else {
            throw XCTSkip("UI test sources not readable at \(root.path)")
        }
        return try walker.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
            .map { ($0.lastPathComponent, try String(contentsOf: $0, encoding: .utf8)) }
    }

    /// A test waits for the element the next screen shows; the only `sleep(`
    /// left is the gap between two screenshots in assertNoDotOverWelcomeText.
    func testNoSleepInUITests() throws {
        let files = try uiTestSources()
        XCTAssertTrue(files.contains { $0.name == "TourUITests.swift" }, "BarkingUITests not scanned")
        for file in files {
            var inAllowed = false
            for (i, line) in file.text.components(separatedBy: "\n").enumerated() {
                if line.contains("func assertNoDotOverWelcomeText") { inAllowed = true }
                else if inAllowed, line.hasPrefix("}") { inAllowed = false; continue }
                if !inAllowed, line.contains("sleep(") {
                    XCTFail("\(file.name):\(i + 1): sleep( outside assertNoDotOverWelcomeText")
                }
            }
        }
    }

    /// These tests cover the welcome and onboarding screens: each one still
    /// walks the screen it is about and never starts from the seed.
    func testOnboardingTestsStillOnboard() throws {
        let flow = try XCTUnwrap(try uiTestSources().first { $0.name == "FlowUITests.swift" }?.text)
        // What each body must still do (any one of the strings).
        let walks: [String: [String]] = [
            "testCreateIdentityAndConfirmPhrase": ["onboard("],
            "testFieldFooterIsReadOnce": ["Create my identity"],
            "testWelcomeDotsStayOffTheText": ["-BarkingUITestKeepAnimations"],
            "testRecoverTileSaysItsWord": ["Recover with 24 words"],
            "testLaterKeepsTheBanner": ["onboard("],
            "testAppearanceChosenOnWelcomeIsKept": ["appearance.dark"]]
        XCTAssertEqual(walks.count, 6)
        for (name, needles) in walks {
            let start = try XCTUnwrap(flow.range(of: "func \(name)()"), "\(name) not found")
            let rest = flow[start.upperBound...]
            let end = rest.range(of: "\n    }\n")?.lowerBound ?? rest.endIndex
            let body = rest[..<end]
            XCTAssertTrue(needles.contains { body.contains($0) }, "\(name) lost \(needles)")
            XCTAssertFalse(body.contains("seeded(") || body.contains("-BarkingUITestSeed"),
                           "\(name) must not use the seed")
        }
    }
}
