import XCTest
@testable import Barking
@testable import BarkingKit

@MainActor
final class NetworkModelTests: XCTestCase {
    func testTerminalAfterSyncNow() async {
        let d = FakeDevice()
        d.summary = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: false, error: nil)
        let m = NetworkModel(core: CoreService(device: d, runner: DirectRunner()))
        await m.syncNow()
        XCTAssertEqual(m.terminal, ["$ barking sync", "internet: network unreachable, nothing is lost"])
        XCTAssertEqual(m.internetReachable, false)
    }

    func testAddRelayLinkParsing() {
        let id = String(repeating: "A", count: 52)
        XCTAssertEqual(NetworkModel.parseRelay(link: "barking://node#\(id)@203.0.113.7:4433")?.addr, "203.0.113.7:4433")
        XCTAssertNil(NetworkModel.parseRelay(link: "barking://node#SHORT@203.0.113.7:4433"))
        XCTAssertNil(NetworkModel.parseRelay(link: "barking://node#\(id)@203.0.113.7"))
        XCTAssertNil(NetworkModel.parseRelay(link: "https://node#\(id)@203.0.113.7:4433"))
    }
}

@MainActor
final class SettingsModelTests: XCTestCase {
    func testAppearanceAndLanguagePersist() {
        let defaults = UserDefaults(suiteName: "test.\(UUID())")!
        let s = AppSettings(defaults: defaults)
        s.language = .french
        s.appearance = .dark
        let again = AppSettings(defaults: defaults)
        XCTAssertEqual(again.language, .french)
        XCTAssertEqual(again.appearance, .dark)
        XCTAssertEqual(again.colorScheme, .dark)
    }

    func testDisplayNameIsTrimmedAndBounded() {
        XCTAssertEqual(SettingsModel.validName("  Alice "), "Alice")
        XCTAssertNil(SettingsModel.validName("   "))
        XCTAssertNil(SettingsModel.validName(String(repeating: "a", count: 65)))
        XCTAssertEqual(SettingsModel.validName(String(repeating: "a", count: 64))?.count, 64)
    }
}

@MainActor
final class LinkModelTests: XCTestCase {
    func testFullFlowAgainstFake() async {
        let core = CoreService(device: FakeDevice(), runner: DirectRunner())
        let m = LinkModel(core: core, inspect: { _ in "tablet" })
        await m.start()
        guard case .offer = m.state else { return XCTFail("\(m.state)") }
        await m.scannedRequest(Data([1]))
        XCTAssertEqual(m.state, .confirm(name: "tablet"))
        await m.accept(history: true)
        guard case .share = m.state else { return XCTFail("\(m.state)") }
    }

    func testExpiredShowsExpiredText() {
        XCTAssertEqual(LinkModel.text(for: .expired), "This offer has expired. Start again.")
        XCTAssertEqual(LinkModel.text(for: .notAdmin), "Only your first device can link new ones")
    }

    func testNotAdminHidesLinkButton() async {
        let d = FakeDevice()
        d.devicesList = [MyDeviceInfo(name: "t", issuedAt: 1, thisDevice: true, admin: false)]
        let m = DevicesModel(core: CoreService(device: d, runner: DirectRunner()))
        await m.load()
        XCTAssertFalse(m.canLink)
        d.devicesList = [MyDeviceInfo(name: "a", issuedAt: 1, thisDevice: true, admin: true)]
        await m.load()
        XCTAssertTrue(m.canLink)
        XCTAssertEqual(m.count, 1)
    }
}
