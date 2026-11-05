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
    func testAppearancePersists() {
        let defaults = UserDefaults(suiteName: "test.\(UUID())")!
        let s = AppSettings(defaults: defaults)
        XCTAssertEqual(s.appearance, .system)
        XCTAssertNil(s.colorScheme)
        s.appearance = .dark
        let again = AppSettings(defaults: defaults)
        XCTAssertEqual(again.appearance, .dark)
        XCTAssertEqual(again.colorScheme, .dark)
    }

    /// The language now comes from the phone: a choice saved by the old
    /// in-app picker would hide it, so it is dropped.
    func testOldLanguageChoiceIsDropped() {
        let defaults = UserDefaults(suiteName: "test.\(UUID())")!
        defaults.set("french", forKey: "barking.language")
        _ = AppSettings(defaults: defaults)
        XCTAssertNil(defaults.object(forKey: "barking.language"))
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
        d.devicesList = [MyDeviceInfo(id: "t", name: "t", issuedAt: 1, thisDevice: true, admin: false)]
        let m = DevicesModel(core: CoreService(device: d, runner: DirectRunner()))
        await m.load()
        XCTAssertFalse(m.canLink)
        d.devicesList = [MyDeviceInfo(id: "a", name: "a", issuedAt: 1, thisDevice: true, admin: true)]
        await m.load()
        XCTAssertTrue(m.canLink)
        XCTAssertEqual(m.count, 1)
    }

    func testAdminCanTransferToAnotherDevice() async {
        let d = FakeDevice()
        let me = MyDeviceInfo(id: "a", name: "a", issuedAt: 1, thisDevice: true, admin: true)
        let tablet = MyDeviceInfo(id: "t", name: "t", issuedAt: 2, thisDevice: false, admin: false)
        d.devicesList = [me, tablet]
        let m = DevicesModel(core: CoreService(device: d, runner: DirectRunner()))
        await m.load()
        XCTAssertFalse(m.canTransfer(to: me))
        XCTAssertTrue(m.canTransfer(to: tablet))
        await m.transfer(to: tablet)
        XCTAssertEqual(d.transferredTo, ["t"])
        XCTAssertEqual(m.pendingTarget, "t")
        XCTAssertFalse(m.canTransfer(to: tablet))
        XCTAssertFalse(m.canLink)
    }

    func testNonAdminCannotTransfer() async {
        let d = FakeDevice()
        let tablet = MyDeviceInfo(id: "t", name: "t", issuedAt: 2, thisDevice: false, admin: true)
        d.devicesList = [MyDeviceInfo(id: "a", name: "a", issuedAt: 1, thisDevice: true, admin: false), tablet]
        let m = DevicesModel(core: CoreService(device: d, runner: DirectRunner()))
        await m.load()
        XCTAssertFalse(m.canTransfer(to: tablet))
    }

    func testRemovedDeviceCannotLinkNorTransfer() async {
        let d = FakeDevice()
        let tablet = MyDeviceInfo(id: "t", name: "t", issuedAt: 2, thisDevice: false, admin: false)
        d.devicesList = [MyDeviceInfo(id: "a", name: "a", issuedAt: 1, thisDevice: true, admin: true), tablet]
        d.removedInfo = RemovedInfo(version: 9, at: 1)
        let m = DevicesModel(core: CoreService(device: d, runner: DirectRunner()))
        await m.load()
        XCTAssertTrue(m.removed)
        XCTAssertFalse(m.canLink)
        XCTAssertFalse(m.canTransfer(to: tablet))
    }

    func testRemovedDeviceCannotSend() async {
        let d = FakeDevice()
        d.removedInfo = RemovedInfo(version: 9, at: 1)
        let m = ConversationModel(contact: "c", core: CoreService(device: d, runner: DirectRunner()))
        await m.onAppear()
        m.draft = "hello"
        XCTAssertFalse(m.canSend)
    }
}

/// Counts the wipes a model asked for.
@MainActor
final class WipeRecorder {
    var count = 0
    func wipe(_ core: CoreService) async { count += 1 }
}

@MainActor
final class DevicesModelTests: XCTestCase {
    private let me = MyDeviceInfo(id: "a", name: "iPhone", issuedAt: 1, thisDevice: true, admin: true)
    private let tablet = MyDeviceInfo(id: "t", name: "iPad", issuedAt: 2, thisDevice: false, admin: false)

    private func model(_ d: FakeDevice, owner: Bool = true, wipes: WipeRecorder = WipeRecorder()) -> DevicesModel {
        DevicesModel(core: CoreService(device: d, runner: DirectRunner()),
                     owner: { owner }, wipe: { await wipes.wipe($0) })
    }

    func testAdminSeesRemoveOnOthersAndDisconnectOnSelf() async {
        let d = FakeDevice()
        d.devicesList = [me, tablet]
        let admin = model(d)
        await admin.load()
        XCTAssertTrue(admin.canRemove(tablet))
        XCTAssertFalse(admin.canRemove(me))
        XCTAssertTrue(admin.canDisconnect(me))
        XCTAssertFalse(admin.canDisconnect(tablet))

        let linkedMe = MyDeviceInfo(id: "t", name: "iPad", issuedAt: 2, thisDevice: true, admin: false)
        let adminOther = MyDeviceInfo(id: "a", name: "iPhone", issuedAt: 1, thisDevice: false, admin: true)
        d.devicesList = [adminOther, linkedMe]
        let linked = model(d)
        await linked.load()
        XCTAssertFalse(linked.canRemove(adminOther))
        XCTAssertTrue(linked.canDisconnect(linkedMe))
    }

    func testDisconnectPlans() async {
        let d = FakeDevice()
        d.devicesList = [me]
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.disconnectPlan, .erase)
        d.devicesList = [me, tablet]
        await m.load()
        XCTAssertEqual(m.disconnectPlan, .handOver(candidates: [tablet]))
        d.devicesList = [MyDeviceInfo(id: "t", name: "iPad", issuedAt: 2, thisDevice: true, admin: false),
                         MyDeviceInfo(id: "a", name: "iPhone", issuedAt: 1, thisDevice: false, admin: true)]
        await m.load()
        XCTAssertEqual(m.disconnectPlan, .leave)
    }

    func testRemoveNeedsTheOwner() async {
        let d = FakeDevice()
        d.devicesList = [me, tablet]
        let refused = model(d, owner: false)
        await refused.load()
        await refused.remove(tablet)
        XCTAssertEqual(d.removedIds, [])

        let m = model(d)
        await m.load()
        await m.remove(tablet)
        XCTAssertEqual(d.removedIds, ["t"])
        XCTAssertFalse(m.removeFailed)
    }

    func testLinkedLeaveWipesOnceSent() async {
        let d = FakeDevice()
        d.devicesList = [MyDeviceInfo(id: "t", name: "iPad", issuedAt: 2, thisDevice: true, admin: false)]
        let wipes = WipeRecorder()
        let m = model(d, wipes: wipes)
        await m.load()
        await m.disconnect()
        XCTAssertEqual(d.leaveCalls, 1)
        XCTAssertGreaterThanOrEqual(d.syncCalls, 1)
        XCTAssertEqual(wipes.count, 1)
        XCTAssertEqual(m.departure, .wiped)
    }

    func testLeaveOfflineErasesNothing() async {
        let d = FakeDevice()
        d.devicesList = [MyDeviceInfo(id: "t", name: "iPad", issuedAt: 2, thisDevice: true, admin: false)]
        d.summary = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: false, error: nil)
        let wipes = WipeRecorder()
        let m = model(d, wipes: wipes)
        await m.load()
        await m.disconnect()
        XCTAssertEqual(m.departure, .offline)
        XCTAssertEqual(wipes.count, 0)
        // Back online: the retry sends the request, then wipes.
        d.summary = SyncSummary(itemsReceived: 0, sent: 1, newMessages: [], networkUp: true, error: nil)
        await m.finishLeaving()
        XCTAssertEqual(wipes.count, 1)
        XCTAssertEqual(d.leaveCalls, 1)
    }

    func testDeclinedOwnerErasesNothing() async {
        let d = FakeDevice()
        d.devicesList = [me]
        let wipes = WipeRecorder()
        let m = model(d, owner: false, wipes: wipes)
        await m.load()
        await m.disconnect()
        XCTAssertEqual(wipes.count, 0)
        XCTAssertEqual(m.departure, .idle)
    }

    func testAdminAloneErases() async {
        let d = FakeDevice()
        d.devicesList = [me]
        let wipes = WipeRecorder()
        let m = model(d, wipes: wipes)
        await m.load()
        await m.disconnect()
        XCTAssertEqual(d.leaveCalls, 0)
        XCTAssertEqual(wipes.count, 1)
        XCTAssertEqual(m.departure, .wiped)
    }

    func testHandOverWipesWhenReady() async {
        let d = FakeDevice()
        d.devicesList = [me, tablet]
        let wipes = WipeRecorder()
        let m = model(d, wipes: wipes)
        await m.load()
        await m.handOver(to: tablet)
        XCTAssertEqual(d.leavingTo, ["t"])
        XCTAssertEqual(m.departure, .handingOver(name: "iPad"))
        await m.pollHandover()
        XCTAssertEqual(m.departure, .handingOver(name: "iPad"))
        XCTAssertEqual(wipes.count, 0)
        d.leaveReadyValue = true
        await m.pollHandover()
        XCTAssertEqual(m.departure, .wiped)
        XCTAssertEqual(wipes.count, 1)
    }

    /// Known core limit: an expired transfer never makes `leave_ready` true.
    func testHandOverFailsWhenTheTransferExpires() async {
        let d = FakeDevice()
        d.devicesList = [me, tablet]
        let wipes = WipeRecorder()
        let m = model(d, wipes: wipes)
        await m.load()
        await m.handOver(to: tablet)
        d.transferExpired = true
        await m.pollHandover()
        XCTAssertEqual(m.departure, .handoverFailed(name: "iPad"))
        XCTAssertEqual(wipes.count, 0)
        m.dismissDeparture()
        XCTAssertEqual(m.departure, .idle)
    }

    /// Killed after `leave`: the request is queued, the screen finishes it.
    func testLoadResumesAQueuedLeave() async {
        let d = FakeDevice()
        d.devicesList = [MyDeviceInfo(id: "t", name: "iPad", issuedAt: 2, thisDevice: true, admin: false)]
        d.leaveReadyValue = true
        let wipes = WipeRecorder()
        let m = model(d, wipes: wipes)
        await m.load()
        XCTAssertEqual(wipes.count, 1)
    }
}
