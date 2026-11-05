import XCTest
@testable import Barking
@testable import BarkingKit

struct Boom: Error {}

@MainActor
final class ReviewFixTests: XCTestCase {
    // C1, I6: what the app opens at launch.
    func testLaunchStateTellsPendingFailedAndAbsentApart() {
        let pending = FakeDevice()
        pending.pending = true
        guard case .linking = AppRouter.initialState(opening: { pending }, runner: DirectRunner()) else {
            return XCTFail("pending link must resume the linking screen")
        }
        guard case .ready = AppRouter.initialState(opening: { FakeDevice() }, runner: DirectRunner()) else {
            return XCTFail("a linked device is ready")
        }
        guard case .onboarding = AppRouter.initialState(opening: { nil }, runner: DirectRunner()) else {
            return XCTFail("no identity means onboarding")
        }
        guard case .failed = AppRouter.initialState(opening: { throw Boom() }, runner: DirectRunner()) else {
            return XCTFail("an error opening must not look like no identity")
        }
    }

    // C1, I4: the new device's linking can start again, and scans begin once.
    func testNewDeviceStartAgainAndSingleBegin() async {
        var begins = 0
        var resets = 0
        let m = NewDeviceLinkModel(
            begin: { _, _ in begins += 1; try await Task.sleep(for: .milliseconds(100))
                return (CoreService(device: FakeDevice(), runner: DirectRunner()), Data([1])) },
            reset: { resets += 1 })
        async let a: Void = m.scannedOffer(Data([9]))
        async let b: Void = m.scannedOffer(Data([9]))
        _ = await (a, b)
        XCTAssertEqual(begins, 1)
        await m.startAgain()
        XCTAssertEqual(resets, 1)
        XCTAssertEqual(m.state, .scanOffer)
        let resumed = NewDeviceLinkModel(resume: CoreService(device: FakeDevice(), runner: DirectRunner()),
                                         begin: { _, _ in throw Boom() }, reset: {})
        XCTAssertEqual(resumed.state, .waiting)
    }

    // I2: a linked device never had a phrase to write down.
    func testLinkedDeviceHasNoPhraseAlarm() async {
        let defaults = UserDefaults(suiteName: "test.\(UUID())")!
        let m = NewDeviceLinkModel(resume: CoreService(device: FakeDevice(), runner: DirectRunner()),
                                   begin: { _, _ in throw Boom() }, reset: {}, defaults: defaults)
        await m.received(package: Data([1]))
        XCTAssertEqual(m.state, .done)
        XCTAssertTrue(defaults.bool(forKey: OnboardingModel.confirmedKey))
        XCTAssertEqual(PhraseBanner.state(confirmed: true, inMemory: false), .hidden)
        XCTAssertEqual(PhraseBanner.state(confirmed: false, inMemory: true), .confirmable)
        XCTAssertEqual(PhraseBanner.state(confirmed: false, inMemory: false), .lost)
    }

    // I3: a call waits longer than a sync can hold the lock.
    func testAppLockOutlastsSync() {
        XCTAssertGreaterThan(Budget.appLockMs, Budget.appSyncMs + Budget.shutdownMs)
    }

    // I3: a failed send says so.
    func testSendFailureShowsError() async {
        let d = FakeDevice()
        d.sendError = Boom()
        d.contactList = [Contact(fingerprint: "b", alias: nil, displayName: "Bob", verified: false)]
        let m = ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
        m.draft = "hi"
        await m.send()
        XCTAssertEqual(m.draft, "hi")
        XCTAssertNotNil(m.sendError)
    }

    // I4: double taps on Retry and Link.
    func testDoubleRetryAndDoubleLink() async {
        let d = FakeDevice()
        d.syncDelay = 0.1
        d.contactList = [Contact(fingerprint: "b", alias: nil, displayName: "Bob", verified: false)]
        d.messageList = ["b": [Message(id: 7, outgoing: true, body: "lost", status: "failed", at: 1, failed: true)]]
        let m = ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
        await m.onAppear()
        async let r1: Void = m.retry(7)
        async let r2: Void = m.retry(7)
        _ = await (r1, r2)
        XCTAssertEqual(d.sent.count, 1)

        let link = LinkModel(core: CoreService(device: d, runner: DirectRunner()), inspect: { _ in "tablet" })
        await link.start()
        await link.scannedRequest(Data([1]))
        async let a1: Void = link.accept(history: false)
        async let a2: Void = link.accept(history: false)
        _ = await (a1, a2)
        XCTAssertEqual(d.linkCalls, 1)
        guard case .share(let url) = link.state else { return XCTFail("\(link.state)") }
        // I5: the file is deleted once shared.
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        link.cleanup()
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }

    // I5: the remote device's name never decides a path.
    func testLinkFileNameIsSanitized() {
        XCTAssertEqual(LinkModel.fileName(for: "iPad / work"), "iPad-work.barkinglink")
        XCTAssertEqual(LinkModel.fileName(for: "../../etc"), "etc.barkinglink")
        XCTAssertEqual(LinkModel.fileName(for: "  "), "device.barkinglink")
    }

    // I7: messages that arrive while the conversation is open are read.
    func testMessagesArrivingWhileOpenAreRead() async {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "b", alias: nil, displayName: "Bob", verified: false)]
        let m = ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
        await m.onAppear()
        d.messageList = ["b": [Message(id: 9, outgoing: false, body: "new", status: "delivered", at: 5, failed: false)]]
        await m.reload()
        XCTAssertEqual(d.reads.last?.1, 9)
        m.onDisappear()
        d.messageList["b"]?.append(Message(id: 10, outgoing: false, body: "later", status: "delivered", at: 6, failed: false))
        await m.reload()
        XCTAssertEqual(d.reads.last?.1, 9)
    }
}
