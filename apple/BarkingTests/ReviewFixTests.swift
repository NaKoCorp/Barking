import SwiftUI
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

    /// A reset that fails is shown: never a fresh scan over a pending wipe.
    func testNewDeviceStartAgainShowsAFailedReset() async {
        let m = NewDeviceLinkModel(
            resume: CoreService(device: FakeDevice(), runner: DirectRunner()),
            begin: { _, _ in throw Boom() }, reset: { throw Boom() })
        await m.startAgain()
        XCTAssertEqual(m.state, .refused("Something went wrong. Your data is safe."))
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
        d.messageList = ["b": [Message(id: 7, outgoing: true, body: "lost", at: 1, delivery: .state(.notDelivered))]]
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
        d.messageList = ["b": [Message(id: 9, outgoing: false, body: "new", at: 5)]]
        await m.reload()
        XCTAssertEqual(d.reads.last?.1, 9)
        m.onDisappear()
        d.messageList["b"]?.append(Message(id: 10, outgoing: false, body: "later", at: 6))
        await m.reload()
        XCTAssertEqual(d.reads.last?.1, 9)
    }

    /// Final review 8: a wipe that still cannot finish at launch has its own
    /// screen ("could not finish erasing"), not "Your data is safe".
    func testUnfinishedWipeAtLaunchIsNotOpenFailed() {
        guard case .wipeFailed = AppRouter.afterResume({ throw Boom() }) else {
            return XCTFail("an unfinished wipe must say so")
        }
        XCTAssertNil(AppRouter.afterResume({ true }))
        XCTAssertNil(AppRouter.afterResume({ false }))
    }

    /// Final review 8: "Try again" runs the wipe again; once it finishes,
    /// the welcome screen.
    func testTryAgainRerunsTheWipe() {
        let router = AppRouter(start: .wipeFailed)
        var runs = 0
        router.retryWipe { runs += 1; throw Boom() }
        XCTAssertEqual(runs, 1)
        guard case .wipeFailed = router.state else { return XCTFail("still unfinished") }
        router.retryWipe { runs += 1; return true }
        XCTAssertEqual(runs, 2)
        guard case .onboarding = router.state else { return XCTFail("finished: welcome screen") }
    }

    /// Final review 9 (spec §8.2): the confirmation names the device.
    func testDisconnectConfirmationNamesTheDevice() {
        XCTAssertEqual(DevicesView.disconnectTitle("Kitchen iPad"), "Disconnect Kitchen iPad?")
    }
}

/// The final review of the UI overhaul (review-final.md, findings 1, 2, 6,
/// 7 and 14).
@MainActor
final class UIFinalReviewTests: XCTestCase {
    private static let groups = ["90450", "67048", "03127", "88812", "40404", "12345",
                                 "67890", "11111", "22222", "33333", "44444", "55555"]

    /// #1: a 5-digit group never wraps inside itself. At every text size the
    /// grid is whole rows of one-line groups (3, 2 or 1 per row) and fits
    /// the width of the smallest iPhone's safety-code screen.
    func testSafetyCodeGroupsNeverWrapAtAnySize() {
        let width: CGFloat = 375 - 2 * Space.gutter
        for size in DynamicTypeSize.allCases {
            let line = UIHostingController(rootView: Text(verbatim: "90450")
                .font(BarkingFont.mono(.title3, size: 17, weight: .medium)).tracking(1)
                .fixedSize().environment(\.dynamicTypeSize, size))
                .sizeThatFits(in: CGSize(width: 2000, height: 2000))
            let grid = UIHostingController(rootView: CodeGrid(groups: Self.groups)
                .environment(\.dynamicTypeSize, size))
                .sizeThatFits(in: CGSize(width: width, height: 4000))
            let layouts = [3, 2, 1].filter { cols in
                let rows = CGFloat(12 / cols)
                let height = rows * line.height + (rows - 1) * 10 + 32
                let rowWidth = CGFloat(cols) * line.width + CGFloat(cols - 1) * 12 + 32
                return abs(grid.height - height) < 1.5 && rowWidth <= width + 0.5
            }
            XCTAssertFalse(layouts.isEmpty, "\(size): groups wrap (grid \(grid), one group \(line))")
            XCTAssertLessThanOrEqual(grid.width, width + 0.5, "\(size): grid overflows")
        }
    }

    /// #2: the 24 words typed on Recover are not drawn in the app-switcher
    /// snapshot or while the screen is captured: the hidden card replaces
    /// the grid, as on screen 06.
    func testRecoverHidesTheWordsWhenInactiveOrCaptured() throws {
        let cases: [(ScenePhase, Bool, Bool)] = [(.active, false, true), (.inactive, false, false),
                                                 (.background, false, false), (.active, true, false)]
        for (phase, captured, shown) in cases {
            let model = OnboardingModel(defaults: UserDefaults(suiteName: UUID().uuidString)!)
            model.recoveryWords[0] = "abandon"
            let view = RecoverView(model: model, onRecovered: { _ in })
                .environment(\.scenePhase, phase).environment(\.isSceneCaptured, captured)
            let word = AccessibilityProbe.element(labelled: "Word 1", in: view)
            XCTAssertEqual(word != nil, shown, "\(phase), captured \(captured): word 1")
            let card = AccessibilityProbe.element(
                labelled: "Hidden while the screen is recorded or the app is in the background.", in: view)
            XCTAssertEqual(card != nil, !shown, "\(phase), captured \(captured): hidden card")
        }
    }

    /// #7: the suggested PDF password is masked when the scene is not
    /// active or is captured, even while revealed.
    func testSuggestedPasswordIsMaskedWhenInactiveOrCaptured() throws {
        let cases: [(ScenePhase, Bool, Bool, Bool)] = [(.active, false, true, true), (.active, false, false, false),
                                                       (.inactive, false, true, false), (.background, false, true, false),
                                                       (.active, true, true, false)]
        for (phase, captured, revealed, shown) in cases {
            let view = SuggestedPasswordText(password: "lunar-orbit-cactus-violet", revealed: revealed)
                .environment(\.scenePhase, phase).environment(\.isSceneCaptured, captured)
            let node = try XCTUnwrap(AccessibilityProbe.element(labelled: "Suggested password", in: view))
            XCTAssertEqual(node.accessibilityValue, shown ? "lunar-orbit-cactus-violet" : "Hidden",
                           "\(phase), captured \(captured), revealed \(revealed)")
        }
    }

    /// #6: a secure field's inputs (the hidden one and the revealed one)
    /// never capitalise, autocorrect or spell-check, so the keyboard does
    /// not change or learn the secret.
    func testSecureFieldInputsDoNotCorrectOrLearn() {
        let view = BarkingTextField("Password", text: .constant("secret"), secure: true, trailing: .reveal)
        let host = UIHostingController(rootView: view)
        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 390, height: 844))
        window.rootViewController = host
        window.makeKeyAndVisible()
        host.view.layoutIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
        func fields(in v: UIView) -> [UITextField] {
            if let f = v as? UITextField { return [f] }
            return v.subviews.flatMap(fields)
        }
        let inputs = fields(in: host.view)
        XCTAssertEqual(inputs.count, 2, "a secure field stacks two inputs")
        for f in inputs {
            let kind = f.isSecureTextEntry ? "secure" : "revealed"
            XCTAssertEqual(f.autocapitalizationType, .none, "\(kind) input capitalises")
            XCTAssertEqual(f.autocorrectionType, .no, "\(kind) input autocorrects")
            // SwiftUI has no spell-check modifier on iOS: `.default` follows
            // the autocorrection type, so it is off when autocorrection is.
            XCTAssertTrue(f.spellCheckingType == .no || (f.spellCheckingType == .default && f.autocorrectionType == .no),
                          "\(kind) input spell-checks")
            XCTAssertEqual(f.writingToolsBehavior, UIWritingToolsBehavior.none, "\(kind) input offers Writing Tools")
        }
        window.isHidden = true
    }

    /// #14: Add shows its spinner while the add runs, and a second tap in
    /// that time does nothing: the contact is added exactly once.
    func testAddIsInFlightOnceUntilItEnds() async throws {
        let d = FakeDevice()
        d.addDelay = 0.3
        let m = AddContactModel(core: CoreService(device: d, runner: DirectRunner()))
        await m.scanned(try tempDevice("Bob").contactCardBytes())
        XCTAssertNotNil(m.preview)
        XCTAssertFalse(m.isAdding)
        let first = Task { await m.add(alias: "") }
        for _ in 0..<200 where !m.isAdding { await Task.yield() }
        XCTAssertTrue(m.isAdding, "Add shows no in-flight state")
        let second = await m.add(alias: "")
        XCTAssertFalse(second)
        let added = await first.value
        XCTAssertTrue(added)
        XCTAssertFalse(m.isAdding)
        XCTAssertEqual(d.addCalls, 1)
    }
}
