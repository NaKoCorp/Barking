import XCTest
@testable import Barking
@testable import BarkingKit

/// The request page's model (design decision 4): what it reads, and what
/// accepting, refusing, blocking and hiding ask of the core.
@MainActor
final class RequestModelTests: XCTestCase {
    private let fp = "lea0-2ccf-kzfa-fsms-5gfi"

    private func request(clash: Bool = false) -> ContactRequestInfo {
        ContactRequestInfo(fingerprint: fp, displayName: "Léa", firstSeen: 1_000, lastSeen: 2_000, inviteCount: 2,
                           pendingMessages: 1, hidden: false, unseen: true, nameClash: clash)
    }

    private func make(_ d: FakeDevice, clash: Bool = false) -> RequestModel {
        d.requestList = [request(clash: clash)]
        return RequestModel(fingerprint: fp, core: CoreService(device: d, runner: DirectRunner()))
    }

    func testLoadReadsRequestAndCode() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        XCTAssertEqual(m.request?.displayName, "Léa")
        XCTAssertEqual(m.request?.inviteCount, 2)
        XCTAssertEqual(m.codeGroups, Array(repeating: "54321", count: 12))
        XCTAssertFalse(m.vanished)
        XCTAssertNil(m.error)
    }

    func testAcceptReturnsContactAndTrimsAlias() async {
        let d = FakeDevice()
        var m = make(d)
        await m.load()
        let blank = await m.accept(alias: "  ")
        XCTAssertEqual(blank, fp)
        m = make(d)
        await m.load()
        let named = await m.accept(alias: " Léa ")
        XCTAssertEqual(named, fp)
        XCTAssertEqual(d.accepted.map(\.fingerprint), [fp, fp])
        XCTAssertEqual(d.accepted.map(\.alias), [nil, "Léa"])
        XCTAssertNil(m.error)
        XCTAssertFalse(m.vanished, "its own accept is not a vanish")
    }

    /// The core publishes `.contacts` before the accept returns: the reload
    /// it causes must not read the accepted request as vanished.
    func testAcceptedRequestNeverVanishes() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        _ = await m.accept(alias: "")
        await m.handle(.contacts)
        XCTAssertFalse(m.vanished)
    }

    func testAcceptAliasTaken() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        d.acceptError = .InvalidInput(detail: "alias taken")
        let contact = await m.accept(alias: "Sam")
        XCTAssertNil(contact)
        XCTAssertEqual(m.error, .aliasTaken)
        XCTAssertFalse(m.vanished)
        XCTAssertFalse(m.isWorking)

        d.acceptError = .Storage(detail: "disk")
        _ = await m.accept(alias: "Sam")
        XCTAssertEqual(m.error, .failed)
    }

    func testVanishedRequestDismisses() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        XCTAssertFalse(m.vanished)
        d.requestList = []
        await m.load()
        XCTAssertTrue(m.vanished)

        let r = make(d)
        await r.load()
        d.refuseError = .NotFound
        let refused = await r.refuse()
        XCTAssertFalse(refused)
        XCTAssertTrue(r.vanished)
        XCTAssertNil(r.error)
    }

    /// A failed read says nothing about the request: the page stays.
    func testFailedReadIsNotVanished() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        d.requestsError = .Locked
        await m.load()
        XCTAssertFalse(m.vanished)
        XCTAssertEqual(m.request?.displayName, "Léa")
    }

    func testNameClash() async {
        let m = make(FakeDevice(), clash: true)
        await m.load()
        XCTAssertTrue(m.nameClash)
        let n = make(FakeDevice())
        await n.load()
        XCTAssertFalse(n.nameClash)
    }

    func testRefuseAndBlockCallCore() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        let refused = await m.refuse()
        XCTAssertTrue(refused)
        XCTAssertEqual(d.refused, [fp])

        let b = make(d)
        await b.load()
        let blocked = await b.block()
        XCTAssertTrue(blocked)
        XCTAssertEqual(d.blockedRequests, [fp])
        XCTAssertFalse(b.vanished)

        let f = make(d)
        await f.load()
        d.blockRequestError = .Storage(detail: "disk")
        let failed = await f.block()
        XCTAssertFalse(failed)
        XCTAssertEqual(f.error, .failed)
    }

    func testSetHiddenCallsCoreAndReloads() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        await m.setHidden(true)
        XCTAssertEqual(d.hidden.map(\.0), [fp])
        XCTAssertEqual(d.hidden.map(\.1), [true])
        XCTAssertEqual(m.request?.hidden, true)
    }

    /// Editing the alias takes "already used" away; another error stays.
    func testAliasEditClearsAliasTaken() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        d.acceptError = .InvalidInput(detail: "alias taken")
        _ = await m.accept(alias: "Sam")
        XCTAssertEqual(m.error, .aliasTaken)
        m.aliasEdited()
        XCTAssertNil(m.error)
        d.acceptError = .Storage(detail: "disk")
        _ = await m.accept(alias: "Sam")
        m.aliasEdited()
        XCTAssertEqual(m.error, .failed)
    }

    /// The spinner belongs to Accept's own call: off before and after it,
    /// and never set by another action.
    func testAcceptingFollowsAcceptsOwnCall() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        XCTAssertFalse(m.isAccepting)
        await m.setHidden(true)
        XCTAssertFalse(m.isAccepting)
        d.acceptError = .Storage(detail: "disk")
        _ = await m.accept(alias: "")
        XCTAssertFalse(m.isAccepting, "cleared when the call ends, even failed")
    }

    /// Two taps on Accept: one call, one contact, no error.
    func testWorkingIgnoresSecondAccept() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        async let first = m.accept(alias: "")
        async let second = m.accept(alias: "")
        let results = await [first, second]
        XCTAssertEqual(d.accepted.count, 1)
        XCTAssertEqual(results.compactMap { $0 }, [fp])
        XCTAssertNil(m.error)
        XCTAssertFalse(m.vanished, "the second tap never reached the core (it would have found nothing)")
        XCTAssertFalse(m.isAccepting)
    }
}
