import XCTest
@testable import Barking
@testable import BarkingKit

@MainActor
final class ContactModelTests: XCTestCase {
    func make(_ d: FakeDevice) -> ContactModel {
        d.contactList = [Contact(fingerprint: "zab2-2ccf-kzfa-fsms-5gfi", alias: nil, displayName: "Maya", verified: false)]
        return ContactModel(contact: "zab2-2ccf-kzfa-fsms-5gfi", core: CoreService(device: d, runner: DirectRunner()))
    }

    func testMatchThenUndo() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        await m.match()
        XCTAssertTrue(d.verified.contains(m.contact))
        XCTAssertTrue(m.justVerified)
        await m.undo()
        XCTAssertFalse(d.verified.contains(m.contact))
        XCTAssertFalse(m.justVerified)
    }

    /// Review B3 #8: a verification the core did not record is said, not
    /// silent; the next try clears it.
    func testFailedVerificationIsReported() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        d.verifyError = NSError(domain: "test", code: 1)
        await m.match()
        XCTAssertFalse(m.verified)
        XCTAssertFalse(m.justVerified)
        XCTAssertTrue(m.saveFailed)
        d.verifyError = nil
        await m.match()
        XCTAssertTrue(m.verified)
        XCTAssertFalse(m.saveFailed)
        d.verifyError = NSError(domain: "test", code: 1)
        await m.undo()
        XCTAssertTrue(m.verified)
        XCTAssertTrue(m.saveFailed)
    }

    func testMismatchDoesNotVerify() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        m.mismatch()
        XCTAssertTrue(d.verified.isEmpty)
        XCTAssertTrue(m.mismatched)
    }

    func testGroupsAndShortFingerprint() async {
        let m = make(FakeDevice())
        await m.load()
        XCTAssertEqual(m.groups.count, 12)
        // The shared format: a no-break space keeps `·` off the start of a line.
        XCTAssertEqual(m.fingerprintShort, "zab2 2ccf\u{00A0}· kzfa fsms")
        XCTAssertEqual(m.name, "Maya")
    }

    // MARK: Invitation (design decision 6)

    private let now = Date(timeIntervalSince1970: 2_000_000_000)
    private var nowSecs: UInt64 { UInt64(now.timeIntervalSince1970) }

    func makeInvite(_ d: FakeDevice, _ status: InviteStatus) -> ContactModel {
        let fp = "zab2-2ccf-kzfa-fsms-5gfi"
        d.contactList = [Contact(fingerprint: fp, alias: nil, displayName: "Maya", verified: false)]
        d.inviteStatusByContact[fp] = status
        let clock = now
        return ContactModel(contact: fp, core: CoreService(device: d, runner: DirectRunner()), now: { clock })
    }

    func testSentStateWithRetry() async {
        let at = nowSecs - 3600
        let m = makeInvite(FakeDevice(), .sent(at: at))
        await m.load()
        XCTAssertEqual(m.invite, .sent(at: at))
        XCTAssertTrue(m.showsInvite)
        XCTAssertFalse(m.resendAllowed)
        XCTAssertEqual(m.retryAt, Date(timeIntervalSince1970: TimeInterval(at + 86_400)))
        XCTAssertEqual(m.hoursUntilRetry, 23)
    }

    /// The page stays open while the invitation is answered: a `.contacts`
    /// change, or a sync's end (`.network`: an acceptance alone publishes no
    /// `.contacts`), reloads its state, and only it (the alias being typed
    /// and the name stay as they are); other changes do not.
    func testContactsChangeReloadsTheInvitation() async {
        let d = FakeDevice()
        let at = nowSecs - 3600
        let m = makeInvite(d, .sent(at: at))
        await m.load()
        d.inviteStatusByContact[m.contact] = .accepted(at: nowSecs - 60)
        d.contactList = [Contact(fingerprint: m.contact, alias: "Mai", displayName: "Maya", verified: false)]
        await m.handle(.devices)
        XCTAssertEqual(m.invite, .sent(at: at))
        await m.handle(.contacts)
        XCTAssertEqual(m.invite, .accepted(at: nowSecs - 60))
        XCTAssertNil(m.retryAt)
        XCTAssertEqual(m.name, "Maya", "only the invitation reloads")
        XCTAssertEqual(m.alias, "")
        d.inviteStatusByContact[m.contact] = .unanswered(at: at)
        await m.handle(.network)
        XCTAssertEqual(m.invite, .unanswered(at: at))
    }

    func testUnansweredAllowsResend() async {
        let at = nowSecs - 8 * 86_400
        let m = makeInvite(FakeDevice(), .unanswered(at: at))
        await m.load()
        XCTAssertTrue(m.showsInvite)
        XCTAssertTrue(m.resendAllowed)
        XCTAssertEqual(m.retryAt, Date(timeIntervalSince1970: TimeInterval(at + 86_400)))
        XCTAssertNil(m.hoursUntilRetry)
    }

    func testResendTooSoonShowsRetry() async {
        let d = FakeDevice()
        let m = makeInvite(d, .unanswered(at: nowSecs - 8 * 86_400))
        await m.load()
        let x = nowSecs + 4 * 3600 + 1
        d.inviteError = .TooSoon(retryAt: x)
        await m.resend()
        XCTAssertEqual(m.retryAt, Date(timeIntervalSince1970: TimeInterval(x)))
        XCTAssertFalse(m.resendAllowed)
        // Rounded up, never "0 h".
        XCTAssertEqual(m.hoursUntilRetry, 5)
        XCTAssertFalse(m.resendFailed)
    }

    func testResendReloadsTheState() async {
        let d = FakeDevice()
        let m = makeInvite(d, .unanswered(at: nowSecs - 8 * 86_400))
        await m.load()
        d.inviteStatusByContact[m.contact] = .sent(at: nowSecs)
        await m.resend()
        XCTAssertEqual(d.invited, [m.contact])
        XCTAssertEqual(m.invite, .sent(at: nowSecs))
        XCTAssertEqual(m.hoursUntilRetry, 24)
    }

    func testResendFailureIsReported() async {
        let d = FakeDevice()
        let m = makeInvite(d, .unanswered(at: nowSecs - 8 * 86_400))
        await m.load()
        d.inviteError = .InvalidInput(detail: "malformed")
        await m.resend()
        XCTAssertTrue(m.resendFailed)
        XCTAssertTrue(m.resendAllowed)
        d.inviteError = nil
        await m.resend()
        XCTAssertFalse(m.resendFailed)
    }

    /// Accepted long ago or not at all, the section stays: the contact may
    /// have deleted me since, and an invitation brings them back.
    func testInviteAlwaysOffered() async {
        let accepted = makeInvite(FakeDevice(), .accepted(at: nowSecs - 30 * 86_400))
        await accepted.load()
        XCTAssertTrue(accepted.showsInvite)
        XCTAssertNil(accepted.retryAt)
        XCTAssertTrue(accepted.resendAllowed)
        XCTAssertEqual(accepted.inviteAction, .inviteAgain)
        let none = makeInvite(FakeDevice(), .none)
        await none.load()
        XCTAssertTrue(none.showsInvite)
        XCTAssertEqual(none.inviteAction, .send)
        let sent = makeInvite(FakeDevice(), .sent(at: nowSecs - 3600))
        await sent.load()
        XCTAssertEqual(sent.inviteAction, .resend)
    }

    /// Inviting again after an acceptance calls the core, which decides.
    func testInviteAgainCallsTheCore() async {
        let d = FakeDevice()
        let m = makeInvite(d, .accepted(at: nowSecs - 30 * 86_400))
        await m.load()
        await m.resend()
        XCTAssertFalse(m.resendFailed)
        XCTAssertEqual(d.invited.count, 1)
    }

    /// A card too large for an invitation is not a failure to retry: the
    /// page offers my code instead.
    func testResendTooLargeOffersTheCode() async {
        let d = FakeDevice()
        let m = makeInvite(d, .unanswered(at: nowSecs - 8 * 86_400))
        await m.load()
        d.inviteError = .InvalidInput(detail: "data too large")
        await m.resend()
        XCTAssertTrue(m.resendTooLarge)
        XCTAssertFalse(m.resendFailed)
        d.inviteError = .InvalidInput(detail: "malformed")
        await m.resend()
        XCTAssertTrue(m.resendFailed)
        XCTAssertFalse(m.resendTooLarge, "a later failure replaces the too-large card")
        d.inviteError = .InvalidInput(detail: "data too large")
        await m.resend()
        d.inviteError = .TooSoon(retryAt: nowSecs + 3600)
        await m.resend()
        XCTAssertFalse(m.resendTooLarge, "a later too-soon replaces the too-large card")
        XCTAssertFalse(m.resendFailed)
    }

    /// A reload keeps the later date the core gave with `TooSoon`.
    func testReloadKeepsTheCoresLaterRetry() async {
        let d = FakeDevice()
        let at = nowSecs - 3600
        let m = makeInvite(d, .sent(at: at))
        await m.load()
        let x = at + 86_400 + 7200
        d.inviteError = .TooSoon(retryAt: x)
        await m.resend()
        await m.load()
        XCTAssertEqual(m.retryAt, Date(timeIntervalSince1970: TimeInterval(x)))
    }

    /// A resend that went waits a day, even when the status cannot be read back.
    func testResendWaitsADayWithoutReload() async {
        let d = FakeDevice()
        let m = makeInvite(d, .unanswered(at: nowSecs - 8 * 86_400))
        await m.load()
        d.inviteStatusError = .InvalidInput(detail: "unreadable")
        await m.resend()
        XCTAssertEqual(m.retryAt, now.addingTimeInterval(86_400))
        XCTAssertEqual(m.hoursUntilRetry, 24)
    }
}
