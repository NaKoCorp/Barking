import BarkingKit
import Foundation
import Observation

/// Safety code and contact page (screen 6, spec §5.6).
@MainActor @Observable
final class ContactModel {
    let contact: String
    private let core: CoreService
    private(set) var name = ""
    private(set) var alias = ""
    private(set) var groups: [String] = []
    private(set) var verified = false
    private(set) var justVerified = false
    private(set) var mismatched = false
    /// The core did not record the last mark or unmark: the screen says so.
    private(set) var saveFailed = false
    /// The contact's devices, from its card.
    private(set) var devices: [MyDeviceInfo] = []
    /// The last invitation sent to the contact (design decision 6).
    private(set) var invite: InviteStatus = .none
    /// When a resend becomes possible: 24 h after the last invitation, or
    /// the core's own answer to a resend that came too soon.
    private(set) var retryAt: Date?
    /// The last resend failed for another reason than "too soon" or "too large".
    private(set) var resendFailed = false
    /// The card is too large for an invitation: a retry cannot help, the
    /// contact must scan my code instead.
    private(set) var resendTooLarge = false
    private let now: () -> Date

    init(contact: String, core: CoreService, now: @escaping () -> Date = Date.init) {
        self.contact = contact
        self.core = core
        self.now = now
    }

    /// A day between two invitations, as the core counts it.
    static let inviteInterval: UInt64 = 86_400

    var resendAllowed: Bool { retryAt.map { $0 <= now() } ?? true }

    /// The whole hours until a resend, rounded up and never under 1; nil
    /// once it is allowed.
    var hoursUntilRetry: Int? {
        guard let retryAt, !resendAllowed else { return nil }
        return max(1, Int((retryAt.timeIntervalSince(now()) / 3600).rounded(.up)))
    }

    /// The section is always there: an invitation can always be sent
    /// (again), within the 24 h cap. A contact who deleted me is never
    /// told to me, so "Accepted" must not close the door.
    var showsInvite: Bool { true }

    /// What the invitation button does, from the last invitation's state.
    enum InviteAction: Equatable {
        /// No invitation yet.
        case send
        /// Sent, answered or not: the same invitation again.
        case resend
        /// Accepted: for a contact who may have deleted me since.
        case inviteAgain
    }

    var inviteAction: InviteAction {
        switch invite {
        case .none: .send
        case .sent, .unanswered: .resend
        case .accepted: .inviteAgain
        }
    }

    private static func date(_ secs: UInt64) -> Date { Date(timeIntervalSince1970: TimeInterval(secs)) }

    /// The first four groups of the fingerprint: `zab2 2ccf · kzfa fsms`.
    var fingerprintShort: String { FingerprintFormat.grouped(contact, form: .short) }

    func load() async {
        if let c = try? await core.contacts().first(where: { $0.fingerprint == contact }) {
            name = c.alias ?? c.displayName
            alias = c.alias ?? ""
            verified = c.verified
        }
        groups = (try? await core.safetyNumber(for: contact)) ?? []
        devices = (try? await core.contactDevices(contact)) ?? []
        await loadInvite()
    }

    /// While the page is open the invitation may be answered or sent from
    /// another device: `.contacts`, and the end of any sync (`.network`: an
    /// acceptance alone brings no message, so no `.contacts`), reload its
    /// state, and only it (the alias being typed stays).
    func handle(_ change: CoreChange) async {
        if change == .contacts || change == .network { await loadInvite() }
    }

    private func loadInvite() async {
        guard let status = try? await core.inviteStatus(contact) else { return }
        invite = status
        switch status {
        case .sent(let at), .unanswered(let at):
            // A later date the core gave with `TooSoon` stays.
            let fromStatus = Self.date(at + Self.inviteInterval)
            retryAt = retryAt.map { max($0, fromStatus) } ?? fromStatus
        case .none, .accepted: retryAt = nil
        }
    }

    /// Sends the invitation again; the core says when a resend comes too soon.
    func resend() async {
        do {
            try await core.invite(contact)
            resendFailed = false
            resendTooLarge = false
            // Holds even if the reload below fails.
            retryAt = now().addingTimeInterval(TimeInterval(Self.inviteInterval))
            await loadInvite()
        } catch BarkingError.TooSoon(let at) {
            resendFailed = false
            resendTooLarge = false
            retryAt = Self.date(at)
        } catch let e as BarkingError where e.isCardTooLarge {
            resendFailed = false
            resendTooLarge = true
        } catch {
            resendFailed = true
            resendTooLarge = false
        }
    }

    func match() async {
        guard (try? await core.markVerified(contact)) != nil else { saveFailed = true; return }
        saveFailed = false
        verified = true
        justVerified = true
        mismatched = false
    }

    func undo() async {
        guard (try? await core.unmarkVerified(contact)) != nil else { saveFailed = true; return }
        saveFailed = false
        verified = false
        justVerified = false
    }

    func mismatch() { mismatched = true }

    func rename(_ newAlias: String) async {
        try? await core.setAlias(contact, alias: newAlias.trimmingCharacters(in: .whitespaces))
        await load()
    }

    func delete() async { try? await core.removeContact(contact) }

    /// Blocks the contact; false if the core did not record it.
    func block() async -> Bool { (try? await core.blockContact(contact)) != nil }
}
