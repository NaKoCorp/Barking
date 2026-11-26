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
    /// The last resend failed for another reason than "too soon".
    private(set) var resendFailed = false
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

    /// No section without an invitation; "Accepted" only for a day.
    var showsInvite: Bool {
        switch invite {
        case .none: false
        case .sent, .unanswered: true
        case .accepted(let at): now() < Self.date(at + Self.inviteInterval)
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

    private func loadInvite() async {
        guard let status = try? await core.inviteStatus(contact) else { return }
        invite = status
        switch status {
        case .sent(let at), .unanswered(let at): retryAt = Self.date(at + Self.inviteInterval)
        case .none, .accepted: retryAt = nil
        }
    }

    /// Sends the invitation again; the core says when a resend comes too soon.
    func resend() async {
        do {
            try await core.invite(contact)
            resendFailed = false
            await loadInvite()
        } catch BarkingError.TooSoon(let at) {
            resendFailed = false
            retryAt = Self.date(at)
        } catch {
            resendFailed = true
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
