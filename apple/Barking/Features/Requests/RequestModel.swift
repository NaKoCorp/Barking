import BarkingKit
import Foundation
import Observation

/// A contact request's page (design decision 4): the request, its safety
/// code, and the four answers (accept, refuse, block, hide). Reloads on
/// `.contacts`, which also stands for request changes.
@MainActor @Observable
final class RequestModel {
    enum RequestError: Equatable {
        /// The alias asked for is another contact's.
        case aliasTaken
        /// The core wrote nothing.
        case failed
    }

    let fingerprint: String
    private let core: CoreService
    private(set) var request: ContactRequestInfo?
    private(set) var codeGroups: [String] = []
    /// A call runs: a second tap does nothing.
    private(set) var isWorking = false
    private(set) var error: RequestError?
    /// The request left the core from elsewhere (another device, a race):
    /// the page closes.
    private(set) var vanished = false
    /// Accepted, refused or blocked from here: the request leaving the core
    /// is this page's own doing, never a vanish.
    private var resolved = false

    init(fingerprint: String, core: CoreService) {
        self.fingerprint = fingerprint
        self.core = core
    }

    /// The declared name equals the alias or the name of one of my contacts.
    var nameClash: Bool { request?.nameClash ?? false }

    /// Only a read that succeeds and lacks the request closes the page: a
    /// failed read keeps what is shown. Skipped while a call runs (its own
    /// publish would read the accepted request as gone).
    func load() async {
        guard !isWorking, !resolved, let all = try? await core.requests() else { return }
        guard !isWorking, !resolved else { return }
        guard let found = all.first(where: { $0.fingerprint == fingerprint }) else {
            vanished = true
            return
        }
        request = found
        if codeGroups.isEmpty, let groups = try? await core.requestSafetyNumber(fingerprint) {
            codeGroups = groups
        }
    }

    func handle(_ change: CoreChange) async {
        if change == .contacts { await load() }
    }

    /// The new contact's fingerprint, or nil (the reason is in `error`, or
    /// the request vanished). A blank alias is no alias.
    func accept(alias: String) async -> String? {
        guard !isWorking, !resolved else { return nil }
        isWorking = true
        error = nil
        defer { isWorking = false }
        let trimmed = alias.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let contact = try await core.acceptRequest(fingerprint, alias: trimmed.isEmpty ? nil : trimmed)
            resolved = true
            return contact
        } catch {
            fail(error, aliasTaken: true)
            return nil
        }
    }

    /// True once refused: the page goes back to the list.
    func refuse() async -> Bool {
        await resolve { [core, fingerprint] in try await core.refuseRequest(fingerprint) }
    }

    /// True once blocked: the page goes back to the list.
    func block() async -> Bool {
        await resolve { [core, fingerprint] in try await core.blockRequest(fingerprint) }
    }

    func setHidden(_ hidden: Bool) async {
        guard !isWorking, !resolved else { return }
        isWorking = true
        error = nil
        do {
            try await core.setRequestHidden(fingerprint, hidden: hidden)
        } catch {
            fail(error, aliasTaken: false)
        }
        isWorking = false
        await load()
    }

    private func resolve(_ call: @escaping () async throws -> Void) async -> Bool {
        guard !isWorking, !resolved else { return false }
        isWorking = true
        error = nil
        defer { isWorking = false }
        do {
            try await call()
            resolved = true
            return true
        } catch {
            fail(error, aliasTaken: false)
            return false
        }
    }

    /// A request already gone closes the page and is no error.
    private func fail(_ error: any Error, aliasTaken: Bool) {
        switch error as? BarkingError {
        case .NotFound: vanished = true
        case .InvalidInput(let detail) where aliasTaken && detail == "alias taken": self.error = .aliasTaken
        default: self.error = .failed
        }
    }
}
