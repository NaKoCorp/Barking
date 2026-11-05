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

    init(contact: String, core: CoreService) {
        self.contact = contact
        self.core = core
    }

    /// The first four groups of the fingerprint: `zab2 2ccf · kzfa fsms`.
    var fingerprintShort: String {
        let g = contact.split(separator: "-").prefix(4).map(String.init)
        guard g.count == 4 else { return contact }
        return "\(g[0]) \(g[1]) · \(g[2]) \(g[3])"
    }

    func load() async {
        if let c = try? await core.contacts().first(where: { $0.fingerprint == contact }) {
            name = c.alias ?? c.displayName
            alias = c.alias ?? ""
            verified = c.verified
        }
        groups = (try? await core.safetyNumber(for: contact)) ?? []
    }

    func match() async {
        guard (try? await core.markVerified(contact)) != nil else { return }
        verified = true
        justVerified = true
        mismatched = false
    }

    func undo() async {
        guard (try? await core.unmarkVerified(contact)) != nil else { return }
        verified = false
        justVerified = false
    }

    func mismatch() { mismatched = true }

    func rename(_ newAlias: String) async {
        try? await core.setAlias(contact, alias: newAlias.trimmingCharacters(in: .whitespaces))
        await load()
    }

    func delete() async { try? await core.removeContact(contact) }
}
