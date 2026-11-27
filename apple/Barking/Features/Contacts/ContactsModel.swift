import BarkingKit
import Foundation
import Observation

/// One line of the Contacts tab: who, and whether their code was compared.
struct ContactRow: Identifiable, Equatable {
    var id: String { fingerprint }
    let fingerprint: String
    let name: String
    let verified: Bool
}

/// The Contacts tab: every contact, with or without a conversation, in
/// name order. Deleting a contact happens here or on its page, never by
/// deleting a conversation.
@MainActor @Observable
final class ContactsModel {
    private let core: CoreService
    private(set) var rows: [ContactRow] = []
    /// The first read has answered: an empty list is really empty.
    private(set) var loaded = false
    var query = ""

    init(core: CoreService) { self.core = core }

    /// Rows whose name contains the query, ignoring case and accents.
    var visibleRows: [ContactRow] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return rows }
        return rows.filter { $0.name.range(of: q, options: [.caseInsensitive, .diacriticInsensitive]) != nil }
    }

    /// The contacts change with an add, a removal, a rename, a block or a
    /// verification: all published as `.contacts`.
    static func reloads(on change: CoreChange) -> Bool { change == .contacts }

    func reload() async {
        // A failed read keeps the last list rather than blanking it.
        guard let contacts = try? await core.contacts() else { return }
        rows = contacts
            .map { ContactRow(fingerprint: $0.fingerprint, name: $0.alias ?? $0.displayName, verified: $0.verified) }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        loaded = true
    }

    func delete(_ fingerprint: String) async {
        try? await core.removeContact(fingerprint)
        await reload()
    }
}
