import BarkingKit
import Observation
import SwiftUI

/// The blocked contacts, each with an Unblock button, then the blocked
/// people who are no contact (a blocked invitation), by fingerprint. A
/// blocked contact is hidden everywhere else; this is the only way back.
@MainActor @Observable
final class BlockedContactsModel {
    private let core: CoreService
    private(set) var contacts: [Contact] = []
    /// Blocked fingerprints that are no contact (a requester blocked from
    /// its invitation): nothing else names them.
    private(set) var strangers: [String] = []
    private(set) var loaded = false
    /// The last unblock was not recorded: the screen says so.
    private(set) var failed = false

    init(core: CoreService) { self.core = core }

    func load() async {
        contacts = ((try? await core.blockedContacts()) ?? [])
            .sorted { name($0).localizedStandardCompare(name($1)) == .orderedAscending }
        strangers = (try? await core.blockedFingerprints()) ?? []
        loaded = true
    }

    /// Nothing blocked at all.
    var isEmpty: Bool { contacts.isEmpty && strangers.isEmpty }

    func name(_ c: Contact) -> String { c.alias ?? c.displayName }

    /// No name to give: the fingerprint's start, as in a request's quotes.
    func name(stranger fingerprint: String) -> String { String(fingerprint.prefix(8)) }

    /// Unblocks; the contact and its chat come back.
    func unblock(_ c: Contact) async { await unblock(fingerprint: c.fingerprint) }

    /// Unblocks a contact or a stranger: its next invitation is a request again.
    func unblock(fingerprint: String) async {
        failed = (try? await core.unblockContact(fingerprint)) == nil
        await load()
    }
}

struct BlockedContactsView: View {
    @State private var model: BlockedContactsModel

    init(core: CoreService) { _model = State(initialValue: BlockedContactsModel(core: core)) }

    var body: some View {
        Group {
            Text("A blocked contact's messages are dropped without being shown, and nothing is sent to them. They are not told, but their messages stay marked as not delivered on their side.")
                .font(.bBody).foregroundStyle(Color.fgMuted)
                .fixedSize(horizontal: false, vertical: true)
            if model.failed { Banner(kind: .danger, title: "Not saved. Try again.") }
            if model.loaded && model.isEmpty {
                Text("No blocked contacts").font(.bBody).foregroundStyle(Color.fgSoft)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if !model.isEmpty {
                FormCard {
                    ForEach(model.contacts, id: \.fingerprint) { c in
                        row(name: model.name(c), subtitle: FingerprintFormat.grouped(c.fingerprint, form: .short)) {
                            await model.unblock(c)
                        }
                    }
                    // No name: the start of the fingerprint, then all of it
                    // to compare with the person's own.
                    ForEach(model.strangers, id: \.self) { fp in
                        row(name: model.name(stranger: fp), subtitle: FingerprintFormat.grouped(fp, form: .full)) {
                            await model.unblock(fingerprint: fp)
                        }
                    }
                }
            }
        }
        .barkingScreen()
        .navigationTitle(Text("Blocked contacts"))
        .toolbarTitleDisplayMode(.inline)
        .task { await model.load() }
    }

    private func row(name: String, subtitle: String, unblock: @escaping () async -> Void) -> some View {
        FormRow(title: Text(verbatim: name), subtitle: Text(verbatim: subtitle).font(.bMeta)) {
            Button("Unblock") { Task { await unblock() } }
                .font(.bBody.weight(.semibold))
                .foregroundStyle(Color.accent)
                .accessibilityLabel(Text("Unblock \(name)"))
                .accessibilityIdentifier("blocked.unblock")
        }
    }
}
