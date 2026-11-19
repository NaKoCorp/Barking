import BarkingKit
import Observation
import SwiftUI

/// The blocked contacts, each with an Unblock button. A blocked contact is
/// hidden everywhere else; this is the only way back.
@MainActor @Observable
final class BlockedContactsModel {
    private let core: CoreService
    private(set) var contacts: [Contact] = []
    private(set) var loaded = false
    /// The last unblock was not recorded: the screen says so.
    private(set) var failed = false

    init(core: CoreService) { self.core = core }

    func load() async {
        contacts = ((try? await core.blockedContacts()) ?? [])
            .sorted { name($0).localizedStandardCompare(name($1)) == .orderedAscending }
        loaded = true
    }

    func name(_ c: Contact) -> String { c.alias ?? c.displayName }

    /// Unblocks; the contact and its chat come back.
    func unblock(_ c: Contact) async {
        failed = (try? await core.unblockContact(c.fingerprint)) == nil
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
            if model.loaded && model.contacts.isEmpty {
                Text("No blocked contacts").font(.bBody).foregroundStyle(Color.fgSoft)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if !model.contacts.isEmpty {
                FormCard {
                    ForEach(model.contacts, id: \.fingerprint) { c in
                        FormRow(title: Text(verbatim: model.name(c)),
                                subtitle: Text(verbatim: FingerprintFormat.grouped(c.fingerprint, form: .short)).font(.bMeta)) {
                            Button("Unblock") { Task { await model.unblock(c) } }
                                .font(.bBody.weight(.semibold))
                                .foregroundStyle(Color.accent)
                                .accessibilityLabel(Text("Unblock \(model.name(c))"))
                                .accessibilityIdentifier("blocked.unblock")
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
}
