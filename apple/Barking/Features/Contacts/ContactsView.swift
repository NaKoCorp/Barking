import BarkingKit
import SwiftUI

/// The Contacts tab: every contact, its page, and adding or deleting one.
/// A contact's page offers "Send a message", which opens its conversation
/// under Chats.
struct ContactsView: View {
    let core: CoreService
    @Environment(AppRouter.self) private var router
    @State private var model: ContactsModel
    @State private var adding = false
    /// The contact the add sheet just added: its conversation opens once
    /// the sheet closes.
    @State private var addedContact: String?
    @State private var confirmDelete: ContactRow?
    @State private var path: [String] = []

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: ContactsModel(core: core))
    }

    var body: some View {
        @Bindable var model = model
        NavigationStack(path: $path) {
            List {
                if model.loaded, model.rows.isEmpty {
                    ListEmptyState(title: "No contacts yet",
                                   message: "Add someone from their code, or show them yours.",
                                   action: "Add a contact") { adding = true }
                        .listRowSeparator(.hidden).listRowBackground(Color.surface)
                }
                ForEach(model.visibleRows) { row in
                    NavigationLink(value: row.fingerprint) { ContactRowView(row: row) }
                        .listRowBackground(Color.surface)
                        .listRowSeparator(.hidden)
                        .swipeActions {
                            Button(role: .destructive) { confirmDelete = row } label: {
                                Label("Delete", systemImage: "trash")
                            }
                            .tint(Color.danger)
                        }
                        .accessibilityIdentifier("contacts.row.\(row.fingerprint.prefix(8))")
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .background(Color.surface)
            .safeAreaInset(edge: .top, spacing: 0) {
                ListHeader(title: "Contacts", symbol: "person.badge.plus", actionLabel: "Add a contact",
                           query: $model.query) { adding = true }
            }
            .navigationTitle(Text("Contacts"))
            .toolbarVisibility(.hidden, for: .navigationBar)
            .navigationDestination(for: String.self) { fingerprint in
                SafetyCodeView(core: core, contact: fingerprint) {
                    router.openConversation(with: fingerprint)
                }
            }
            .sheet(isPresented: $adding, onDismiss: openAdded) {
                AddContactView(core: core, link: nil, onAdded: { addedContact = $0 }) { adding = false }
            }
            // An alert, not a confirmation dialog: on iOS 26 the dialog of a
            // swipe action floats as a popover at the foot of the list.
            .alert(Text("Delete \(confirmDelete?.name ?? "")?"),
                   isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
                   presenting: confirmDelete) { row in
                Button("Delete", role: .destructive) { Task { await model.delete(row.fingerprint) } }
                Button("Cancel", role: .cancel) {}
            } message: { row in
                Text("\(row.name) leaves your contacts on all your devices. They are not told.")
            }
        }
        .task {
            await model.reload()
            for await change in await core.changes where ContactsModel.reloads(on: change) {
                await model.reload()
                // A contact deleted from its page: the page is gone with it.
                if let open = path.last, !model.rows.contains(where: { $0.fingerprint == open }) { path = [] }
            }
        }
    }

    /// After the add sheet: the new contact's conversation, under Chats.
    private func openAdded() {
        guard let contact = addedContact else { return }
        addedContact = nil
        router.openConversation(with: contact)
    }
}

/// One contact: its avatar, its name and whether its code was compared.
struct ContactRowView: View {
    let row: ContactRow

    var body: some View {
        HStack(spacing: 12) {
            Avatar(name: row.name, fingerprint: row.fingerprint, size: 44)
            VStack(alignment: .leading, spacing: 2) {
                Text(row.name).font(BarkingFont.sans(.headline, size: 16, weight: .semibold))
                    .foregroundStyle(Color.fg).lineLimit(1)
                TrustLine(trust: Trust(verified: row.verified))
            }
            Spacer(minLength: 0)
        }
        .frame(minHeight: 64)
        .accessibilityElement(children: .combine)
    }
}

/// "New message" from Chats: pick the contact to write to, or add one.
struct NewMessageSheet: View {
    let core: CoreService
    let onPick: (String) -> Void
    let onAdd: () -> Void
    @State private var model: ContactsModel
    @Environment(\.dismiss) private var dismiss

    init(core: CoreService, onPick: @escaping (String) -> Void, onAdd: @escaping () -> Void) {
        self.core = core
        self.onPick = onPick
        self.onAdd = onAdd
        _model = State(initialValue: ContactsModel(core: core))
    }

    var body: some View {
        @Bindable var model = model
        NavigationStack {
            List {
                Button { onAdd(); dismiss() } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "person.badge.plus").font(.bSymbol(18, maximum: 26))
                            .foregroundStyle(Color.accent)
                            .frame(width: 44, height: 44)
                            .background(Color.wash, in: .circle)
                            .accessibilityHidden(true)
                        Text("Add a contact").font(BarkingFont.sans(.headline, size: 16, weight: .semibold))
                            .foregroundStyle(Color.accent)
                    }
                    .frame(minHeight: 64)
                }
                .listRowBackground(Color.surface)
                .listRowSeparator(.hidden)
                ForEach(model.visibleRows) { row in
                    Button { onPick(row.fingerprint); dismiss() } label: { ContactRowView(row: row) }
                        .listRowBackground(Color.surface)
                        .listRowSeparator(.hidden)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .background(Color.surface)
            .searchable(text: $model.query, placement: .navigationBarDrawer(displayMode: .always))
            .navigationTitle(Text("New message"))
            .toolbarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            }
        }
        .presentationBackground(Color.surface)
        .task { await model.reload() }
    }
}
