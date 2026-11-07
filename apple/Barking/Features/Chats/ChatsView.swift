import BarkingKit
import SwiftUI

/// Screen 3 of the mockup.
struct ChatsView: View {
    let core: CoreService
    @Environment(AppRouter.self) private var router
    @State private var model: ChatsModel
    @State private var adding = false
    @State private var pendingLink: String?
    @State private var confirmDelete: ChatRow?

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: ChatsModel(core: core))
    }

    var body: some View {
        NavigationStack {
            List {
                RemovedBanner(core: core).listRowSeparator(.hidden).listRowBackground(Color.surface)
                if PhraseBanner.current != .hidden {
                    PhraseBanner().listRowSeparator(.hidden).listRowBackground(Color.surface)
                }
                if model.offline {
                    Banner(kind: .info, title: "No relay reachable.",
                           message: "Messages wait and leave as soon as one is.")
                        .listRowSeparator(.hidden).listRowBackground(Color.surface)
                }
                if model.rows.isEmpty {
                    VStack(spacing: 16) {
                        Text("No chats yet").font(BarkingFont.mono(.headline, size: 16, weight: .semibold))
                            .foregroundStyle(Color.fg)
                        PrimaryButton("Add a contact") { adding = true }
                    }
                    .padding(.vertical, 40)
                    .listRowSeparator(.hidden).listRowBackground(Color.surface)
                }
                ForEach(model.visibleRows) { row in
                    NavigationLink(value: row.contact) { ChatRowView(row: row) }
                        .listRowBackground(Color.surface)
                        .listRowSeparator(.hidden)
                        .swipeActions {
                            Button(role: .destructive) { confirmDelete = row } label: {
                                Label("Delete", systemImage: "trash")
                            }
                            .tint(Color.danger)
                        }
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .background(Color.surface)
            .refreshable {
                _ = await core.sync(reason: .pull)
                await model.reload()
            }
            .safeAreaInset(edge: .top, spacing: 0) { header }
            .navigationTitle(Text("Chats"))
            .toolbarVisibility(.hidden, for: .navigationBar)
            .navigationDestination(for: String.self) { contact in
                ConversationView(core: core, contact: contact)
            }
            .sheet(isPresented: $adding, onDismiss: { pendingLink = nil }) {
                AddContactView(core: core, link: pendingLink) { adding = false }
            }
            .confirmationDialog(Text("Delete this contact? The history is kept."),
                                isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
                                titleVisibility: .visible) {
                Button("Delete", role: .destructive) {
                    if let row = confirmDelete { Task { await model.delete(row.contact) } }
                }
            }
        }
        .task {
            await model.reload()
            for await change in await core.changes {
                if change == .contacts || change == .network || { if case .messages = change { true } else if case .delivery = change { true } else { false } }() {
                    await model.reload()
                }
            }
        }
        .onChange(of: router.pendingCardLink, initial: true) { _, link in
            if link != nil { pendingLink = router.takePendingCardLink(); adding = true }
        }
    }
}

extension ChatsView {
    /// The mockup's header: title, compose button, search field.
    private var header: some View {
        @Bindable var model = model
        return VStack(spacing: 12) {
            HStack {
                Text("Chats").font(BarkingFont.mono(.largeTitle, size: 30, weight: .semibold))
                    .tracking(-0.5).foregroundStyle(Color.fg)
                    .accessibilityAddTraits(.isHeader)
                Spacer()
                Button { adding = true } label: {
                    Image(systemName: "square.and.pencil").font(.bSymbol(18, maximum: 26))
                        .foregroundStyle(Color.accent)
                        .frame(width: 44, height: 44)
                        .background(Color.wash, in: .circle)
                }
                .accessibilityLabel(Text("New message"))
            }
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(Color.fgSoft).accessibilityHidden(true)
                TextField(text: $model.query, prompt: Text("Search").foregroundStyle(Color.fgSoft)) { Text("Search") }
                    .font(.bBody).foregroundStyle(Color.fg)
                    .submitLabel(.search)
            }
            .padding(.horizontal, 12)
            .frame(height: 40)
            .background(Color.field, in: .rect(cornerRadius: 10))
        }
        .padding(.horizontal, 20)
        .padding(.top, 8)
        .padding(.bottom, 12)
        .background(Color.surfaceCard)
        .overlay(alignment: .bottom) { Rectangle().fill(Color.border).frame(height: 1) }
    }
}

/// One chat (U-22): a 44 pt avatar, the name and the time, then the last
/// message or the contact's trust, centred in a 64 pt row.
struct ChatRowView: View {
    let row: ChatRow

    var body: some View {
        HStack(spacing: 12) {
            Avatar(name: row.name, fingerprint: row.contact, size: 44)
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .firstTextBaseline) {
                    Text(row.name).font(BarkingFont.sans(.headline, size: 16, weight: .semibold))
                        .foregroundStyle(Color.fg).lineLimit(1)
                    // Verified stays visible when the second line is a message.
                    if row.verified, case .preview = row.line {
                        Text(verbatim: "✓").font(.bSymbol(13, relativeTo: .footnote, weight: .bold))
                            .foregroundStyle(Color.ok)
                            .accessibilityLabel(Text("verified"))
                    }
                    Spacer(minLength: 8)
                    if let at = row.lastAt {
                        Text(at, format: .dateTime.hour().minute())
                            .font(.bMeta).foregroundStyle(Color.fgSoft)
                    }
                }
                HStack(spacing: 6) {
                    switch row.line {
                    case .preview(let text):
                        if let s = row.lastStatus { DeliveryGlyph(s) }
                        Text(text).font(.bBodySmall).foregroundStyle(Color.fgMuted).lineLimit(1)
                    case .trust(let trust):
                        TrustLine(trust: trust)
                    }
                    Spacer(minLength: 0)
                    if row.unread > 0 {
                        Text(verbatim: "\(row.unread)").font(BarkingFont.mono(.caption, size: 12, weight: .semibold))
                            .foregroundStyle(.white).padding(.horizontal, 7).frame(minHeight: 22)
                            .background(Color.accentFill, in: .capsule)
                            .accessibilityLabel(Text("\(row.unread) unread"))
                    }
                }
            }
        }
        .frame(minHeight: 64)
    }
}

/// Recovery phrase reminder (spec §5.2): opens the 3-word check while the
/// phrase is still in memory; after a relaunch it can only say to write it down.
struct PhraseBanner: View {
    enum Kind: Equatable { case hidden, confirmable, lost }

    static func state(confirmed: Bool, inMemory: Bool) -> Kind {
        confirmed ? .hidden : (inMemory ? .confirmable : .lost)
    }

    static var current: Kind {
        state(confirmed: UserDefaults.standard.bool(forKey: OnboardingModel.confirmedKey),
              inMemory: PhraseMemory.shared.phrase != nil)
    }

    @State private var checking = false
    @State private var model = OnboardingModel()

    var body: some View {
        switch Self.current {
        case .hidden: EmptyView()
        case .confirmable:
            Banner(kind: .warning, title: "Recovery phrase not confirmed",
                   message: "Check three words while you still have your copy.",
                   action: .init(label: "Check now", hint: "Opens the 3-word check.") {
                       model.phrase = PhraseMemory.shared.phrase
                       model.startQuiz()
                       checking = true
                   })
            .sheet(isPresented: $checking) {
                NavigationStack {
                    PhraseConfirmView(model: model) { checking = false }
                }
            }
        case .lost:
            Banner(kind: .warning, title: "Write your phrase down now: it cannot be shown again",
                   message: "If you lose this phone without it, your identity is lost.")
        }
    }
}
