import BarkingKit
import Observation
import SwiftUI

/// Every contact request, the hidden ones apart (design decision 3).
@MainActor @Observable
final class InvitationsModel {
    private let core: CoreService
    private(set) var requests: [ContactRequestInfo] = []
    private(set) var loaded = false

    init(core: CoreService) { self.core = core }

    /// Requests in the chat list, newest first.
    var visible: [ContactRequestInfo] { requests.filter { !$0.hidden }.sorted { $0.lastSeen > $1.lastSeen } }
    /// Hidden requests, newest first.
    var hidden: [ContactRequestInfo] { requests.filter(\.hidden).sorted { $0.lastSeen > $1.lastSeen } }

    /// The screen opened: no request is new any more (the chats' entry
    /// loses its dot), then the list.
    func open() async {
        try? await core.markRequestsSeen()
        await load()
    }

    /// A failed read keeps the last list.
    func load() async {
        if let requests = try? await core.requests() { self.requests = requests }
        loaded = true
    }

    func setHidden(_ fp: String, hidden: Bool) async {
        try? await core.setRequestHidden(fp, hidden: hidden)
        await load()
    }
}

struct InvitationsView: View {
    let core: CoreService
    @State private var model: InvitationsModel

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: InvitationsModel(core: core))
    }

    var body: some View {
        List {
            ForEach(model.visible, id: \.fingerprint) { row($0) }
            if !model.hidden.isEmpty {
                SectionLabel("Hidden (invitations)")
                    .padding(.top, Space.s4)
                    .listRowSeparator(.hidden).listRowBackground(Color.surface)
                ForEach(model.hidden, id: \.fingerprint) { row($0) }
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .background(Color.surface)
        // Reachable only with requests, but it can empty while shown.
        .overlay {
            if model.loaded && model.requests.isEmpty {
                Text("No invitations").font(.bBody).foregroundStyle(Color.fgMuted)
                    .multilineTextAlignment(.center)
            }
        }
        .navigationTitle(Text("Invitations"))
        .toolbarTitleDisplayMode(.inline)
        .task {
            // Marking seen publishes `.contacts`: only the loop below reloads,
            // so it never marks again.
            await model.open()
            for await change in await core.changes where change == .contacts {
                await model.load()
            }
        }
    }

    private func row(_ request: ContactRequestInfo) -> some View {
        NavigationLink(value: ChatsRoute.request(request.fingerprint)) { RequestRowView(request: request) }
            .accessibilityIdentifier("invitations.row.\(request.fingerprint.prefix(8))")
            .listRowBackground(Color.surface)
            .listRowSeparator(.hidden)
            .swipeActions {
                Button { Task { await model.setHidden(request.fingerprint, hidden: !request.hidden) } } label: {
                    if request.hidden {
                        Label("Show", systemImage: "eye")
                    } else {
                        Label("Hide", systemImage: "eye.slash")
                    }
                }
                .tint(Color.fgMuted)
            }
    }
}

/// The chats' way to hidden requests (design decision 2): shown only when
/// one is hidden, with a dot while one of them is new. VoiceOver reads one
/// message: "Invitations, 3, 1 new".
struct InvitationsEntry: View {
    let count: Int
    let unseen: Int

    var body: some View {
        NavigationLink(value: ChatsRoute.invitations) {
            HStack(spacing: Space.s3) {
                Image(systemName: "envelope").font(.bSymbol(16, relativeTo: .body))
                    .foregroundStyle(Color.fgMuted).accessibilityHidden(true)
                Text("Invitations").font(.bBody).foregroundStyle(Color.fg)
                Spacer(minLength: Space.s2)
                if unseen > 0 {
                    // Drawn as `StatusDot` draws its dot, in the accent: the one "new" mark.
                    Text(verbatim: "●").font(.bSymbol(11, relativeTo: .caption, weight: .bold))
                        .foregroundStyle(Color.accent).accessibilityHidden(true)
                }
                Text(verbatim: "\(count)").font(.bMeta).foregroundStyle(Color.fgSoft)
            }
            .frame(minHeight: 44)
        }
        .accessibilityLabel(Text("Invitations") + Text(verbatim: ", \(count)"))
        .accessibilityValue(unseen > 0 ? Text("\(unseen) new") : Text(verbatim: ""))
        .accessibilityIdentifier("chats.invitations")
    }
}
