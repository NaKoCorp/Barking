import BarkingKit
import Foundation
import Observation

/// One conversation (screen 4, spec §5.5).
@MainActor @Observable
final class ConversationModel {
    struct Item: Identifiable, Equatable {
        let id: Int64
        let outgoing: Bool
        let text: String
        let at: Date
        let status: MessageStatusKind
    }

    static let maxBytes = 4000
    static let counterFrom = 3500

    let contact: String
    private let core: CoreService
    private(set) var items: [Item] = []
    private(set) var name = ""
    private(set) var verified = false
    private(set) var keyChanged = false
    private var hidden: Set<Int64> = []
    private var sending = false
    private var retrying = false
    private var visible = false
    private(set) var sendError: String?
    var draft = ""

    init(contact: String, core: CoreService) {
        self.contact = contact
        self.core = core
    }

    var byteCount: Int { draft.utf8.count }
    var showsCounter: Bool { byteCount >= Self.counterFrom }
    var canSend: Bool {
        !sending && byteCount <= Self.maxBytes
            && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func onAppear() async {
        visible = true
        await reload()
        let changes = (try? await core.keyChanges(since: 0)) ?? []
        keyChanged = !verified && changes.contains { $0.contact == contact }
    }

    func onDisappear() { visible = false }

    func reload() async {
        if let c = try? await core.contacts().first(where: { $0.fingerprint == contact }) {
            name = c.alias ?? c.displayName
            verified = c.verified
        }
        let messages = (try? await core.messages(with: contact)) ?? []
        items = messages.filter { !hidden.contains($0.id) }.map {
            Item(id: $0.id, outgoing: $0.outgoing, text: $0.body,
                 at: Date(timeIntervalSince1970: TimeInterval($0.at)),
                 status: MessageStatusKind(status: $0.status, failed: $0.failed, outgoing: $0.outgoing))
        }
        // What arrives while the conversation is on screen is read.
        if visible, let last = items.last(where: { !$0.outgoing }) {
            try? await core.markRead(contact, upTo: last.id)
        }
    }

    /// Sends the draft; a second call while one runs does nothing.
    func send() async {
        guard canSend else { return }
        sending = true
        defer { sending = false }
        let text = draft
        draft = ""
        sendError = nil
        do {
            try await core.send(text, to: contact)
        } catch {
            draft = text
            sendError = String(localized: "Not sent. Try again in a moment.")
        }
        await reload()
    }

    /// Sends a failed message's text again and hides the failed one.
    func retry(_ id: Int64) async {
        guard !retrying, !hidden.contains(id), let item = items.first(where: { $0.id == id }) else { return }
        retrying = true
        defer { retrying = false }
        hidden.insert(id)
        try? await core.send(item.text, to: contact)
        await reload()
    }
}
