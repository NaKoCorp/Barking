import BarkingKit
import Foundation
import Observation

/// One line of the chats list (screen 3).
struct ChatRow: Identifiable, Equatable {
    var id: String { contact }
    let contact: String
    let name: String
    let verified: Bool
    let lastText: String?
    let lastAt: Date?
    let lastStatus: DeliveryState?
    let unread: Int

    /// The row's second line (U-22): the last message, or, with none, the
    /// contact's trust (U-20).
    enum Line: Equatable { case preview(String), trust(Trust) }

    var line: Line {
        if let lastText, !lastText.isEmpty { return .preview(lastText) }
        return .trust(Trust(verified: verified))
    }
}

@MainActor @Observable
final class ChatsModel {
    private let core: CoreService
    private(set) var rows: [ChatRow] = []
    private(set) var offline = false
    var query = ""

    init(core: CoreService) { self.core = core }

    /// Rows filtered on name and alias, ignoring case and accents.
    var visibleRows: [ChatRow] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return rows }
        return rows.filter { $0.name.range(of: q, options: [.caseInsensitive, .diacriticInsensitive]) != nil }
    }

    /// The contact is still there (a notification may outlive it): rows are
    /// reloaded first.
    func canOpen(_ contact: String) async -> Bool {
        await reload()
        return rows.contains { $0.contact == contact }
    }

    func reload() async {
        offline = await core.lastSync.map { !$0.networkUp } ?? false
        guard let summaries = try? await core.chatSummaries() else { return }
        var out: [ChatRow] = []
        for s in summaries {
            let c = s.contact
            let last = s.last
            out.append(ChatRow(
                contact: c.fingerprint,
                name: c.alias ?? c.displayName,
                verified: c.verified,
                lastText: last?.body,
                lastAt: last.map { Date(timeIntervalSince1970: TimeInterval($0.at)) },
                lastStatus: last?.shownState,
                unread: Int(s.unread)))
        }
        rows = out.sorted { ($0.lastAt ?? .distantPast) > ($1.lastAt ?? .distantPast) }
    }

    func delete(_ contact: String) async {
        try? await core.removeContact(contact)
        await reload()
    }
}

/// Adding a contact (spec §5.3): scan, link, confirmation.
@MainActor @Observable
final class AddContactModel {
    enum AddError: Equatable { case notACard, ownCard, failed }

    private let core: CoreService
    private(set) var preview: CardPreview?
    private(set) var error: AddError?
    private var bytes: Data?
    private var text: String?
    /// An add is running: Add shows its spinner and ignores taps.
    private(set) var isAdding = false
    /// The contact just added: the sheet then shows its safety code.
    private(set) var added: String?

    init(core: CoreService) { self.core = core }

    /// A QR code's bytes: a binary card, else a card link in text. `text` is
    /// the scanner's own decoding: VisionKit's raw symbol of a large link QR
    /// can decode short on an iPhone while its text is whole.
    func scanned(_ data: Data, text scannerText: String? = nil) async {
        if let p = try? inspectCard(bytes: data) {
            await show(p)
            if preview != nil { bytes = data; text = nil }
            return
        }
        let candidates = [String(data: data, encoding: .utf8), scannerText].compactMap { $0 }
        if let link = candidates.lazy.compactMap(Self.cardText(inLink:))
            .first(where: { (try? inspectCardText(text: $0)) != nil }) {
            await opened(link: link)
        } else {
            await show(nil)
        }
    }

    /// A QR code's text (any mode): only a `barking://card#…` link is a card.
    func scannedText(_ s: String) async {
        guard let link = Self.cardText(inLink: s) else { await show(nil); return }
        await opened(link: link)
    }

    /// The card text of a `barking://card#…` link.
    private static func cardText(inLink s: String) -> String? {
        let prefix = "barking://card#"
        return s.hasPrefix(prefix) ? String(s.dropFirst(prefix.count)) : nil
    }

    func opened(link: String) async {
        await show(try? inspectCardText(text: link))
        if preview != nil { text = link; bytes = nil }
    }

    private func show(_ p: CardPreview?) async {
        guard let p else { preview = nil; error = .notACard; return }
        if p.fingerprint == (try? await core.fingerprint()) {
            preview = nil
            error = .ownCard
            return
        }
        error = nil
        preview = p
    }

    /// Adds the previewed card; a second call while one runs does nothing.
    func add(alias: String) async -> Bool {
        guard !isAdding, preview != nil else { return false }
        isAdding = true
        defer { isAdding = false }
        let a = alias.trimmingCharacters(in: .whitespaces)
        do {
            if let bytes {
                added = try await core.addContact(card: bytes, alias: a.isEmpty ? nil : a)
            } else if let text {
                added = try await core.addContact(text: text, alias: a.isEmpty ? nil : a)
            }
            preview = nil
            return true
        } catch {
            self.error = .failed
            return false
        }
    }

    func reset() { preview = nil; error = nil; bytes = nil; text = nil; added = nil }
}
