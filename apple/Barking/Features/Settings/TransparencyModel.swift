import BarkingKit
import Foundation
import Observation

/// Text of a log entry, from the key and args the core gives: the app
/// translates, the core's English `describe()` is never shown.
enum LogText {
    /// Args that are Unix seconds, by key: shown as a date.
    private static let dateArgs: [String: Int] = ["log.packet_sealed": 2]
    /// Args that are counts, by key: the text has plural forms (stringsdict).
    private static let countArgs: [String: Set<Int>] = ["log.history_imported": [0]]

    static func render(_ entry: LogEntry, locale: Locale = .current) -> String {
        format(NSLocalizedString(entry.key, tableName: "Log", comment: ""), entry, locale: locale)
    }

    /// The journal row's title (U-30): short, one line, from
    /// `log.title.<name>` (a sealed packet has one per mailbox kind).
    static func title(_ entry: LogEntry, locale: Locale = .current) -> String {
        let name = entry.key.hasPrefix("log.") ? String(entry.key.dropFirst(4)) : entry.key
        var key = "log.title.\(name)"
        if entry.key == "log.packet_sealed" {
            key += entry.args.count > 3 && entry.args[3] == "@intro_mailbox" ? ".intro_mailbox" : ".daily_mailbox"
        }
        let format = NSLocalizedString(key, tableName: "Log", comment: "")
        // An unknown key (a newer core): the full text still says it all.
        return format == key ? render(entry, locale: locale) : self.format(format, entry, locale: locale)
    }

    /// The text under the title. A sealed packet leaves out what the meta
    /// line already gives (size, tier, expiry), so raw bytes never show.
    static func body(_ entry: LogEntry, locale: Locale = .current) -> String {
        guard entry.key == "log.packet_sealed", entry.args.count > 3 else { return render(entry, locale: locale) }
        let mailbox = NSLocalizedString("log.arg.\(entry.args[3].dropFirst())", tableName: "Log", comment: "")
        return String(format: NSLocalizedString("log.body.packet_sealed", tableName: "Log", comment: ""),
                      locale: locale, mailbox)
    }

    /// The meta line after the time: "16 KB · large · expires 13 Nov 11:50"
    /// for a sealed packet, nothing for the others.
    static func meta(_ entry: LogEntry) -> [String] {
        guard entry.key == "log.packet_sealed", entry.args.count > 2 else { return [] }
        var parts: [String] = []
        if let size = UInt64(entry.args[0]) { parts.append(ByteSize.kilobytes(size)) }
        if entry.args[1].hasPrefix("@") {
            parts.append(NSLocalizedString("log.arg.\(entry.args[1].dropFirst())", tableName: "Log", comment: ""))
        }
        if let secs = TimeInterval(entry.args[2]) {
            // "13 Nov 11:50": the day and the clock, without the "at" a
            // combined format adds, so the meta line stays short.
            let d = Date(timeIntervalSince1970: secs)
            let date = "\(d.formatted(.dateTime.day().month())) \(d.formatted(.dateTime.hour().minute()))"
            parts.append(String(localized: "expires \(date)"))
        }
        return parts
    }

    private static func format(_ format: String, _ entry: LogEntry, locale: Locale) -> String {
        let args: [any CVarArg] = entry.args.enumerated().map { i, raw -> any CVarArg in
            if raw.hasPrefix("@") {
                return NSLocalizedString("log.arg.\(raw.dropFirst())", tableName: "Log", comment: "")
            }
            if countArgs[entry.key]?.contains(i) == true, let n = Int(raw) { return n }
            if dateArgs[entry.key] == i, let secs = TimeInterval(raw) {
                return Date(timeIntervalSince1970: secs).formatted(.dateTime.day().month().year().hour().minute())
            }
            return raw
        }
        return String(format: format, locale: locale, arguments: args)
            .trimmingCharacters(in: .whitespaces)
    }
}

/// The glyph that leads a journal row's meta line (U-30): which way the
/// event went, in place of an icon. Never colour alone.
enum LogGlyph: Equatable {
    case sent, received, verified, warning, devices, node, other

    static func of(key: String) -> LogGlyph {
        switch key {
        case "log.packet_sealed", "log.ack_emitted", "log.node_deposit": .sent
        case "log.packet_opened", "log.node_fetch", "log.duplicate_ignored": .received
        case "log.ack_verified": .verified
        case "log.contact_key_changed", "log.decrypt_failed": .warning
        case "log.node_avoided": .node
        case "log.device_linked", "log.link_finished", "log.sync_applied", "log.sync_skipped",
             "log.contact_card_updated", "log.history_imported", "log.own_devices_updated", "log.seal_skipped",
             "log.admin_transfer_started", "log.admin_transferred", "log.admin_received",
             "log.this_device_removed", "log.device_removed", "log.remove_requested": .devices
        // Session, rejected frame, and any key a newer core adds: a glyph
        // that claims nothing.
        default: .other
        }
    }

    var symbol: String {
        switch self {
        case .sent: "↑"
        case .received: "↓"
        case .verified: "✓"
        case .warning: "✗"
        case .devices: "⇄"
        case .node: "≋"
        case .other: "·"
        }
    }

    /// Asset name of the glyph.
    var token: String {
        switch self {
        case .verified: "ok"
        case .warning: "danger"
        case .sent, .received: "accent"
        default: "fgSoft"
        }
    }

    /// ✓ and ✗ come from the system font: Fira Code draws ✓ like a √.
    var usesSystemFont: Bool { self == .verified || self == .warning }
}

/// One line of the journal: a title, a meta line, then the explanation.
struct LogRow: Identifiable, Equatable {
    /// Id of the event in the core's log (unique, grows with time).
    let id: Int64
    let at: Date
    let family: String
    let title: String
    let glyph: LogGlyph
    /// What follows the time on the meta line ("16 KB", "large", …).
    let details: [String]
    /// The explanation, shown two lines until tapped.
    let text: String
    let security: Bool

    /// "11:58 · 16 KB · large · expires 13 Nov 11:50" (the glyph is drawn
    /// before it).
    var meta: String {
        ([at.formatted(.dateTime.hour().minute())] + details).joined(separator: " · ")
    }
}

/// The rows of one day, newest first.
struct LogDay: Identifiable, Equatable {
    var id: Date { date }
    /// Start of the day.
    let date: Date
    let rows: [LogRow]
}

/// A line of "Where my data is".
struct DataRow: Identifiable, Equatable {
    let id: String
    let icon: String
    let title: String
    let detail: String
}

/// Which events the journal lists. "Keys and devices" is the security class:
/// the events to watch first.
enum JournalFilter: Hashable { case everything, keysAndDevices }

/// Settings › Transparency (spec block 2b §5): the core's journal by day,
/// 100 entries a page, and where the data is.
@MainActor @Observable
final class TransparencyModel {
    static let pageSize: UInt32 = 100

    private let core: CoreService
    private let protection: () -> String
    private let calendar: Calendar
    private(set) var days: [LogDay] = []
    private(set) var dataRows: [DataRow] = []
    private(set) var canLoadMore = false
    private(set) var loading = false
    private(set) var filter: JournalFilter = .everything
    private var rows: [LogRow] = []
    /// Id of the oldest row loaded: the next page starts before it.
    private var cursor: Int64?

    init(core: CoreService, protection: @escaping () -> String = { KeyStore.live.protection },
         calendar: Calendar = .current) {
        self.core = core
        self.protection = protection
        self.calendar = calendar
    }

    var isEmpty: Bool { rows.isEmpty }
    /// The oldest row loaded: showing it asks for the next page.
    var oldestID: Int64? { cursor }

    func load() async {
        dataRows = Self.dataRows(protection: protection())
        await reload()
    }

    func setFilter(_ filter: JournalFilter) async {
        self.filter = filter
        await reload()
    }

    func loadMore() async {
        guard canLoadMore, !loading else { return }
        await fetch(before: cursor)
    }

    private func reload() async {
        rows = []
        days = []
        cursor = nil
        canLoadMore = false
        await fetch(before: nil)
    }

    private func fetch(before: Int64?) async {
        loading = true
        defer { loading = false }
        let filter = self.filter
        guard let page = try? await core.transparencyLog(limit: Self.pageSize, before: before, securityOnly: filter == .keysAndDevices),
              filter == self.filter, before == cursor else { return }
        rows += page.map { e in
            LogRow(id: e.id, at: Date(timeIntervalSince1970: TimeInterval(e.at)), family: e.family,
                   title: LogText.title(e), glyph: LogGlyph.of(key: e.key), details: LogText.meta(e),
                   text: LogText.body(e), security: e.security)
        }
        cursor = rows.last?.id
        canLoadMore = page.count == Int(Self.pageSize)
        days = Self.group(rows, calendar: calendar)
    }

    /// Rows (newest first) by day. Rows are ordered by id, the day groups
    /// by first appearance; a day never shows twice, even when the phone's
    /// clock went back and forth.
    static func group(_ rows: [LogRow], calendar: Calendar) -> [LogDay] {
        var order: [Date] = []
        var byDay: [Date: [LogRow]] = [:]
        for row in rows {
            let day = calendar.startOfDay(for: row.at)
            if byDay[day] == nil { order.append(day) }
            byDay[day, default: []].append(row)
        }
        return order.map { LogDay(date: $0, rows: byDay[$0] ?? []) }
    }

    /// "Today", "Yesterday", otherwise the date in full.
    func title(of day: LogDay) -> String {
        if calendar.isDateInToday(day.date) { return String(localized: "Today") }
        if calendar.isDateInYesterday(day.date) { return String(localized: "Yesterday") }
        return day.date.formatted(.dateTime.weekday(.wide).day().month(.wide))
    }

    /// Where the data is: here, the key, the nodes, the log (spec §5).
    static func dataRows(protection: String) -> [DataRow] {
        let enclave = protection == "secure-enclave"
        return [
            DataRow(id: "database", icon: "internaldrive", title: String(localized: "Encrypted database on this iPhone"),
                    detail: String(localized: "Your contacts and messages are kept here, encrypted with SQLCipher.")),
            DataRow(id: "key", icon: enclave ? "cpu" : "key",
                    title: enclave ? String(localized: "Database key protected by the Secure Enclave")
                        : String(localized: "Database key protected by the keychain only"),
                    detail: enclave ? String(localized: "Wrapped by a key that never leaves this iPhone's chip.")
                        : String(localized: "Kept in the keychain, without the Secure Enclave.")),
            DataRow(id: "nodes", icon: "point.3.connected.trianglepath.dotted",
                    title: String(localized: "Nothing in clear on the nodes"),
                    detail: String(localized: "Packets stay there at most 24 hours.")),
            DataRow(id: "log", icon: "clock.arrow.circlepath", title: String(localized: "Journal and paths"),
                    detail: String(localized: "Kept 30 days on this iPhone, never sent.")),
        ]
    }
}
