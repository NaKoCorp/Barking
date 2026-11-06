import BarkingKit
import Foundation
import Observation

/// Text of a log entry, from the key and args the core gives: the app
/// translates, the core's English `describe()` is never shown.
enum LogText {
    /// Args that are Unix seconds, by key: shown as a date.
    private static let dateArgs: [String: Int] = ["log.packet_sealed": 2]

    static func render(_ entry: LogEntry, locale: Locale = .current) -> String {
        let format = NSLocalizedString(entry.key, tableName: "Log", comment: "")
        let args: [CVarArg] = entry.args.enumerated().map { i, raw in
            if raw.hasPrefix("@") {
                return NSLocalizedString("log.arg.\(raw.dropFirst())", tableName: "Log", comment: "")
            }
            if dateArgs[entry.key] == i, let secs = TimeInterval(raw) {
                return Date(timeIntervalSince1970: secs).formatted(.dateTime.day().month().year().hour().minute())
            }
            return raw
        }
        return String(format: format, locale: locale, arguments: args)
            .trimmingCharacters(in: .whitespaces)
    }
}

/// One line of the journal.
struct LogRow: Identifiable, Equatable {
    /// Position in the log, newest first.
    let id: Int
    let at: Date
    let family: String
    let text: String
    let security: Bool

    var icon: String {
        switch family {
        case "session": "key.horizontal"
        case "packet": "envelope"
        case "device": "iphone"
        case "node": "point.3.connected.trianglepath.dotted"
        default: "shield.lefthalf.filled"
        }
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
    private(set) var securityOnly = false
    private var rows: [LogRow] = []

    init(core: CoreService, protection: @escaping () -> String = { KeyStore.live.protection },
         calendar: Calendar = .current) {
        self.core = core
        self.protection = protection
        self.calendar = calendar
    }

    var isEmpty: Bool { rows.isEmpty }

    func load() async {
        dataRows = Self.dataRows(protection: protection())
        await reload()
    }

    func setSecurityOnly(_ on: Bool) async {
        securityOnly = on
        await reload()
    }

    func loadMore() async {
        guard canLoadMore, !loading else { return }
        await fetch(offset: rows.count)
    }

    private func reload() async {
        rows = []
        days = []
        canLoadMore = false
        await fetch(offset: 0)
    }

    private func fetch(offset: Int) async {
        loading = true
        defer { loading = false }
        let filter = securityOnly
        guard let page = try? await core.transparencyLog(limit: Self.pageSize, offset: UInt32(offset),
                                                          securityOnly: filter),
              filter == securityOnly, offset == rows.count else { return }
        rows += page.enumerated().map { i, e in
            LogRow(id: offset + i, at: Date(timeIntervalSince1970: TimeInterval(e.at)), family: e.family,
                   text: LogText.render(e), security: e.security)
        }
        canLoadMore = page.count == Int(Self.pageSize)
        days = Self.group(rows, calendar: calendar)
    }

    /// Rows (newest first) by day, newest day first.
    static func group(_ rows: [LogRow], calendar: Calendar) -> [LogDay] {
        var out: [LogDay] = []
        var current: (date: Date, rows: [LogRow])?
        for row in rows {
            let day = calendar.startOfDay(for: row.at)
            if current?.date == day {
                current?.rows.append(row)
            } else {
                if let c = current { out.append(LogDay(date: c.date, rows: c.rows)) }
                current = (day, [row])
            }
        }
        if let c = current { out.append(LogDay(date: c.date, rows: c.rows)) }
        return out
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
                    detail: String(localized: "Your contacts and messages are kept here, encrypted.")),
            DataRow(id: "key", icon: enclave ? "cpu" : "key",
                    title: enclave ? String(localized: "Database key protected by the Secure Enclave")
                        : String(localized: "Database key protected by the keychain only"),
                    detail: enclave ? String(localized: "The key never leaves this iPhone's chip.")
                        : String(localized: "This iPhone has no Secure Enclave available.")),
            DataRow(id: "nodes", icon: "point.3.connected.trianglepath.dotted",
                    title: String(localized: "Nothing in clear on the nodes"),
                    detail: String(localized: "Packets stay there at most 7 days.")),
            DataRow(id: "log", icon: "clock.arrow.circlepath", title: String(localized: "Journal and paths"),
                    detail: String(localized: "Kept 30 days on this iPhone, never sent.")),
        ]
    }
}
