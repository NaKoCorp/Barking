import BarkingKit
import Foundation

/// Every word and sentence a node is shown with (node transparency spec
/// §7.1 to §7.3), shared by the "Internet relays" list and the node's
/// detail screen. A state is always a glyph and a word, never a colour
/// alone, and never a percentage.
enum NodeLabels {
    /// The language the texts are read in: the app's, or a forced one in tests.
    struct Lang {
        var bundle: Bundle
        var locale: Locale
        var timeZone: TimeZone = .current

        static var current: Lang { Lang(bundle: .main, locale: .current) }

        /// The table of `locale`'s language, so a screen follows the app's
        /// `\.locale` rather than the system's.
        static func of(_ locale: Locale) -> Lang { Lang(bundle: .strings(for: locale), locale: locale) }

        fileprivate func text(_ key: String.LocalizationValue) -> String {
            String(localized: key, bundle: bundle, locale: locale)
        }

        fileprivate var calendar: Calendar {
            var c = Calendar(identifier: .gregorian)
            c.timeZone = timeZone
            c.locale = locale
            return c
        }
    }

    /// A glyph state and its word.
    struct Line: Equatable {
        let state: StatusDot.State
        let text: String
    }

    // MARK: Names

    /// "A7KQ2M…X4Q": enough to tell two nodes apart, short enough for a row.
    static func shortId(_ id: String) -> String {
        id.count > 9 ? "\(id.prefix(6))…\(id.suffix(3))" : id
    }

    /// The host it declares, else its short identifier.
    static func name(_ node: NodeInfo) -> String {
        guard let host = node.origin?.asName.trimmingCharacters(in: .whitespaces), !host.isEmpty
        else { return shortId(node.id) }
        return host
    }

    /// Its declared country as an ISO code, else a dash (no flag, no emoji).
    /// An en dash: the app's copy keeps no em dash.
    static let noCountry = "–"

    static func country(_ node: NodeInfo) -> String {
        guard let code = node.origin?.country, code.count == 2 else { return noCountry }
        return code.uppercased()
    }

    /// How it came to this iPhone.
    static func originKind(_ kind: NodeOriginKind, lang: Lang = .current) -> String {
        switch kind {
        case .bootstrap: lang.text("provided with Barking")
        case .manual: lang.text("added by hand")
        case .fromCard: lang.text("from a contact's card")
        case .discovered: lang.text("found on the network")
        }
    }

    // MARK: Reliability (§7.3)

    static func reliabilityWord(_ r: Reliability, now: Date = .now, lang: Lang = .current) -> String {
        switch r {
        case .new: return lang.text("new")
        case .good: return lang.text("good")
        case .fair: return lang.text("fair (reliability)")
        case .weak: return lang.text("weak (reliability)")
        case .avoided(let until, _):
            let end = Date(timeIntervalSince1970: TimeInterval(until))
            // Avoided for days: an hour alone would read as today.
            if lang.calendar.isDate(end, inSameDayAs: now) {
                let time = end.formatted(Date.FormatStyle(date: .omitted, time: .shortened, locale: lang.locale,
                                                          timeZone: lang.timeZone))
                return lang.text("avoided until \(time)")
            }
            let day = end.formatted(Date.FormatStyle(locale: lang.locale, timeZone: lang.timeZone).day().month())
            return lang.text("avoided until \(day) (date)")
        }
    }

    /// The glyph of a reliability: amber once it falters, never red.
    static func reliabilityState(_ r: Reliability) -> StatusDot.State {
        switch r {
        case .new: .checking
        case .good, .fair: .ok
        case .weak, .avoided: .waiting
        }
    }

    /// The sentence always shown under the value, in plain words.
    static func reliabilitySentence(_ r: Reliability, lang: Lang = .current) -> String {
        switch r {
        case .new: lang.text("This iPhone hasn't exchanged enough with this relay to judge it yet.")
        case .good: lang.text("This relay has been answering your iPhone well lately.")
        case .fair:
            lang.text("This relay doesn't always answer. Your messages stay safe: they're also kept elsewhere.")
        case .weak:
            lang.text("This relay has often failed. Barking uses it less and hands your messages to others.")
        case .avoided(_, .messageLost):
            lang.text("A message left with this relay disappeared. Barking avoids it for now and will try again later.")
        case .avoided(_, .unreachable):
            lang.text("This relay stopped answering. Barking avoids it for now and will try again later.")
        }
    }

    // MARK: Latency, fill, push link

    /// rapide under 100 ms, correct under 300 ms, lent beyond.
    static func latencyWord(ms: UInt32, lang: Lang = .current) -> String {
        switch ms {
        case ..<100: lang.text("fast")
        case ..<300: lang.text("okay")
        default: lang.text("slow")
        }
    }

    static func milliseconds(_ ms: UInt32, lang: Lang = .current) -> String {
        lang.text("\(Int(ms)) ms")
    }

    /// "38 ms · rapide".
    static func latency(ms: UInt32, lang: Lang = .current) -> String {
        "\(milliseconds(ms, lang: lang)) · \(latencyWord(ms: ms, lang: lang))"
    }

    static func fillWord(_ tier: FillTierView, lang: Lang = .current) -> String {
        switch tier {
        case .low: lang.text("low")
        case .medium: lang.text("medium")
        case .high: lang.text("high")
        case .full: lang.text("full")
        }
    }

    /// Filled segments out of 4.
    static func fillSegments(_ tier: FillTierView) -> Int {
        switch tier {
        case .low: 1
        case .medium: 2
        case .high: 3
        case .full: 4
        }
    }

    /// Whether the node reaches the push relay that rings this iPhone.
    static func pushLinkLine(_ link: PushLinkView, lang: Lang = .current) -> Line {
        switch link {
        case .ok: Line(state: .ok, text: lang.text("reached"))
        case .failing: Line(state: .down, text: lang.text("unreachable"))
        case .unknown: Line(state: .checking, text: lang.text("not shared"))
        }
    }

    // MARK: Origin (§7.2)

    /// The list's short word for a declared origin.
    static func verdictWord(_ verdict: OriginVerdictView, lang: Lang = .current) -> Line {
        switch verdict {
        case .matches: Line(state: .ok, text: lang.text("verified"))
        case .mismatch: Line(state: .waiting, text: lang.text("doesn't match"))
        case .notReported, .notInBase, .noRecord: Line(state: .checking, text: lang.text("can't be checked"))
        }
    }

    /// The detail screen's line under the declared / observed table.
    static func verdictLine(_ verdict: OriginVerdictView, lang: Lang = .current) -> Line {
        switch verdict {
        case .matches:
            return Line(state: .ok, text: lang.text("Matches what this iPhone sees"))
        case .mismatch(let declaredCountry, let observedCountry, let declaredAsn, let observedAsn):
            if declaredCountry != observedCountry {
                let declared = countryName(declaredCountry, lang: lang)
                let observed = countryName(observedCountry, lang: lang)
                return Line(state: .waiting, text: lang.text("Declared \(declared) · observed \(observed)"))
            }
            return Line(state: .waiting,
                        text: lang.text("Declared \("AS\(declaredAsn)") · observed \("AS\(observedAsn)")"))
        case .notReported:
            return Line(state: .checking, text: lang.text("Can't be checked · this node doesn't share its origin"))
        case .notInBase:
            return Line(state: .checking, text: lang.text("Can't be checked · address missing from the base"))
        case .noRecord:
            return Line(state: .checking, text: lang.text("Can't be checked · no address to compare"))
        }
    }

    /// Said under a mismatch.
    static func mismatchAdvice(lang: Lang = .current) -> String {
        lang.text("Address databases are sometimes behind. If the gap stays, you can block this node.")
    }

    /// "France", else the code itself.
    static func countryName(_ code: String, lang: Lang = .current) -> String {
        lang.locale.localizedString(forRegionCode: code) ?? code
    }

    // MARK: Times and counts

    /// `last_seen` is rounded to the hour on purpose: never a minute.
    static func lastSeen(_ seconds: UInt64, now: Date, lang: Lang = .current) -> String {
        guard seconds > 0 else { return lang.text("never") }
        let at = Date(timeIntervalSince1970: TimeInterval(seconds))
        let hours = Int(now.timeIntervalSince(at) / 3_600)
        if hours < 1 { return lang.text("less than an hour ago") }
        let calendar = lang.calendar
        if calendar.isDate(at, inSameDayAs: now) { return lang.text("\(hours) h ago") }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now),
           calendar.isDate(at, inSameDayAs: yesterday) { return lang.text("yesterday") }
        return at.formatted(Date.FormatStyle(locale: lang.locale, timeZone: lang.timeZone).day().month().year())
    }

    static func subscriptions(_ n: Int, lang: Lang = .current) -> String {
        lang.text("\(n) subscriptions")
    }

    /// The question of "Restore the default nodes" (§7.1).
    static func resetMessage(_ n: Int, lang: Lang = .current) -> String {
        lang.text("The \(n) nodes that came with Barking and that you removed come back to the list. Blocked nodes stay blocked.")
    }

    // MARK: The row (§7.1)

    /// The texts of one row of the list, and the one sentence VoiceOver
    /// reads for it.
    struct Row {
        let country: String
        let name: String
        let status: Line
        /// Short id and address; empty when the name is the short id and
        /// the address is unknown.
        let idLine: String
        let verdict: Line?
        /// "wakes · 3 subscriptions" when it holds wake-ups of mine.
        let extras: String?
        let accessibilityLabel: String

        init(_ node: NodeInfo, now: Date = .now, lang: Lang = .current) {
            country = NodeLabels.country(node)
            name = NodeLabels.name(node)
            let word = NodeLabels.reliabilityWord(node.reliability, now: now, lang: lang)
            let ms = node.latencyMs.map { NodeLabels.milliseconds($0, lang: lang) }
            status = Line(state: NodeLabels.reliabilityState(node.reliability),
                          text: [word, ms].compactMap { $0 }.joined(separator: " · "))
            // The short id once: as the name when no host is declared.
            let short = NodeLabels.shortId(node.id)
            idLine = [name == short ? nil : short, node.addr.isEmpty ? nil : node.addr]
                .compactMap { $0 }.joined(separator: " · ")
            verdict = node.origin.map { NodeLabels.verdictWord($0.verdict, lang: lang) }
            let subs = node.mySubscriptions > 0
                ? NodeLabels.subscriptions(Int(node.mySubscriptions), lang: lang) : nil
            extras = subs.map { "\(lang.text("wakes")) · \($0)" }
            let place = node.origin.map { NodeLabels.countryName($0.country, lang: lang) }
                ?? lang.text("origin unknown")
            accessibilityLabel = [place, name, lang.text("reliability \(word)"), ms, verdict?.text,
                                  subs.map { "\(lang.text("wakes")), \($0)" }]
                .compactMap { $0 }.joined(separator: ", ")
        }
    }
}
