import BarkingKit
import Foundation

/// The history of a contact request, in words: the list row's second line
/// (`short`) and the request page's History section (`long`).
enum RequestHistory {
    /// "2 hr. ago", "il y a 3 j": the Copie's relative durations, from
    /// `Date.RelativeFormatStyle(presentation: .named, unitsStyle: .abbreviated)`
    /// anchored at `now` (the abbreviated `RelativeDateTimeFormatter` says
    /// "-2 h" in French). A date after `now` (a clock ahead) reads as now,
    /// never "in 2 min".
    static func relative(_ date: Date, now: Date, locale: Locale = .current) -> String {
        Date.AnchoredRelativeFormatStyle(anchor: min(date, now), presentation: .named, unitsStyle: .abbreviated,
                                         locale: locale).format(now)
    }

    private static func date(_ secs: UInt64) -> Date { Date(timeIntervalSince1970: TimeInterval(secs)) }

    /// One invitation: received, dated by its first sight. Resent: dated by
    /// the last one, so a resend reads as recent.
    static func short(_ r: ContactRequestInfo, now: Date, bundle: Bundle = .main, locale: Locale = .current) -> String {
        if r.inviteCount <= 1 {
            let ago = relative(date(r.firstSeen), now: now, locale: locale)
            return String(localized: "Invitation received \(ago)", bundle: bundle, locale: locale)
        }
        let ago = relative(date(r.lastSeen), now: now, locale: locale)
        return String(localized: "Invitation resent · \(ago)", bundle: bundle, locale: locale)
    }

    /// The short line, then, after a resend, how many invitations came.
    static func long(_ r: ContactRequestInfo, now: Date, bundle: Bundle = .main, locale: Locale = .current) -> [String] {
        let first = short(r, now: now, bundle: bundle, locale: locale)
        guard r.inviteCount > 1 else { return [first] }
        let count = Int(r.inviteCount)
        return [first, String(localized: "\(count) invitations", bundle: bundle, locale: locale)]
    }

    /// "2 messages waiting", after the history on a list row.
    static func waiting(_ count: Int, bundle: Bundle = .main, locale: Locale = .current) -> String {
        String(localized: "\(count) messages waiting", bundle: bundle, locale: locale)
    }
}
