import BarkingKit
import Foundation

/// The history of a contact request, in words: the list row's second line
/// (`short`) and the request page's History section (`long`).
enum RequestHistory {
    /// "3 d ago", "2 h ago": the Copie's relative durations. A date after
    /// `now` (a clock ahead) reads as now, never "in 2 min".
    static func relative(_ date: Date, now: Date, locale: Locale = .current) -> String {
        let f = RelativeDateTimeFormatter()
        f.dateTimeStyle = .named
        f.unitsStyle = .abbreviated
        f.locale = locale
        return f.localizedString(for: min(date, now), relativeTo: now)
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
