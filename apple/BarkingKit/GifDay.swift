import Foundation

/// The local day GIF usage is counted on (spec GIF §6.6). Each GIF call
/// hands the core the phone's UTC offset at that moment, and the core files
/// the use under `(unix + offset) / 86 400`: the user's own date, whatever
/// UTC says. `GifUsageDayInfo.day` is that number, read as a calendar date
/// (its UTC components), never as an instant.
public enum GifDay {
    /// The phone's offset from UTC at `date`, in seconds east (summer time
    /// included).
    public static func utcOffset(at date: Date = Date(), in timeZone: TimeZone = .current) -> Int32 {
        Int32(timeZone.secondsFromGMT(for: date))
    }

    /// The day number the core files a use at `date` under, in `timeZone`.
    public static func number(of date: Date, in timeZone: TimeZone = .current) -> UInt32 {
        let local = Int64(date.timeIntervalSince1970.rounded(.down)) + Int64(utcOffset(at: date, in: timeZone))
        return local < 0 ? 0 : UInt32(clamping: local / 86_400)
    }

    /// The start, in `calendar`, of the date day `day` stands for.
    public static func date(of day: UInt32, in calendar: Calendar) -> Date? {
        var utc = Calendar(identifier: .gregorian)
        utc.timeZone = TimeZone(identifier: "UTC") ?? .gmt
        let parts = utc.dateComponents([.year, .month, .day],
                                       from: Date(timeIntervalSince1970: TimeInterval(day) * 86_400))
        return calendar.date(from: parts).map(calendar.startOfDay(for:))
    }
}
