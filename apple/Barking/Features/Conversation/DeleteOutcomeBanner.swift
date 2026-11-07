import BarkingKit
import SwiftUI

/// What the app says after a deletion (spec Lot M §6.7): the state shown in
/// the confirmation, set against what the core really did.
enum DeleteBanner {
    /// The sentence to show, before it is turned into text.
    enum Message: Equatable {
        /// "It had already left: Alice will still receive it."
        case alreadyLeft(name: String)
        /// "Part of it had already left: Alice will receive it on 1 of their 2 devices."
        case partlyLeft(name: String, left: Int, total: Int)
        /// Several messages: `count` had already left (or partly), `names` (the
        /// contacts, none for "Cancel all" without names) still receive them.
        case several(count: Int, names: [String])

        /// For a `Banner(.info)`.
        var key: LocalizedStringKey {
            switch self {
            case .alreadyLeft(let name): "It had already left: \(name) will still receive it."
            case .partlyLeft(let name, let left, let total):
                "Part of it had already left: \(name) will receive it on \(left) of their \(total) devices."
            case .several(let count, let names):
                names.isEmpty ? "\(count) had already left and will still be delivered."
                    : "\(count) had already left: \(DeleteBanner.names(names)) will still receive it.\(names.count)"
            }
        }

        /// The sentence in a given language (tests read both).
        func string(bundle: Bundle = .main, locale: Locale = .current) -> String {
            switch self {
            case .alreadyLeft(let name):
                String(localized: "It had already left: \(name) will still receive it.", bundle: bundle, locale: locale)
            case .partlyLeft(let name, let left, let total):
                String(localized: "Part of it had already left: \(name) will receive it on \(left) of their \(total) devices.",
                       bundle: bundle, locale: locale)
            case .several(let count, let names) where names.isEmpty:
                String(localized: "\(count) had already left and will still be delivered.", bundle: bundle, locale: locale)
            case .several(let count, let names):
                // The last argument (the number of names) only drives the French verb.
                String(localized: "\(count) had already left: \(DeleteBanner.names(names, bundle: bundle, locale: locale)) will still receive it.\(names.count)",
                       bundle: bundle, locale: locale)
            }
        }
    }

    /// The sentence due after a deletion, or nil when nothing needs saying.
    /// - `shown`: the state the confirmation showed, nil for several messages
    ///   (selection, "Cancel all").
    /// - `contactName`: alias, otherwise display name (one message).
    /// - `devices`: devices it had left for and its total, from the delivery
    ///   the confirmation showed. Without it, a partly cancelled message is
    ///   told as "already left", which stays true.
    static func message(shown: DeliveryState?, outcome: DeleteOutcome, contactName: String,
                        devices: (left: Int, total: Int)? = nil) -> Message? {
        guard let shown else {
            let count = Int(outcome.alreadyLeft + outcome.partlyCancelled)
            guard count > 0 else { return nil }
            return .several(count: count, names: outcome.stillReceiving)
        }
        // The other states already said what happens: the contact receives
        // it, or has it, or never will.
        guard shown == .pending else { return nil }
        if outcome.alreadyLeft > 0 { return .alreadyLeft(name: contactName) }
        if outcome.partlyCancelled > 0 {
            // A delivery shown as Pending has no device left: without a
            // fresher count, "already left" stays true where "0 of 2" would not.
            guard let devices, devices.left > 0 else { return .alreadyLeft(name: contactName) }
            return .partlyLeft(name: contactName, left: devices.left, total: devices.total)
        }
        return nil
    }

    static func text(shown: DeliveryState?, outcome: DeleteOutcome, contactName: String,
                     devices: (left: Int, total: Int)? = nil) -> LocalizedStringKey? {
        message(shown: shown, outcome: outcome, contactName: contactName, devices: devices)?.key
    }

    /// Names for a sentence: at most two, then "and N others".
    static func names(_ list: [String], bundle: Bundle = .main, locale: Locale = .current) -> String {
        switch list.count {
        case 0: return ""
        case 1: return list[0]
        case 2:
            let f = ListFormatter()
            f.locale = locale
            return f.string(from: list) ?? list.joined(separator: ", ")
        default:
            let (a, b, others) = (list[0], list[1], list.count - 2)
            return String(localized: "\(a), \(b) and \(others) others", bundle: bundle, locale: locale)
        }
    }
}
