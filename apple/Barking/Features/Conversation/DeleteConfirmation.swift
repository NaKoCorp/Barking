import BarkingKit
import SwiftUI

/// The confirmation before deleting one message (spec Lot M §7.4): which
/// case, from the delivery shown, and its texts. Always a
/// `confirmationDialog` whose cancel button is "Keep".
enum DeleteConfirmation: Equatable {
    case pending, onNetwork, received, notDelivered
    /// Left for `left` of the contact's `total` devices, still here for the others.
    case mixed(left: Int, total: Int)
    /// A received message.
    case receivedMessage
    /// A message I sent from another of my devices: no delivery here, so
    /// nothing is said about the contact.
    case sentElsewhere

    /// §7.4 "Choix du cas": Pending if nothing left and something waits
    /// here; Mixed if some left and some wait; otherwise the combined state.
    init(outgoing: Bool, delivery: Delivery?) {
        guard outgoing else {
            self = .receivedMessage
            return
        }
        guard let d = delivery else {
            self = .sentElsewhere
            return
        }
        if d.devicesLeft == 0 && d.devicesPending > 0 {
            self = .pending
        } else if d.devicesLeft > 0 && d.devicesPending > 0 {
            self = .mixed(left: Int(d.devicesLeft), total: Int(d.devices))
        } else {
            switch d.state {
            case .pending: self = .pending
            case .onNetwork: self = .onNetwork
            case .received: self = .received
            case .notDelivered: self = .notDelivered
            }
        }
    }

    var title: LocalizedStringKey {
        switch self {
        case .pending, .notDelivered: "Delete this message?"
        case .onNetwork, .received, .mixed: "Delete from this iPhone?"
        case .receivedMessage, .sentElsewhere: "Delete this message from this iPhone?"
        }
    }

    /// `name`: the contact's alias, otherwise display name.
    func message(name: String, bundle: Bundle = .main, locale: Locale = .current) -> String {
        switch self {
        case .pending:
            String(localized: "It hasn’t left this iPhone. \(name) won’t receive it.", bundle: bundle, locale: locale)
        case .onNetwork:
            String(localized: "It’s already on the network: \(name) will still receive it.", bundle: bundle, locale: locale)
        case .received:
            String(localized: "\(name) already received it and keeps it.", bundle: bundle, locale: locale)
        case .notDelivered:
            String(localized: "No device of theirs ever received it.", bundle: bundle, locale: locale)
        case .mixed(let left, let total):
            String(localized: "It already left for \(left) of \(name)’s \(total) devices: that one keeps it. The rest is cancelled.",
                   bundle: bundle, locale: locale)
        case .receivedMessage:
            String(localized: "\(name) keeps their copy.", bundle: bundle, locale: locale)
        case .sentElsewhere:
            String(localized: "Your other devices keep their copy.", bundle: bundle, locale: locale)
        }
    }

    var button: LocalizedStringKey {
        switch self {
        case .pending: "Delete and cancel"
        case .mixed: "Delete and cancel the rest"
        case .onNetwork, .received, .notDelivered, .receivedMessage, .sentElsewhere: "Delete"
        }
    }
}
