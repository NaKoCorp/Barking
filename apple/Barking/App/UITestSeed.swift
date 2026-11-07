#if BARKING_DEV
import BarkingKit
import Foundation

/// Launch arguments of the UI tests that are read after the identity reset.
/// Never compiled into Release.
enum UITestFlags {
    /// `-BarkingUITestNoAnimations`: no animation anywhere, so a test never
    /// waits for one to end.
    static var noAnimations: Bool {
        ProcessInfo.processInfo.arguments.contains("-BarkingUITestNoAnimations")
    }
}

/// An identity made at launch, so a UI test starts on the chats instead of
/// walking the onboarding: `-BarkingUITestSeed <scenario>` and, for a
/// contact, `-BarkingUITestSeedCard <card>`.
@MainActor
enum UITestSeed {
    enum Error: Swift.Error, Equatable, CustomStringConvertible {
        case unknownScenario(String)

        var description: String {
            switch self {
            case .unknownScenario(let name): "unknown UI test seed scenario \"\(name)\""
            }
        }
    }

    /// Creates what the arguments ask for; nothing without `-BarkingUITestSeed`.
    /// Every handle is released on return: the core holds a file lock while a
    /// device is open, and `boot()` opens the identity again right after.
    static func apply(_ arguments: [String]) throws {
        guard let scenario = value(of: "-BarkingUITestSeed", in: arguments) else { return }
        switch scenario {
        case "ready": try ready(card: value(of: "-BarkingUITestSeedCard", in: arguments))
        default: throw Error.unknownScenario(scenario)
        }
    }

    /// A confirmed identity named Alice, with Sam in the contacts if a card is given.
    private static func ready(card: String?) throws {
        let created = try DeviceFactory.createNew(deviceName: "iPhone")
        try created.device.setDisplayName(name: "Alice")
        if let card { _ = try created.device.addContact(card: card, alias: "Sam") }
        UserDefaults.standard.set(true, forKey: OnboardingModel.confirmedKey)
    }

    private static func value(of flag: String, in arguments: [String]) -> String? {
        guard let i = arguments.firstIndex(of: flag), i + 1 < arguments.count else { return nil }
        return arguments[i + 1]
    }
}
#else
/// Release has no UI test flags: nothing is turned off by one.
enum UITestFlags {
    static var noAnimations: Bool { false }
}
#endif
