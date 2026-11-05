import BarkingKit
import Foundation
import Observation

/// Where the app is: onboarding, or ready with its `CoreService`. Keeps a card
/// link opened before the identity exists (spec iOS messaging, Review Focus 3).
@MainActor @Observable
final class AppRouter {
    enum State {
        case onboarding
        case ready(CoreService)
    }

    private(set) var state: State
    private(set) var pendingCardLink: String?
    /// A `.barkinglink` file opened from AirDrop or Files.
    private(set) var pendingLinkFile: URL?

    init(start: State) { state = start }

    /// The state at launch: the existing identity, else onboarding.
    static func boot() -> AppRouter {
        #if BARKING_DEV
        let args = ProcessInfo.processInfo.arguments
        if args.contains("-BarkingUITestReset") {
            DeviceFactory.resetForUITests()
            for key in [OnboardingModel.confirmedKey, "barking.language", "barking.appearance"] {
                UserDefaults.standard.removeObject(forKey: key)
            }
        }
        if let i = args.firstIndex(of: "-BarkingUITestOpenCard"), i + 1 < args.count {
            let router = AppRouter(start: .onboarding)
            router.pendingCardLink = args[i + 1]
            return router
        }
        #endif
        if let device = try? DeviceFactory.openExisting(lockTimeoutMs: Budget.appLockMs) {
            return AppRouter(start: .ready(CoreService(device: device, runner: AppCallRunner())))
        }
        return AppRouter(start: .onboarding)
    }

    var core: CoreService? {
        if case .ready(let c) = state { return c }
        return nil
    }

    func becomeReady(core: CoreService) { state = .ready(core) }

    /// `barking://card#<card text>` keeps the card for the add-contact sheet;
    /// a `.barkinglink` file waits for the linking screen.
    func open(url: URL) {
        if url.isFileURL, url.pathExtension == "barkinglink" {
            pendingLinkFile = url
            return
        }
        guard url.scheme == "barking", url.host() == "card",
              let card = url.fragment(percentEncoded: false), !card.isEmpty else { return }
        pendingCardLink = card
    }

    func takePendingLinkFile() -> URL? {
        defer { pendingLinkFile = nil }
        return pendingLinkFile
    }

    func takePendingCardLink() -> String? {
        defer { pendingCardLink = nil }
        return pendingCardLink
    }
}
