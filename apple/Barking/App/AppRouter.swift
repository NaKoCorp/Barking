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
        /// This device started linking and waits for its file.
        case linking(CoreService)
        /// The identity exists but could not be opened (lock, keychain).
        case failed
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
            DeviceFactory.resetIdentity()
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
        return AppRouter(start: initialState(
            opening: { try DeviceFactory.openExisting(lockTimeoutMs: Budget.appLockMs) },
            runner: AppCallRunner()))
    }

    /// No identity: onboarding; a pending link: the waiting screen; an error
    /// opening: a retry screen, never onboarding (spec, review I6).
    static func initialState(opening: () throws -> (any DeviceHandle)?, runner: any CallRunner) -> State {
        do {
            guard let device = try opening() else { return .onboarding }
            let core = CoreService(device: device, runner: runner)
            return (try? device.isPendingLink()) == true ? .linking(core) : .ready(core)
        } catch {
            return .failed
        }
    }

    func retry() {
        state = Self.initialState(
            opening: { try DeviceFactory.openExisting(lockTimeoutMs: Budget.appLockMs) },
            runner: AppCallRunner())
    }

    func restartOnboarding() { state = .onboarding }

    var core: CoreService? {
        switch state {
        case .ready(let c), .linking(let c): c
        default: nil
        }
    }

    func becomeReady(core: CoreService) {
        state = .ready(core)
        #if BARKING_DEV
        // End-to-end tests read this device's card from the shared container.
        if ProcessInfo.processInfo.arguments.contains("-BarkingUITestOpenCard") {
            Task { if let card = try? await core.myCard() { SharedPaths.devExport("dev-card.txt", card.text) } }
        }
        #endif
    }

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
