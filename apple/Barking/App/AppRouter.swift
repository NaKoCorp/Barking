import BarkingKit
import Foundation
import Observation
#if BARKING_DEV
import UIKit
#endif

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
        /// The database key no longer unwraps: its Secure Enclave key is
        /// gone (backup restored on another iPhone, spec §7.2). Retrying
        /// cannot help; linking or recovering can, after erasing.
        case unreadable
        /// An erase was asked for and could not finish: nothing opens until
        /// it does; "Try again" runs it again.
        case wipeFailed
    }

    private(set) var state: State
    /// The app's router, for the background wake (`AppDelegate`), which
    /// SwiftUI gives no other way to reach.
    static weak var current: AppRouter?
    private(set) var pendingCardLink: String?
    /// A `.barkinglink` file opened from AirDrop or Files.
    private(set) var pendingLinkFile: URL?
    /// A conversation to open (a tapped notification), on `messageId` when
    /// it names one; taken by the chats once they show.
    struct OpenTarget: Equatable {
        let contact: String
        let messageId: Int64?
    }
    private(set) var pendingOpen: OpenTarget?
    /// Where onboarding starts after erasing unreadable data.
    private(set) var pendingOnboardingStep: OnboardingModel.Step?
    /// Erasing the unreadable data failed; the screen offers it again.
    private(set) var eraseFailed = false

    /// Reloaded whenever the data is erased: the lock goes with it.
    weak var lock: LockController?

    init(start: State) { state = start }

    /// The state at launch: the existing identity, else onboarding. A wipe
    /// cut short (app killed) finishes first, before the database opens.
    static func boot() -> AppRouter {
        // Still unfinished: the database stays closed, the erase screen shows.
        if let unfinished = afterResume({ try Wipe.resumeIfNeeded() }) { return AppRouter(start: unfinished) }
        #if BARKING_DEV
        let args = ProcessInfo.processInfo.arguments
        if args.contains("-BarkingUITestReset") {
            // A failure leaves the marker: creating an identity finishes it first.
            try? DeviceFactory.resetIdentity()
            for key in [OnboardingModel.confirmedKey, "barking.appearance"] {
                UserDefaults.standard.removeObject(forKey: key)
            }
        }
        if args.contains("-BarkingUITestNoAnimations") { UIView.setAnimationsEnabled(false) }
        do { try UITestSeed.apply(args) } catch { fatalError("UI test seed failed: \(error)") }
        if args.contains("-BarkingDevBench") {
            // Device measurement without a push (spec §7.4): key and open
            // only, before the app opens the database; read with devicectl.
            let (record, _, _) = BenchRun.run(source: "launch", sync: false)
            try? BenchStore.shared().append(record)
            SharedPaths.devExportBench()
        }
        let router = AppRouter(start: initialState(
            opening: { try DeviceFactory.openExisting(lockTimeoutMs: Budget.appLockMs) },
            runner: AppCallRunner()))
        // A card to add at launch: after the onboarding on a fresh install,
        // over the chats on a seeded one.
        if let i = args.firstIndex(of: "-BarkingUITestOpenCard"), i + 1 < args.count {
            router.pendingCardLink = args[i + 1]
        }
        return router
        #else
        return AppRouter(start: initialState(
            opening: { try DeviceFactory.openExisting(lockTimeoutMs: Budget.appLockMs) },
            runner: AppCallRunner()))
        #endif
    }

    /// No identity: onboarding; a pending link: the waiting screen; an error
    /// opening: a retry screen, never onboarding (spec, review I6).
    static func initialState(opening: () throws -> (any DeviceHandle)?, runner: any CallRunner) -> State {
        do {
            guard let device = try opening() else { return .onboarding }
            let core = CoreService.app(device, runner: runner)
            return (try? device.isPendingLink()) == true ? .linking(core) : .ready(core)
        } catch is KeyStore.Unavailable {
            return .unreadable
        } catch {
            return .failed
        }
    }

    /// Erases the data this iPhone can no longer read, then opens onboarding
    /// at `step` (link or recover). A wipe that fails stays on the screen:
    /// onboarding would offer a new identity the leftover marker could erase.
    func eraseUnreadable(then step: OnboardingModel.Step,
                         wipe: () throws -> Void = { try DeviceFactory.resetIdentity() }) {
        do {
            try wipe()
        } catch {
            eraseFailed = true
            return
        }
        eraseFailed = false
        lock?.reload()
        pendingOnboardingStep = step
        state = .onboarding
    }

    /// Before anything opens: a wipe cut short must finish. `.wipeFailed`
    /// if it still cannot (the erase screen, not "your data is safe"); `nil`
    /// to go on.
    static func afterResume(_ resume: () throws -> Bool) -> State? {
        (try? resume()) == nil ? .wipeFailed : nil
    }

    /// "Try again" on the erase screen: runs the wipe again; once it
    /// finishes, the welcome screen.
    func retryWipe(resume: () throws -> Bool = { try Wipe.resumeIfNeeded() }) {
        if let unfinished = Self.afterResume(resume) {
            state = unfinished
            return
        }
        restartOnboarding()
    }

    func takeOnboardingStep() -> OnboardingModel.Step? {
        defer { pendingOnboardingStep = nil }
        return pendingOnboardingStep
    }

    func retry() {
        if let unfinished = Self.afterResume({ try Wipe.resumeIfNeeded() }) {
            state = unfinished
            return
        }
        state = Self.initialState(
            opening: { try DeviceFactory.openExisting(lockTimeoutMs: Budget.appLockMs) },
            runner: AppCallRunner())
    }

    /// Back to the welcome screen after a wipe: the lock settings went with
    /// the rest, so the screens must not keep showing them.
    func restartOnboarding() {
        lock?.reload()
        state = .onboarding
    }

    /// The one erase: the core stops, the wipe runs, then the welcome
    /// screen. Throws if the wipe could not finish (the caller stays put).
    func eraseAndRestart(wipe: (CoreService?) async throws -> Void = { try await Wipe.run(closing: $0) }) async throws {
        try await wipe(core)
        restartOnboarding()
    }

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

    /// A tapped notification: its `contact` (and `message_id`, for a failure)
    /// say where to go. False when it names no contact.
    @discardableResult
    func open(notification userInfo: [AnyHashable: Any]) -> Bool {
        // Only an open identity has conversations: no stale target to fire later.
        guard case .ready = state else { return false }
        guard let contact = userInfo[FailureNotifier.contactKey] as? String, !contact.isEmpty else { return false }
        let id = (userInfo[FailureNotifier.messageIdKey] as? NSNumber)?.int64Value
        pendingOpen = OpenTarget(contact: contact, messageId: id)
        return true
    }

    func takePendingOpen() -> OpenTarget? {
        defer { pendingOpen = nil }
        return pendingOpen
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
