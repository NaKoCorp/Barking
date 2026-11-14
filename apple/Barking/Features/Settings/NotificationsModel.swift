import BarkingKit
import Foundation
import Observation
import UserNotifications

/// What Settings › Notifications can offer, in priority order: no relay in
/// this build, permission not asked, permission denied, else the switch.
enum NotificationsState: Equatable {
    case on, off, notAsked, denied, noRelay
}

/// Settings › Notifications: instant wake-ups and the preview mode.
@MainActor @Observable
final class NotificationsModel {
    private let core: CoreService
    private let push: PushToken
    private let lock: AppLock
    private let request: (@Sendable () async -> Void)?

    private(set) var instant = true
    private(set) var preview: PushPreview = .nameAndText
    private(set) var appLocked = false
    /// The full sync a change of the switch started (tests await it).
    @ObservationIgnored private(set) var lastSync: Task<SyncOutcome, Never>?

    /// `request`: the iOS permission prompt (tests give their own).
    init(core: CoreService, push: PushToken = .shared, lock: AppLock = .live,
         request: (@Sendable () async -> Void)? = nil) {
        self.core = core
        self.push = push
        self.lock = lock
        self.request = request
    }

    var state: NotificationsState {
        let host = (push.info["BarkingRelayHost"] as? String) ?? ""
        if host.isEmpty { return .noRelay }
        switch push.status {
        case nil, .notDetermined?: return .notAsked
        case .denied?: return .denied
        default: return instant ? .on : .off
        }
    }

    func load() async {
        // Reads the permission (it may have changed in the iPhone's Settings).
        await push.apply(to: core)
        appLocked = lock.enabled
        await readPrefs()
    }

    func setInstant(_ on: Bool) async {
        instant = on
        try? await core.setInstant(on)
        await readPrefs()
        // The sync follows at once, without making the screen wait.
        lastSync = Task { [core] in await core.sync(reason: .foreground) }
    }

    func setPreview(_ p: PushPreview) async {
        preview = p
        try? await core.setPreview(p)
        await readPrefs()
    }

    /// Shows the iOS prompt, applies the push guard, then reads the state.
    func requestPermission() async {
        if let request {
            await OnboardingFlow.askForNotifications(core: core, push: push, request: request)
        } else {
            await OnboardingFlow.askForNotifications(core: core, push: push)
        }
        await load()
    }

    private func readPrefs() async {
        guard let prefs = try? await core.notificationPrefs() else { return }
        instant = prefs.instant
        preview = prefs.preview
    }
}
