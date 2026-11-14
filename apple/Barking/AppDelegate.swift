import BarkingKit
import UIKit
import UserNotifications

/// The APNs token: shown by the development screen, and given to the core
/// with the relay the app was built with, so that its syncs subscribe to
/// wake-ups.
@MainActor @Observable
final class PushToken {
    static let shared = PushToken()
    var token: Data?
    var hex: String?
    var failure: String?
    /// Where the relay is read from (tests give their own).
    @ObservationIgnored var info: [String: Any] = Bundle.main.infoDictionary ?? [:]
    /// Where the notification permission is read from (tests give their own).
    @ObservationIgnored var authorization: @Sendable () async -> UNAuthorizationStatus = {
        await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
    }
    /// The last permission read by `refreshStatus()`, which `apply(to:)` also
    /// calls (nil before the first).
    private(set) var status: UNAuthorizationStatus?

    /// Reads the notification permission and nothing else (no setting is
    /// written): what a read-only screen needs.
    func refreshStatus() async {
        status = await authorization()
    }

    /// Gives `core` the wake-up settings for the token, or push off when no
    /// relay was built in. Push is off, token or not, while iOS notifications
    /// are denied or not yet asked. Authorized but no token yet: the
    /// settings the core holds stay.
    func apply(to core: CoreService) async {
        await refreshStatus()
        guard let status else { return }
        guard PushRelay.allows(status) else {
            do { try await core.setPush(nil) } catch { failure = String(describing: error) }
            return
        }
        guard let token else { return }
        do {
            try await core.setPush(PushRelay.settings(info: info, token: token))
        } catch {
            failure = String(describing: error)
        }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    /// The service a background wake syncs: the app's, once its device is
    /// open (nil before). Tests give their own.
    var service: @MainActor () -> CoreService? = { AppRouter.current?.core }
    /// Where the APNs token goes (tests give their own).
    @MainActor var pushToken: PushToken { get { _pushToken ?? .shared } set { _pushToken = newValue } }
    @MainActor private var _pushToken: PushToken?

    /// A background push (`content-available`): the relay's receipt wake,
    /// sent when an ack for one of my messages reached a node, or when the
    /// message expired there unacked. Only a quick sync runs; the ack it
    /// fetches then takes the usual path. iOS hears whether anything came
    /// of it (`.failed` when no node answered or the sync failed).
    func application(_ application: UIApplication,
                     didReceiveRemoteNotification userInfo: [AnyHashable: Any],
                     fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        Task { @MainActor in
            completionHandler(await self.backgroundWake())
        }
    }

    @MainActor
    func backgroundWake() async -> UIBackgroundFetchResult {
        guard let core = service() else { return .noData }
        let outcome = await core.quickSync()
        await core.noteWake()
        guard outcome.networkUp else { return .failed }
        return outcome.changed ? .newData : .noData
    }

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        application.registerForRemoteNotifications()
        UNUserNotificationCenter.current().delegate = self
        BackgroundRefresh.register()
        return true
    }

    /// A tap on a notification: the failure notice names its contact and
    /// message; a new-message one only has its thread (the contact).
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            didReceive response: UNNotificationResponse) async {
        guard let target = Self.target(of: response.notification.request.content) else { return }
        await MainActor.run {
            var info: [AnyHashable: Any] = [FailureNotifier.contactKey: target.contact]
            if let id = target.messageId { info[FailureNotifier.messageIdKey] = id }
            AppRouter.current?.open(notification: info)
        }
    }

    /// Where a tapped notification leads: its `contact` (else its thread,
    /// which is the contact for a new message) and, for a failure, the message.
    nonisolated static func target(of content: UNNotificationContent) -> AppRouter.OpenTarget? {
        let contact = (content.userInfo[FailureNotifier.contactKey] as? String)
            ?? (content.threadIdentifier.isEmpty ? nil : content.threadIdentifier)
        guard let contact else { return nil }
        let id = (content.userInfo[FailureNotifier.messageIdKey] as? NSNumber)?.int64Value
        return AppRouter.OpenTarget(contact: contact, messageId: id)
    }

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        let push = pushToken
        push.token = deviceToken
        push.hex = hex
        if let core = service() {
            Task { await push.apply(to: core) }
        }
        #if BARKING_DEV
        // Scripted measurements read it from the shared container
        // (scripts/apns-send.sh needs it).
        SharedPaths.devExport("dev-apns-token.txt", hex)
        #endif
    }

    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        pushToken.failure = error.localizedDescription
    }
}
