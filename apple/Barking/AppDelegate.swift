import BarkingKit
import UIKit

/// The APNs token, shown by the development screen (the subscriptions of
/// block 3 will use it).
@MainActor @Observable
final class PushToken {
    static let shared = PushToken()
    var hex: String?
    var failure: String?
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    /// The service a background wake syncs: the app's, once its device is
    /// open (nil before). Tests give their own.
    var service: @MainActor () -> CoreService? = { AppRouter.current?.core }

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
        guard outcome.networkUp else { return .failed }
        return outcome.changed ? .newData : .noData
    }

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        application.registerForRemoteNotifications()
        return true
    }

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        PushToken.shared.hex = hex
        #if BARKING_DEV
        // Scripted measurements read it from the shared container
        // (scripts/apns-send.sh needs it).
        SharedPaths.devExport("dev-apns-token.txt", hex)
        #endif
    }

    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        PushToken.shared.failure = error.localizedDescription
    }
}
