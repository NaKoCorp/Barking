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
