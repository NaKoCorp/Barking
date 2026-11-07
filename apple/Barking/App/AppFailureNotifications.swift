import BarkingKit
import UIKit

/// What a sync does with the messages it found not delivered: a local
/// notification, unless the app is in front.
///
/// An `.inactive` app (a call, the app switcher, a transition) counts as not
/// active: the notice is posted. That is safe: a notification arriving while
/// the app is still on screen is shown as a banner at worst, and it never
/// carries a name or content.
enum AppFailureNotifications {
    static let handler: @Sendable ([DeliveryChange]) async -> Void = { notices in
        let active = await MainActor.run { UIApplication.shared.applicationState == .active }
        await FailureNotifier().post(notices, appActive: active)
    }
}

extension CoreService {
    /// The app's `CoreService`: wired to post failure notices.
    static func app(_ device: any DeviceHandle, runner: any CallRunner = AppCallRunner()) -> CoreService {
        CoreService(device: device, runner: runner, onFailed: AppFailureNotifications.handler)
    }
}
