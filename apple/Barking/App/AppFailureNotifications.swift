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
    /// The app's `CoreService`: wired to post failure notices, given the nodes
    /// the app was built with, and the wake-up settings by the sync loop (`PushToken.apply`).
    /// In development builds a UI test may ask for the core seen through
    /// `UITestDeliveries` (forced delivery states, a fake received message).
    static func app(_ device: any DeviceHandle, runner: any CallRunner = AppCallRunner()) -> CoreService {
        #if BARKING_DEV
        let device = UITestDeliveries.wrap(device)
        #endif
        let core = CoreService(device: device, runner: runner, onFailed: AppFailureNotifications.handler)
        let info = Bundle.main.infoDictionary ?? [:]
        Task { await BootstrapNodes.add(to: core, info: info) }
        // The push guard is applied by `SyncLoop`, before the launch sync and
        // each resume sync: one ordered path.
        return core
    }
}
