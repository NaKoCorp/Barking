import BarkingKit
import UIKit

/// What a sync does with the messages it found not delivered: a local
/// notification, unless the app is in front.
enum AppFailureNotifications {
    static let handler: @Sendable ([DeliveryChange]) async -> Void = { notices in
        let active = await MainActor.run { UIApplication.shared.applicationState == .active }
        await FailureNotifier().post(notices, appActive: active)
    }
}
