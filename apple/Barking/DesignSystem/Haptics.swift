import SwiftUI
import UIKit

/// The haptic map (UI review U-25): one feedback per kind of moment.
/// - `success`: identity created, quiz passed, contact added, numbers match.
/// - `error`: quiz wrong, PDF password refused.
/// - `send`: a message leaves the composer.
/// - `holdCompleted`: a hold-to-confirm reached its end.
enum Haptic: CaseIterable {
    case success, error, send, holdCompleted

    /// For `.sensoryFeedback`, where a state of the view drives it.
    var feedback: SensoryFeedback {
        switch self {
        case .success: .success
        case .error: .error
        case .send: .impact(weight: .light)
        case .holdCompleted: .warning
        }
    }

    /// Plays it now: for a moment that ends an async call, or one after
    /// which the view leaves the screen (its own `.sensoryFeedback` would go
    /// with it). Same map as `feedback`.
    @MainActor func play() {
        switch self {
        case .success: UINotificationFeedbackGenerator().notificationOccurred(.success)
        case .error: UINotificationFeedbackGenerator().notificationOccurred(.error)
        case .send: UIImpactFeedbackGenerator(style: .light).impactOccurred()
        case .holdCompleted: UINotificationFeedbackGenerator().notificationOccurred(.warning)
        }
    }
}
