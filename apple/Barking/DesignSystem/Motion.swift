import SwiftUI

/// The two animations of the app (UI review U-40). Callers read
/// `accessibilityReduceMotion` and pass it to `gated`, which drops the
/// animation when Reduce Motion is on: the change then happens at once.
enum Motion {
    /// A state answering a touch: a check appearing, a line of feedback.
    static let feedback: Animation = .easeOut(duration: 0.18)
    /// Something entering the screen: a banner, a result line.
    static let enter: Animation = .spring(response: 0.35, dampingFraction: 0.9)

    static func gated(_ animation: Animation, reduceMotion: Bool) -> Animation? {
        reduceMotion ? nil : animation
    }
}

extension View {
    /// `animation(_:value:)` that honours Reduce Motion.
    func barkingAnimation<V: Equatable>(_ animation: Animation, value: V) -> some View {
        modifier(GatedAnimation(animation: animation, value: value))
    }
}

private struct GatedAnimation<V: Equatable>: ViewModifier {
    let animation: Animation
    let value: V
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content.animation(Motion.gated(animation, reduceMotion: reduceMotion), value: value)
    }
}
