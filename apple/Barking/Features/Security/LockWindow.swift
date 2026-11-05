import SwiftUI
import UIKit

/// Hosts `LockView` in a window above every other one, so that sheets,
/// alerts and the keyboard cannot show through it, or be used, while the app
/// is covered (spec §6.1), and so that the app switcher snapshots the cover.
@MainActor
final class LockWindow {
    static let shared = LockWindow()

    private var window: UIWindow?
    private var tracking = false

    func install(lock: LockController, router: AppRouter) {
        guard window == nil,
              let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first
        else { return }
        let window = UIWindow(windowScene: scene)
        window.windowLevel = UIWindow.Level(UIWindow.Level.alert.rawValue + 100)
        window.rootViewController = UIHostingController(
            rootView: LockView().environment(lock).environment(router))
        window.rootViewController?.view.backgroundColor = .clear
        self.window = window
        track(lock)
    }

    /// Follows `LockController.covered`.
    private func track(_ lock: LockController) {
        let covered = withObservationTracking { lock.covered } onChange: { [weak self] in
            Task { @MainActor in self?.track(lock) }
        }
        show(covered)
    }

    private func show(_ covered: Bool) {
        guard let window, window.isHidden == covered else { return }
        if covered {
            // The keyboard of a text field below would stay up.
            UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
            window.isHidden = false
            window.makeKey()
        } else {
            window.isHidden = true
            window.windowScene?.windows.first { $0 !== window && !$0.isHidden }?.makeKey()
        }
    }
}
