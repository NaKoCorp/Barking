import SwiftUI

@main
struct BarkingApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var router: AppRouter
    @State private var settings = AppSettings()
    @State private var lock = LockController()

    init() {
        BarkingNavigationAppearance.apply()
        // Built here, not lazily by the view: a background wake launches
        // the app without showing it, and its delegate needs the router.
        let router = AppRouter.boot()
        AppRouter.current = router
        _router = State(initialValue: router)
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(router)
                .environment(settings)
                .environment(lock)
                // At the root, so onboarding, sheets, alerts and dialogs
                // inherit it, not only the tabs.
                .tint(Color.accent)
                .preferredColorScheme(settings.colorScheme)
                .onOpenURL { router.open(url: $0) }
                // UI tests: nothing animates (`-BarkingUITestNoAnimations`).
                .transaction { if UITestFlags.noAnimations { $0.disablesAnimations = true } }
        }
    }
}
