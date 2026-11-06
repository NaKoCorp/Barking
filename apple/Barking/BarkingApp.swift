import SwiftUI

@main
struct BarkingApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var router = AppRouter.boot()
    @State private var settings = AppSettings()
    @State private var lock = LockController()

    init() {
        BarkingNavigationAppearance.apply()
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
        }
    }
}
