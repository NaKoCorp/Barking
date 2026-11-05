import SwiftUI

@main
struct BarkingApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var router = AppRouter.boot()
    @State private var settings = AppSettings()
    @State private var lock = LockController()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(router)
                .environment(settings)
                .environment(lock)
                .preferredColorScheme(settings.colorScheme)
                .onOpenURL { router.open(url: $0) }
        }
    }
}
