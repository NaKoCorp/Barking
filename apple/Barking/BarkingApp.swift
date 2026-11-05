import SwiftUI

@main
struct BarkingApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var router = AppRouter.boot()
    @State private var settings = AppSettings()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(router)
                .environment(settings)
                .environment(\.locale, settings.locale)
                .preferredColorScheme(settings.colorScheme)
                .onOpenURL { router.open(url: $0) }
        }
    }
}
