import SwiftUI

@main
struct BarkingApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            #if BARKING_DEV
            DevView()
            #else
            Text("Barking")
            #endif
        }
    }
}
