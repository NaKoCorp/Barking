import BarkingKit
import SwiftUI

/// Onboarding until the identity exists, then the tabs.
struct RootView: View {
    @Environment(AppRouter.self) private var router

    var body: some View {
        switch router.state {
        case .onboarding: OnboardingFlow()
        case .ready(let core): MainTabView(core: core)
        }
    }
}

/// Chats, Network, Settings (screens 3, 7, 8). Filled by Tasks 8 to 11.
struct MainTabView: View {
    let core: CoreService

    var body: some View {
        TabView {
            Tab("Chats", systemImage: "bubble.left.and.bubble.right") { ChatsView(core: core) }
            Tab("Network", systemImage: "point.3.connected.trianglepath.dotted") { Text("Network") }
            Tab("Settings", systemImage: "gearshape") {
                #if BARKING_DEV
                DevView()
                #else
                Text("Settings")
                #endif
            }
        }
        .tint(Color.accent)
    }
}
