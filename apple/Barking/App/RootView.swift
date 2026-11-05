import BarkingKit
import SwiftUI

/// Onboarding until the identity exists, then the tabs.
struct RootView: View {
    @Environment(AppRouter.self) private var router

    var body: some View {
        switch router.state {
        case .onboarding: OnboardingFlow()
        case .ready(let core): MainTabView(core: core)
        case .linking(let core): NavigationStack { LinkFromExistingView(resume: core) }
        case .failed: OpenFailedView()
        }
    }
}

/// Chats, Network, Settings (screens 3, 7, 8). Filled by Tasks 8 to 11.
struct MainTabView: View {
    let core: CoreService

    var body: some View {
        TabView {
            Tab("Chats", systemImage: "bubble.left.and.bubble.right") { ChatsView(core: core) }
            Tab("Network", systemImage: "point.3.connected.trianglepath.dotted") { NetworkView(core: core) }
            Tab("Settings", systemImage: "gearshape") { SettingsView(core: core) }
        }
        .tint(Color.accent)
    }
}

/// The identity could not be opened: retry, never onboarding over it.
struct OpenFailedView: View {
    @Environment(AppRouter.self) private var router

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            ScreenTitle("Barking could not open your data", size: 22)
            Text("Your data is safe. Unlock the phone and try again.").foregroundStyle(Color.fgMuted)
            PrimaryButton("Try again") { router.retry() }
        }
        .padding(24)
        .frame(maxHeight: .infinity)
        .background(Color.surface)
    }
}
