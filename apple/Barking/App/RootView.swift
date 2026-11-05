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
        case .unreadable: UnreadableDataView()
        }
    }
}

/// Chats, Network, Settings (screens 3, 7, 8). Filled by Tasks 8 to 11.
struct MainTabView: View {
    enum Tabs { case chats, network, settings }
    let core: CoreService
    @State private var tab = Tabs.chats

    var body: some View {
        TabView(selection: $tab) {
            Tab("Chats", systemImage: "bubble.left.and.bubble.right", value: .chats) { ChatsView(core: core) }
            Tab("Network", systemImage: "point.3.connected.trianglepath.dotted", value: .network) { NetworkView(core: core) }
            Tab("Settings", systemImage: "gearshape", value: .settings) {
                SettingsView(core: core) { tab = .network }
            }
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

/// The database key no longer unwraps on this iPhone (spec §7.2): link it
/// or recover with the phrase, each after erasing what it cannot read.
struct UnreadableDataView: View {
    static let explanation = "This iPhone can no longer read your data, for example after restoring a backup from another iPhone."
    static let warning = "The unreadable data on this iPhone will be erased."

    @Environment(AppRouter.self) private var router
    @State private var next: OnboardingModel.Step?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            ScreenTitle("Barking could not open your data", size: 22)
            Text(LocalizedStringKey(Self.explanation)).foregroundStyle(Color.fgMuted)
            if router.eraseFailed {
                Banner(kind: .danger, title: "Barking could not erase everything. Try again.")
            }
            PrimaryButton("Link to an existing device") { next = .link }
            SecondaryButton("Recover with 24 words") { next = .recover }
        }
        .padding(24)
        .frame(maxHeight: .infinity)
        .background(Color.surface)
        .confirmationDialog("Erase and continue", isPresented: Binding(get: { next != nil }, set: { if !$0 { next = nil } }),
                            titleVisibility: .visible) {
            Button("Erase and continue", role: .destructive) {
                if let step = next { router.eraseUnreadable(then: step) }
                next = nil
            }
        } message: {
            Text(LocalizedStringKey(Self.warning))
        }
    }
}
