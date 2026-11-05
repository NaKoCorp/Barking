import BarkingKit
import SwiftUI
import UserNotifications

/// Onboarding navigation: welcome, then create (names, phrase, confirmation),
/// recover, or link (Task 11).
struct OnboardingFlow: View {
    @Environment(AppRouter.self) private var router
    @State private var model = OnboardingModel(identityExists: { false })
    @State private var created: CoreService?

    var body: some View {
        NavigationStack(path: $model.path) {
            WelcomeView(onCreate: { model.path.append(.create) },
                        onRecover: { model.path.append(.recover) },
                        onLink: { model.path.append(.link) })
                .toolbar(.hidden, for: .navigationBar)
                .navigationDestination(for: OnboardingModel.Step.self) { step in
                    switch step {
                    case .create:
                        CreateIdentityView(model: model) { model.path.append(.phrase) }
                    case .phrase:
                        PhraseView(model: model) { model.path.append(.confirm) }
                    case .confirm:
                        PhraseConfirmView(model: model) { finish() }
                    case .recover:
                        RecoverView(model: model) { core in ready(core) }
                    case .link:
                        LinkFromExistingView()
                    }
                }
        }
        .task { model = OnboardingModel(identityExists: { DeviceFactory.hasIdentity }) }
        .onChange(of: model.phrase) { _, _ in }
    }

    private func finish() {
        Task {
            if let core = await coreAfterCreate() { ready(core) }
        }
    }

    private func coreAfterCreate() async -> CoreService? {
        if let created { return created }
        return try? DeviceFactory.openExisting(lockTimeoutMs: Budget.appLockMs)
            .map { CoreService(device: $0, runner: AppCallRunner()) }
    }

    private func ready(_ core: CoreService) {
        PhraseMemory.shared.phrase = model.phrase
        router.becomeReady(core: core)
        Task { _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) }
    }
}

/// The phrase kept in memory after onboarding, for a later confirmation
/// (spec §5.2): gone when the app quits.
@MainActor
final class PhraseMemory {
    static let shared = PhraseMemory()
    var phrase: [String]?
}
