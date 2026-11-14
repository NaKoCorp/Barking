import BarkingKit
import SwiftUI
import UserNotifications

/// Onboarding navigation: welcome, then create (names, phrase, confirmation),
/// recover, or link (Task 11).
struct OnboardingFlow: View {
    @Environment(AppRouter.self) private var router
    @State private var model = OnboardingModel()

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
        // Unreadable data was erased to link or recover (spec §7.2).
        .onAppear { if let step = router.takeOnboardingStep() { model.path = [step] } }
    }

    private func finish() {
        if let core = model.createdCore { ready(core) }
    }

    private func ready(_ core: CoreService) {
        PhraseMemory.shared.phrase = model.phrase
        router.becomeReady(core: core)
        Task { await Self.askForNotifications(core: core) }
    }

    /// Asks iOS for the notification permission, then applies the push guard
    /// to `core`: it was created while the status was still undetermined, so
    /// it holds push off, and no foreground transition follows the alert.
    static func askForNotifications(
        core: CoreService, push: PushToken = .shared,
        request: @Sendable () async -> Void = {
            _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound])
        }
    ) async {
        await request()
        await push.apply(to: core)
    }
}

/// The phrase kept in memory after onboarding, for a later confirmation
/// (spec §5.2): gone when the app quits.
@MainActor
final class PhraseMemory {
    static let shared = PhraseMemory()
    var phrase: [String]?
}
