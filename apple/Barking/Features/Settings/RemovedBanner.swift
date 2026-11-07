import BarkingKit
import SwiftUI

/// This device was removed from the account by a newer device list (a
/// recovery from the 24 words elsewhere): it can still read, not send.
/// "Reset this device" erases it and goes back to the welcome screen.
struct RemovedBanner: View {
    let core: CoreService
    @Environment(AppRouter.self) private var router
    @State private var removed = false
    @State private var confirming = false
    @State private var wipeFailed = false

    var body: some View {
        Group {
            if removed {
                VStack(alignment: .leading, spacing: 8) {
                    Banner(kind: .danger, title: "This device was removed from your account",
                           message: "It can still read, but no longer send. Reset it, then link it again from your administrator device.")
                    if wipeFailed {
                        Banner(kind: .danger, title: "Barking could not erase everything. Try again.")
                    }
                    // Outlined in `danger`, never system red (U-2); the first tap asks.
                    DangerButton(wipeFailed ? "Try again" : "Reset this device") {
                        if wipeFailed { Task { await reset() } } else { confirming = true }
                    }
                }
                .confirmationDialog("Reset this device", isPresented: $confirming, titleVisibility: .visible) {
                    Button("Reset this device", role: .destructive) { Task { await reset() } }
                } message: {
                    Text("Its chats and history will be erased.")
                }
            }
        }
        .task {
            await load()
            for await _ in await core.changes { await load() }
        }
    }

    private func load() async { removed = ((try? await core.removed()) ?? nil) != nil }

    /// The core stops first: no sync may write to the files being erased.
    /// A wipe that still fails stays here: the welcome screen would offer a
    /// new identity the leftover marker could erase.
    private func reset() async {
        do {
            try await router.eraseAndRestart()
        } catch {
            wipeFailed = true
        }
    }
}
