import BarkingKit
import SwiftUI

/// Settings › Security: the app lock and the emergency erase (spec §6).
struct SecuritySettingsView: View {
    @Environment(LockController.self) private var lock
    @State private var refused = false

    private static func title(_ delay: TimeInterval) -> LocalizedStringKey {
        switch delay {
        case 0: "Immediately"
        case 60: "1 min"
        case 300: "5 min"
        default: "1 h"
        }
    }

    var body: some View {
        @Bindable var lock = lock
        List {
            Section {
                Toggle("Lock Barking", isOn: Binding(
                    get: { lock.enabled },
                    set: { refused = !lock.setEnabled($0) }))
                    .accessibilityIdentifier("security.lock")
                if refused {
                    Banner(kind: .danger, title: "Set a passcode on the iPhone first")
                }
                if lock.enabled {
                    Picker("Lock after", selection: $lock.delay) {
                        ForEach(AppLock.delays, id: \.self) { Text(Self.title($0)).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("security.delay")
                }
            } footer: {
                Text("Face ID, Touch ID or the iPhone's passcode opens it. Messages keep arriving; while it is locked, notifications only say “New message”.")
            }
            Section("Erase Barking") {
                Text("Everything on this iPhone will be erased. Your contacts will not be told. To get your identity back, you will need the 24-word phrase.")
                    .foregroundStyle(Color.fgMuted)
                EraseBarkingControl(identifier: "security.erase")
                    .frame(maxWidth: .infinity)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color.surface)
        .navigationTitle(Text("Security"))
    }
}

/// "Erase Barking": a tap does nothing, a 2 s press then a destructive
/// confirmation does (spec §6.2). No Face ID: the same control serves the lock
/// screen. A wipe that fails stays here, never on the welcome screen.
struct EraseBarkingControl: View {
    let identifier: String
    @Environment(AppRouter.self) private var router
    @State private var confirming = false
    @State private var failed = false
    @State private var erasing = false

    var body: some View {
        VStack(spacing: 6) {
            if failed {
                Banner(kind: .danger, title: "Barking could not erase everything. Try again.")
            }
            Text("Erase Barking")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(Color.red)
                .frame(minHeight: 44)
                .padding(.horizontal, 16)
                .contentShape(.rect)
                .onLongPressGesture(minimumDuration: 2) { confirming = true }
                .accessibilityAddTraits(.isButton)
                .accessibilityHint(Text("Press and hold for 2 seconds"))
                .accessibilityIdentifier(identifier)
            Text("Press and hold for 2 seconds")
                .font(.caption2).foregroundStyle(Color.fgSoft)
                .accessibilityHidden(true)
        }
        .disabled(erasing)
        .confirmationDialog("Erase", isPresented: $confirming, titleVisibility: .visible) {
            Button("Erase", role: .destructive) { Task { await erase() } }
        } message: {
            Text("Everything on this iPhone will be erased. Your contacts will not be told. To get your identity back, you will need the 24-word phrase.")
        }
    }

    private func erase() async {
        erasing = true
        defer { erasing = false }
        do {
            try await router.eraseAndRestart()
            failed = false
        } catch {
            failed = true
        }
    }
}
