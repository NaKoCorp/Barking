import BarkingKit
import SwiftUI

/// Settings › Security: the app lock and the emergency erase (spec §6).
struct SecuritySettingsView: View {
    @Environment(LockController.self) private var lock
    @State private var refused = false
    /// Bumped after a refused change so the switch is drawn again from the
    /// controller's value (it stays where it was).
    @State private var redraw = 0
    @Environment(\.dynamicTypeSize) private var size

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
        Group {
            VStack(alignment: .leading, spacing: Space.s2) {
                FormCard {
                    Toggle(isOn: Binding(
                        get: { _ = redraw; return lock.enabled },
                        set: { on in
                            Task {
                                refused = await lock.setEnabled(on) == .noPasscode
                                redraw += 1
                            }
                        })) {
                        Text("Lock Barking").font(.bBody.weight(.semibold)).foregroundStyle(Color.fg)
                    }
                    .tint(Color.toggleOn)
                    .padding(.horizontal, FormRowMetrics.inset)
                    .frame(minHeight: FormRowMetrics.minHeight(hasSubtitle: false))
                    .accessibilityIdentifier("security.lock")
                    if lock.enabled {
                        // A menu row: never truncates "Immediately", in French or at AX sizes (U-9).
                        // At AX sizes the menu goes under its label, so neither truncates.
                        let layout = size.isAccessibilitySize
                            ? AnyLayout(VStackLayout(alignment: .leading, spacing: Space.s1))
                            : AnyLayout(HStackLayout(spacing: Space.s3))
                        layout {
                            Text("Lock after").font(.bBody.weight(.semibold)).foregroundStyle(Color.fg)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                // The menu says it: "Lock after, Immediately".
                                .accessibilityHidden(true)
                            // A menu with its own label: the system menu picker's label
                            // hyphenated and clipped "Immédiatement" at AX sizes.
                            Menu {
                                Picker(selection: $lock.delay) {
                                    ForEach(AppLock.delays, id: \.self) { Text(Self.title($0)).tag($0) }
                                } label: { Text("Lock after") }
                            } label: {
                                HStack(spacing: Space.s1) {
                                    Text(Self.title(lock.delay)).font(.bBody)
                                        .fixedSize(horizontal: false, vertical: true)
                                    Image(systemName: "chevron.up.chevron.down")
                                        .font(.bSymbol(12, relativeTo: .footnote, weight: .semibold, maximum: 20))
                                }
                                .foregroundStyle(Color.accent)
                                .frame(minHeight: 44)
                                .contentShape(.rect)
                            }
                            .accessibilityLabel(Text("Lock after"))
                            .accessibilityValue(Text(Self.title(lock.delay)))
                            .accessibilityIdentifier("security.delay")
                        }
                        .padding(.horizontal, FormRowMetrics.inset)
                        .padding(.vertical, size.isAccessibilitySize ? Space.s2 : 0)
                        .frame(minHeight: FormRowMetrics.minHeight(hasSubtitle: false))
                    }
                }
                if refused {
                    Banner(kind: .danger, title: "Set a passcode on the iPhone first")
                }
                Text("Face ID, Touch ID or the iPhone's passcode opens it. Messages keep arriving; while it is locked, notifications only say “New message”.")
                    .font(BarkingFont.sans(.footnote, size: 13)).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // On no card, 32 pt below the lock (U-2).
            DangerZone("Erase Barking") {
                Text("Everything on this iPhone will be erased. Your contacts will not be told. To get your identity back, you will need the 24-word phrase.")
                    .font(.bBody).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.bottom, Space.s1)
                EraseBarkingControl(identifier: "security.erase")
            }
        }
        .barkingScreen()
        .navigationTitle(Text("Security"))
    }
}

/// "Erase Barking": a tap does nothing, a 2 s hold then a destructive
/// confirmation does (spec §6.2, UI review U-8); VoiceOver opens the same
/// confirmation with a double-tap. No Face ID: the same control serves the
/// lock screen. A wipe that fails stays here, never on the welcome screen.
struct EraseBarkingControl: View {
    let identifier: String
    @Environment(AppRouter.self) private var router
    @State private var confirming = false
    @State private var failed = false
    @State private var erasing = false

    var body: some View {
        VStack(spacing: Space.s2) {
            if failed {
                Banner(kind: .danger, title: "Barking could not erase everything. Try again.")
            }
            HoldToConfirmButton("Erase Barking", hint: "Press and hold for 2 seconds",
                                identifier: identifier) { confirming = true }
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
