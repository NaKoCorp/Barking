import BarkingKit
import SwiftUI

/// The full-screen cover (spec §6.1). Locked: the rooster, "Unlock" and a
/// discreet "Erase Barking" that needs no Face ID, so that it works under
/// duress without reading anything (§6.2). Not locked but not active (the
/// app switcher, a system sheet): the rooster alone.
struct LockView: View {
    @Environment(LockController.self) private var lock

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Rooster(size: 72)
                .accessibilityHidden(true)
            if lock.locked {
                ScreenTitle("Barking is locked", size: 22)
                PrimaryButton("Unlock") {
                    Task { if await Owner.check(reason: String(localized: "Unlock Barking")) { lock.unlock() } }
                }
                .padding(.horizontal, 24)
                .accessibilityIdentifier("lock.unlock")
            }
            Spacer()
            if lock.locked {
                EraseBarkingControl(identifier: "lock.erase")
                    .padding(.bottom, 24)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.surface.ignoresSafeArea())
    }
}
