import BarkingKit
import SwiftUI

/// The full-screen cover (spec §6.1). Locked: the samoyed with its padlock,
/// "Unlock" and a discreet "Erase Barking" that needs no Face ID, so that it
/// works under duress without reading anything (§6.2). Not locked but not
/// active (the app switcher, a system sheet): the samoyed alone.
struct LockView: View {
    @Environment(LockController.self) private var lock

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            LockedSamoyed()
            if lock.locked {
                ScreenTitle("Barking is locked", size: 22)
                PrimaryButton("Unlock") { Task { await lock.promptIfLocked() } }
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
        .task(id: lock.locked) {
            #if BARKING_DEV
            if ProcessInfo.processInfo.arguments.contains("-BarkingUITestNoAutoUnlock") { return }
            #endif
            await lock.promptIfLocked()
        }
    }
}

/// The app icon's samoyed in an accent disc, with a padlock badge.
private struct LockedSamoyed: View {
    var body: some View {
        // The head's flat base sits on the bottom of the disc, as on the icon.
        ZStack(alignment: .bottom) {
            Circle().fill(Color.accentFill)
            Image("Samoyed")
                .resizable()
                .renderingMode(.template)
                .scaledToFit()
                .foregroundStyle(.white)
                .frame(width: 84)
                .offset(y: 11)
        }
        .frame(width: 96, height: 96)
        .clipShape(.circle)
            .overlay(alignment: .bottomLeading) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Color.accentFill)
                    .frame(width: 34, height: 34)
                    .background(Color.surface, in: .circle)
                    .overlay(Circle().stroke(Color.accentFill, lineWidth: 2))
                    .offset(x: -4, y: 4)
            }
            .accessibilityHidden(true)
    }
}
