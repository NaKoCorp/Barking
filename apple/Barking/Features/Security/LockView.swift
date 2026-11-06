import BarkingKit
import SwiftUI

/// The full-screen cover (spec §6.1). Locked: the samoyed tile with its padlock,
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
                    .multilineTextAlignment(.center)
                PrimaryButton("Unlock") { Task { await lock.promptIfLocked() } }
                .padding(.horizontal, 24)
                .accessibilityIdentifier("lock.unlock")
            }
            Spacer()
            if lock.locked {
                EraseBarkingControl(identifier: "lock.erase")
                    .padding(.horizontal, 24)
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

enum LockTileMetrics {
    static let size: CGFloat = 96
    static let radius: CGFloat = Radius.card
    /// How far the 40 pt padlock badge passes the tile's corner.
    static let badgeOverhang: CGFloat = 14
}

/// The app icon's samoyed, white, in a 96 pt tile with the logo tile's 145°
/// gradient (UI review U-37), and the padlock badge on the tile's
/// bottom-leading corner (kept: the user asked for a samoyed with a padlock).
private struct LockedSamoyed: View {
    var body: some View {
        let tile = RoundedRectangle(cornerRadius: LockTileMetrics.radius)
        // The head's flat base sits on the bottom of the tile, as on the icon.
        ZStack(alignment: .bottom) {
            // 145°: from the top-leading third to the bottom-trailing one.
            tile.fill(LinearGradient(colors: [.logoTileTop, .logoTileBottom],
                                     startPoint: UnitPoint(x: 0.21, y: 0.09), endPoint: UnitPoint(x: 0.79, y: 0.91)))
            Image("Samoyed")
                .resizable()
                .renderingMode(.template)
                .scaledToFit()
                .foregroundStyle(.white)
                .frame(width: 84)
                .offset(y: 11)
        }
        .frame(width: LockTileMetrics.size, height: LockTileMetrics.size)
        .clipShape(tile)
        .overlay(alignment: .bottomLeading) {
            Image(systemName: "lock.fill")
                .font(.bSymbol(15, weight: .semibold, maximum: 20)) // in a 34 pt badge
                .foregroundStyle(Color.accentFill)
                .frame(width: 34, height: 34)
                .background(Color.surface, in: .circle)
                .overlay(Circle().stroke(Color.accentFill, lineWidth: 2))
                // A ring of the ground parts the badge from the tile.
                .padding(3)
                .background(Color.surface, in: .circle)
                // Over the tile's rounded corner, a little outside it.
                .offset(x: -LockTileMetrics.badgeOverhang, y: LockTileMetrics.badgeOverhang)
        }
        // Room for the overhang, on both sides so the tile stays centred.
        .padding(.horizontal, LockTileMetrics.badgeOverhang)
        .padding(.bottom, LockTileMetrics.badgeOverhang)
        .accessibilityHidden(true)
    }
}
