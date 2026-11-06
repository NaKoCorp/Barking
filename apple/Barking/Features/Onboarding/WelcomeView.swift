import BarkingKit
import SwiftUI

/// Screen 1 of the mockup.
struct WelcomeView: View {
    let onCreate: () -> Void
    let onRecover: () -> Void
    let onLink: () -> Void

    var body: some View {
        ZStack {
            Color.surfaceWelcome.ignoresSafeArea()
            Galaxy().ignoresSafeArea()
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    MadeInFranceChip()
                    Spacer()
                    AppearanceIcons()
                }
                Spacer()
                VStack(alignment: .leading, spacing: 14) {
                    Eyebrow("welcome")
                    Text(verbatim: "Barking")
                        .font(BarkingFont.mono(.largeTitle, size: 44, weight: .semibold))
                        .tracking(-1.5)
                        .foregroundStyle(Color.fg)
                        .accessibilityAddTraits(.isHeader)
                    Text("Messages that get through. Even when the internet doesn't.")
                        .font(BarkingFont.sans(.title3, size: 17))
                        .foregroundStyle(Color.fgMuted)
                    VStack(alignment: .leading, spacing: 4) {
                        Check("No phone number")
                        Check("No central server")
                        Check("End-to-end encrypted, post-quantum")
                    }
                }
                VStack(spacing: 12) {
                    PrimaryButton("Create my identity", action: onCreate)
                    SecondaryButton("Recover with 24 words", action: onRecover)
                    Button(action: onLink) {
                        Text("Link to an existing device")
                            .font(BarkingFont.mono(.footnote, size: 13))
                            .foregroundStyle(Color.accent)
                            .frame(maxWidth: .infinity, minHeight: 44)
                    }
                    Text("by NakoCorp · AGPL-3.0")
                        .font(BarkingFont.mono(.caption2, size: 11))
                        .foregroundStyle(Color.fgMuted)
                        .frame(maxWidth: .infinity)
                }
                .padding(.top, 32)
            }
            .padding(.horizontal, 24)
            .padding(.top, 16)
            .padding(.bottom, 20)
        }
    }

    private struct Check: View {
        let text: LocalizedStringKey
        init(_ text: LocalizedStringKey) { self.text = text }
        var body: some View {
            HStack(spacing: 8) {
                // The system font: Fira Code draws ✓ like a √.
                Text(verbatim: "✓").font(.bSymbol(13, relativeTo: .footnote, weight: .bold))
                    .foregroundStyle(Color.ok).accessibilityHidden(true)
                Text(text).foregroundStyle(Color.fgMuted)
            }
            .font(BarkingFont.mono(.footnote, size: 12.5))
        }
    }
}
