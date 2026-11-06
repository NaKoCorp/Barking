import BarkingKit
import SwiftUI

/// Screen 1 of the mockup. The galaxy lives in the gap between the header
/// and the text, never over them (UI review B5, U-32). When the text is too
/// tall for the screen (accessibility sizes, French), the screen scrolls
/// instead of truncating.
struct WelcomeView: View {
    let onCreate: () -> Void
    let onRecover: () -> Void
    let onLink: () -> Void

    /// The galaxy's band, in the content's coordinates.
    @State private var bandTop: CGFloat = 0
    @State private var bandBottom: CGFloat = 0

    var body: some View {
        ViewThatFits(in: .vertical) {
            content
            ScrollView { content }.scrollBounceBehavior(.basedOnSize)
        }
        .background(Color.surfaceWelcome.ignoresSafeArea())
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                MadeInFranceChip()
                Spacer()
                AppearanceIcons()
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("welcome.header")
            .onGeometryChange(for: CGFloat.self) { $0.frame(in: .named(Self.space)).maxY } action: { bandTop = $0 }
            Spacer(minLength: Space.danger)
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
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("welcome.text")
            .onGeometryChange(for: CGFloat.self) { $0.frame(in: .named(Self.space)).minY } action: { bandBottom = $0 }
            VStack(spacing: 12) {
                PrimaryButton("Create my identity", action: onCreate)
                SecondaryButton("Recover with 24 words", action: onRecover)
                Button(action: onLink) {
                    Text("Link to an existing device")
                        .font(BarkingFont.mono(.footnote, size: 13))
                        .foregroundStyle(Color.accent)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity, minHeight: 44)
                }
                Text("by NakoCorp · AGPL-3.0")
                    .font(BarkingFont.mono(.caption2, size: 11))
                    .foregroundStyle(Color.fgMuted)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
            }
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 32)
        }
        .padding(.horizontal, 24)
        .padding(.top, 16)
        .padding(.bottom, 20)
        .background { Galaxy(top: bandTop, bottom: bandBottom) }
        .coordinateSpace(.named(Self.space))
    }

    private static let space = "welcome"

    private struct Check: View {
        let text: LocalizedStringKey
        init(_ text: LocalizedStringKey) { self.text = text }
        var body: some View {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                // The system font: Fira Code draws ✓ like a √.
                Text(verbatim: "✓").font(.bSymbol(13, relativeTo: .footnote, weight: .bold))
                    .foregroundStyle(Color.ok).accessibilityHidden(true)
                Text(text).foregroundStyle(Color.fgMuted)
            }
            .font(BarkingFont.mono(.footnote, size: 12.5))
        }
    }
}
