import BarkingKit
import SwiftUI

/// Screen 1 of the mockup.
struct WelcomeView: View {
    @Environment(AppSettings.self) private var settings
    let onCreate: () -> Void
    let onRecover: () -> Void
    let onLink: () -> Void

    var body: some View {
        ZStack {
            Color.surfaceWelcome.ignoresSafeArea()
            Rings().accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 20) {
                HStack {
                    Text("Made in France")
                        .font(BarkingFont.mono(.caption, size: 12))
                        .foregroundStyle(Color.fgMuted)
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .overlay(Capsule().stroke(Color.border, lineWidth: 1))
                    Spacer()
                    LanguageToggle()
                }
                Spacer()
                Eyebrow("welcome")
                Text(verbatim: "Barking")
                    .font(BarkingFont.mono(.largeTitle, size: 44, weight: .semibold))
                    .tracking(-1.5)
                    .foregroundStyle(Color.fg)
                    .accessibilityAddTraits(.isHeader)
                Text("Messages that get through. Even when the internet doesn't.")
                    .font(BarkingFont.sans(.title3, size: 17))
                    .foregroundStyle(Color.fgMuted)
                VStack(alignment: .leading, spacing: 8) {
                    Check("No phone number")
                    Check("No central server")
                    Check("End-to-end encrypted, post-quantum")
                }
                Spacer()
                PrimaryButton("Create my identity", action: onCreate)
                SecondaryButton("Recover with 24 words", action: onRecover)
                Button(action: onLink) {
                    Text("Link to an existing device")
                        .font(BarkingFont.mono(.body, size: 14))
                        .foregroundStyle(Color.accent)
                        .frame(maxWidth: .infinity, minHeight: 44)
                }
                Text("by NakoCorp · AGPL-3.0")
                    .font(BarkingFont.mono(.caption2, size: 11))
                    .foregroundStyle(Color.fgSoft)
                    .frame(maxWidth: .infinity)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 16)
        }
    }

    private struct Check: View {
        let text: LocalizedStringKey
        init(_ text: LocalizedStringKey) { self.text = text }
        var body: some View {
            HStack(spacing: 8) {
                // The system font: Fira Code draws ✓ like a √.
                Text(verbatim: "✓").font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Color.ok).accessibilityHidden(true)
                Text(text).foregroundStyle(Color.fg)
            }
            .font(BarkingFont.mono(.footnote, size: 12.5))
        }
    }

    private struct Rings: View {
        var body: some View {
            Canvas { ctx, size in
                let c = CGPoint(x: size.width * 0.8, y: size.height * 0.22)
                for (r, o) in [(70.0, 0.5), (130, 0.3), (190, 0.18), (250, 0.1)] {
                    let rect = CGRect(x: c.x - r, y: c.y - r, width: r * 2, height: r * 2)
                    ctx.stroke(Path(ellipseIn: rect), with: .color(Color.accent.opacity(o)), lineWidth: 1)
                }
                ctx.fill(Path(ellipseIn: CGRect(x: c.x - 5, y: c.y - 5, width: 10, height: 10)),
                         with: .color(Color.accentFill))
            }
        }
    }
}

/// EN | FR, 44 pt targets.
struct LanguageToggle: View {
    @Environment(AppSettings.self) private var settings

    var body: some View {
        HStack(spacing: 0) {
            option("EN", french: false)
            Text(verbatim: "|").foregroundStyle(Color.fgSoft)
            option("FR", french: true)
        }
        .font(BarkingFont.mono(.footnote, size: 13))
    }

    private func option(_ label: String, french: Bool) -> some View {
        let selected = settings.effectiveIsFrench == french
        return Button {
            settings.language = french ? .french : .english
        } label: {
            Text(verbatim: label)
                .foregroundStyle(selected ? Color.accent : Color.fgSoft)
                .fontWeight(selected ? .semibold : .regular)
                .frame(minWidth: 44, minHeight: 44)
        }
        .accessibilityLabel(Text(french ? "Français" : "English"))
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}
