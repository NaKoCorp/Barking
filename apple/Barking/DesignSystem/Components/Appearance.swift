import SwiftUI

extension AppAppearance {
    var title: LocalizedStringKey {
        switch self {
        case .system: "System"
        case .light: "Light"
        case .dark: "Dark"
        }
    }

    var symbol: String {
        switch self {
        case .system: "circle.lefthalf.filled"
        case .light: "sun.max"
        case .dark: "moon"
        }
    }
}

/// Three 44 pt icons on the welcome screen: follow the phone, light, dark.
struct AppearanceIcons: View {
    @Environment(AppSettings.self) private var settings

    var body: some View {
        HStack(spacing: 0) {
            ForEach(AppAppearance.allCases, id: \.self) { a in
                let on = settings.appearance == a
                Button { settings.appearance = a } label: {
                    Image(systemName: a.symbol)
                        .font(.bSymbol(15, weight: on ? .semibold : .regular, maximum: 24))
                        .foregroundStyle(on ? Color.accent : Color.fgMuted)
                        .frame(width: 44, height: 44)
                }
                .accessibilityLabel(Text(a.title))
                .accessibilityAddTraits(on ? .isSelected : [])
                .accessibilityIdentifier("appearance.\(a.rawValue)")
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text("Appearance"))
    }
}

/// The settings' segmented control, drawn as in the mockup.
struct AppearanceSegments: View {
    @Environment(AppSettings.self) private var settings
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        HStack(spacing: 4) {
            ForEach(AppAppearance.allCases, id: \.self) { a in
                let on = settings.appearance == a
                Button { settings.appearance = a } label: {
                    Text(a.title)
                        .font(BarkingFont.mono(.footnote, size: 13, weight: on ? .semibold : .regular))
                        .foregroundStyle(on ? (scheme == .dark ? Color.white : Color.fg) : Color.fgMuted)
                        .frame(maxWidth: .infinity, minHeight: 44)
                        .background(on ? Color.segment : Color.clear, in: .rect(cornerRadius: Radius.button))
                        // The thumb is a ground, not purple: a 1 px edge sets it off the track.
                        .overlay {
                            if on { RoundedRectangle(cornerRadius: Radius.button).strokeBorder(Color.borderStrong, lineWidth: 1) }
                        }
                }
                .accessibilityAddTraits(on ? .isSelected : [])
                .accessibilityIdentifier("appearance.\(a.rawValue)")
            }
        }
        .padding(4)
        .background(Color.field, in: .rect(cornerRadius: Radius.field))
    }
}
