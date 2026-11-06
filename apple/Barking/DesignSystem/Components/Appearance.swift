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

/// The settings' appearance choice: the app's one segmented control (a menu
/// at accessibility text sizes).
struct AppearanceSegments: View {
    @Environment(AppSettings.self) private var settings

    var body: some View {
        @Bindable var settings = settings
        BarkingSegmented("Appearance", selection: $settings.appearance,
                         options: AppAppearance.allCases.map { ($0, $0.title) },
                         optionID: { "appearance.\($0.rawValue)" })
    }
}
