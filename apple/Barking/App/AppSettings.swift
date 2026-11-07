import SwiftUI

enum AppAppearance: String, CaseIterable { case system, light, dark }

/// The appearance chosen in the app (spec iOS messaging §7.1). The language
/// is the phone's, changed in the iPhone's Settings › Barking.
@MainActor @Observable
final class AppSettings {
    private let defaults: UserDefaults

    var appearance: AppAppearance {
        didSet { defaults.set(appearance.rawValue, forKey: "barking.appearance") }
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        // Left by the in-app language picker of earlier builds.
        defaults.removeObject(forKey: "barking.language")
        appearance = AppAppearance(rawValue: defaults.string(forKey: "barking.appearance") ?? "") ?? .system
    }

    var colorScheme: ColorScheme? {
        switch appearance {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}
