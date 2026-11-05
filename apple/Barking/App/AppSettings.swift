import SwiftUI

enum AppLanguage: String, CaseIterable { case system, english, french }
enum AppAppearance: String, CaseIterable { case system, light, dark }

/// In-app language and appearance (spec iOS messaging §5.8, §7.1, §7.4).
@MainActor @Observable
final class AppSettings {
    private let defaults: UserDefaults

    var language: AppLanguage {
        didSet { defaults.set(language.rawValue, forKey: "barking.language") }
    }
    var appearance: AppAppearance {
        didSet { defaults.set(appearance.rawValue, forKey: "barking.appearance") }
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        language = AppLanguage(rawValue: defaults.string(forKey: "barking.language") ?? "") ?? .system
        appearance = AppAppearance(rawValue: defaults.string(forKey: "barking.appearance") ?? "") ?? .system
    }

    var locale: Locale {
        switch language {
        case .system: .autoupdatingCurrent
        case .english: Locale(identifier: "en")
        case .french: Locale(identifier: "fr")
        }
    }

    var colorScheme: ColorScheme? {
        switch appearance {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }

    /// The language the UI shows now (for the EN | FR toggle).
    var effectiveIsFrench: Bool {
        language == .french || (language == .system && Locale.current.language.languageCode?.identifier == "fr")
    }
}
