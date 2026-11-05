import BarkingKit
import Foundation
import Observation
import UIKit

/// Onboarding state (spec iOS messaging §5.1, §5.2). The phrase stays in
/// memory only; whether it was confirmed is a plain flag (no secret).
@MainActor @Observable
final class OnboardingModel {
    enum Step: Hashable { case create, phrase, confirm, recover, link }

    static let confirmedKey = "barking.phraseConfirmed"

    private let defaults: UserDefaults
    private let identityExists: () -> Bool
    private let wordSet: Set<String>

    var path: [Step] = []
    var deviceName = UIDevice.current.model
    var displayName = ""
    var phrase: [String]?
    var wroteItDown = false
    var quiz: PhraseQuiz?
    var answers: [String?] = [nil, nil, nil]
    var recoveryWords = Array(repeating: "", count: 24)
    var busy = false
    var errorText: String?

    init(defaults: UserDefaults = .standard, identityExists: @escaping () -> Bool) {
        self.defaults = defaults
        self.identityExists = identityExists
        self.wordSet = Set(bip39Words())
    }

    var phraseConfirmed: Bool { defaults.bool(forKey: Self.confirmedKey) }

    /// Identity created, phrase never confirmed and no longer in memory.
    var phraseLost: Bool { identityExists() && !phraseConfirmed && phrase == nil }

    var canContinue: Bool { phrase != nil && wroteItDown }

    var canCreate: Bool {
        !deviceName.trimmingCharacters(in: .whitespaces).isEmpty
            && !displayName.trimmingCharacters(in: .whitespaces).isEmpty
    }

    func markPhraseConfirmed() { defaults.set(true, forKey: Self.confirmedKey) }

    func startQuiz() {
        guard let phrase else { return }
        quiz = PhraseQuiz(words: phrase)
        answers = [nil, nil, nil]
    }

    /// Answers complete and right.
    var quizPassed: Bool {
        guard let quiz, answers.allSatisfy({ $0 != nil }) else { return false }
        return quiz.check(answers.compactMap { $0 })
    }

    var invalidRecoveryIndexes: [Int] {
        recoveryWords.indices.filter {
            let w = normalized(recoveryWords[$0])
            return !w.isEmpty && !wordSet.contains(w)
        }
    }

    var canRecover: Bool {
        recoveryWords.allSatisfy { !normalized($0).isEmpty } && invalidRecoveryIndexes.isEmpty
    }

    /// Fills the 24 fields from a pasted phrase.
    func paste(_ text: String) {
        let words = text.split(whereSeparator: \.isWhitespace).map { normalized(String($0)) }
        guard words.count == 24 else { return }
        recoveryWords = words
    }

    func suggestions(for prefix: String) -> [String] {
        let p = normalized(prefix)
        guard p.count >= 2 else { return [] }
        return Array(wordSet.filter { $0.hasPrefix(p) }.sorted().prefix(4))
    }

    private func normalized(_ w: String) -> String {
        w.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    func create() async -> CoreService? {
        busy = true
        defer { busy = false }
        let name = deviceName.trimmingCharacters(in: .whitespaces)
        let display = displayName.trimmingCharacters(in: .whitespaces)
        do {
            let created = try await DeviceCall.run("create") { try DeviceFactory.createNew(deviceName: name) }
            let core = CoreService(device: created.device, runner: AppCallRunner())
            try await core.setDisplayName(display)
            phrase = created.recoveryPhrase.split(separator: " ").map(String.init)
            defaults.set(false, forKey: Self.confirmedKey)
            return core
        } catch {
            errorText = String(localized: "Something went wrong. Your data is safe.")
            return nil
        }
    }

    func recover() async -> CoreService? {
        busy = true
        defer { busy = false }
        let phrase = recoveryWords.map(normalized).joined(separator: " ")
        let name = deviceName.trimmingCharacters(in: .whitespaces)
        do {
            let device = try await DeviceCall.run("recover") {
                try DeviceFactory.recover(phrase: phrase, deviceName: name)
            }
            markPhraseConfirmed()
            return CoreService(device: device, runner: AppCallRunner())
        } catch BarkingError.InvalidInput {
            errorText = String(localized: "These 24 words do not match an identity.")
            return nil
        } catch {
            errorText = String(localized: "Something went wrong. Your data is safe.")
            return nil
        }
    }
}
