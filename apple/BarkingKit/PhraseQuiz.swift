import Foundation

/// Confirmation of the recovery phrase (spec iOS messaging §5.2): 3 words at
/// distinct positions, each among 4 choices taken from the phrase itself.
public struct PhraseQuiz: Sendable {
    public struct Question: Sendable, Equatable {
        /// Position in the phrase, 0-based ("word no. index + 1").
        public let index: Int
        public let choices: [String]
    }

    public let questions: [Question]
    private let answers: [String]

    public init(words: [String], rng: inout some RandomNumberGenerator) {
        let picked = Array((0..<words.count).shuffled(using: &rng).prefix(3)).sorted()
        var questions: [Question] = []
        for i in picked {
            let decoys = Array(Set(words).subtracting([words[i]]).sorted().shuffled(using: &rng).prefix(3))
            questions.append(Question(index: i, choices: (decoys + [words[i]]).shuffled(using: &rng)))
        }
        self.questions = questions
        self.answers = picked.map { words[$0] }
    }

    public init(words: [String]) {
        var g = SystemRandomNumberGenerator()
        self.init(words: words, rng: &g)
    }

    /// The chosen words, in question order, are the right ones.
    public func check(_ chosen: [String]) -> Bool { chosen == answers }
}
