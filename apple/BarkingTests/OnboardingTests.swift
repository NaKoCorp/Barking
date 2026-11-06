import XCTest
@testable import Barking
@testable import BarkingKit

struct SeededRNG: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return state
    }
}

final class PhraseQuizTests: XCTestCase {
    let words = (0..<24).map { "w\($0)" }

    func testThreeDistinctQuestionsWithFourChoices() {
        var rng = SeededRNG(state: 7)
        let quiz = PhraseQuiz(words: words, rng: &rng)
        XCTAssertEqual(quiz.questions.count, 3)
        XCTAssertEqual(Set(quiz.questions.map(\.index)).count, 3)
        for q in quiz.questions {
            XCTAssertEqual(q.choices.count, 4)
            XCTAssertEqual(Set(q.choices).count, 4)
            XCTAssertTrue(q.choices.contains(words[q.index]))
        }
    }

    func testCheckAcceptsRightAnswersOnly() {
        var rng = SeededRNG(state: 9)
        let quiz = PhraseQuiz(words: words, rng: &rng)
        let right = quiz.questions.map { words[$0.index] }
        XCTAssertTrue(quiz.check(right))
        var wrong = right
        wrong[1] = quiz.questions[1].choices.first { $0 != right[1] }!
        XCTAssertFalse(quiz.check(wrong))
        XCTAssertFalse(quiz.check(Array(right.prefix(2))))
    }
}

@MainActor
final class OnboardingModelTests: XCTestCase {
    func freshDefaults() -> UserDefaults {
        let d = UserDefaults(suiteName: "test.\(UUID())")!
        return d
    }

    func testContinueDisabledUntilChecked() {
        let m = OnboardingModel(defaults: freshDefaults())
        m.phrase = (0..<24).map { "w\($0)" }
        XCTAssertFalse(m.canContinue)
        m.wroteItDown = true
        XCTAssertTrue(m.canContinue)
    }

    func testConfirmationIsRemembered() {
        let d = freshDefaults()
        let m = OnboardingModel(defaults: d)
        XCTAssertFalse(m.phraseConfirmed)
        m.markPhraseConfirmed()
        XCTAssertTrue(OnboardingModel(defaults: d).phraseConfirmed)
    }

    /// UI review U-24: a wrong set keeps the picks, Confirm stays usable,
    /// and changing a pick clears the error until the next Confirm.
    func testQuizKeepsThePicksAfterAWrongConfirm() throws {
        let words = (0..<24).map { "w\($0)" }
        let m = OnboardingModel(defaults: freshDefaults())
        m.phrase = words
        m.startQuiz()
        let quiz = try XCTUnwrap(m.quiz)
        let right = quiz.questions.map { words[$0.index] }
        let wrong0 = try XCTUnwrap(quiz.questions[0].choices.first { $0 != right[0] })
        XCTAssertFalse(m.canConfirmQuiz)
        XCTAssertEqual(m.picksLeft, 3)
        m.pick(wrong0, for: 0)
        m.pick(right[1], for: 1)
        XCTAssertFalse(m.canConfirmQuiz)
        XCTAssertEqual(m.picksLeft, 1)
        m.pick(right[2], for: 2)
        XCTAssertTrue(m.canConfirmQuiz)
        XCTAssertFalse(m.quizWrong, "no verdict before Confirm")
        XCTAssertFalse(m.confirmQuiz())
        XCTAssertTrue(m.quizWrong)
        XCTAssertEqual(m.answers, [wrong0, right[1], right[2]])
        XCTAssertTrue(m.canConfirmQuiz)
        XCTAssertFalse(m.phraseConfirmed)
        m.pick(right[0], for: 0)
        XCTAssertFalse(m.quizWrong)
        XCTAssertTrue(m.confirmQuiz())
        XCTAssertTrue(m.phraseConfirmed)
    }

    /// UI review U-31: the Recover button counts the words and says what
    /// is missing.
    func testRecoverSaysWhatIsMissing() {
        let m = OnboardingModel(defaults: freshDefaults())
        XCTAssertEqual(m.filledRecoveryWords, 0)
        XCTAssertEqual(m.recoverBlocker, .missing(24))
        var words = Array(bip39Words().prefix(24))
        words[3] = ""
        words[5] = "notaword"
        m.recoveryWords = words
        XCTAssertEqual(m.filledRecoveryWords, 23)
        XCTAssertEqual(m.recoverBlocker, .unknownWord(6))
        words[5] = "zoo"
        m.recoveryWords = words
        XCTAssertEqual(m.recoverBlocker, .missing(1))
        words[3] = "zoo"
        m.recoveryWords = words
        XCTAssertNil(m.recoverBlocker)
        XCTAssertEqual(m.filledRecoveryWords, 24)
    }

    func testRecoverRejectsUnknownWord() {
        let m = OnboardingModel(defaults: freshDefaults())
        var words = Array(bip39Words().prefix(24))
        words[5] = "notaword"
        m.recoveryWords = words
        XCTAssertEqual(m.invalidRecoveryIndexes, [5])
        XCTAssertFalse(m.canRecover)
        words[5] = "zoo"
        m.recoveryWords = words
        XCTAssertTrue(m.invalidRecoveryIndexes.isEmpty)
        XCTAssertTrue(m.canRecover)
    }
}

@MainActor
final class AppRouterTests: XCTestCase {
    func testCardLinkBeforeOnboardingIsKept() {
        let router = AppRouter(start: .onboarding)
        let link = URL(string: "barking://card#barking1:abc")!
        router.open(url: link)
        XCTAssertEqual(router.pendingCardLink, "barking1:abc")
        router.becomeReady(core: CoreService(device: FakeDevice(), runner: DirectRunner()))
        XCTAssertEqual(router.pendingCardLink, "barking1:abc")
        XCTAssertEqual(router.takePendingCardLink(), "barking1:abc")
        XCTAssertNil(router.pendingCardLink)
    }

    func testOtherURLsAreIgnored() {
        let router = AppRouter(start: .onboarding)
        router.open(url: URL(string: "https://example.org/#x")!)
        XCTAssertNil(router.pendingCardLink)
    }
}
