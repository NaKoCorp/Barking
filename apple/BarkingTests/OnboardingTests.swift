import UIKit
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
        // Review B4 #4: "See the 24 words again" stays once a set was wrong.
        XCTAssertTrue(m.hadWrongConfirm)
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

    func testRestartingTheQuizForgetsTheWrongSet() throws {
        let words = (0..<24).map { "w\($0)" }
        let m = OnboardingModel(defaults: freshDefaults())
        m.phrase = words
        m.startQuiz()
        let q = try XCTUnwrap(m.quiz)
        for (i, question) in q.questions.enumerated() {
            m.pick(try XCTUnwrap(question.choices.first { $0 != words[question.index] }), for: i)
        }
        m.confirmQuiz()
        XCTAssertTrue(m.hadWrongConfirm)
        m.startQuiz()
        XCTAssertFalse(m.hadWrongConfirm)
    }

    /// Review B4 #3: four chips per row only while an 8-letter word fits.
    func testQuizColumns() {
        XCTAssertEqual(PhraseConfirmView.columns(for: .large), 4)
        XCTAssertEqual(PhraseConfirmView.columns(for: .xLarge), 4)
        XCTAssertEqual(PhraseConfirmView.columns(for: .xxLarge), 2)
        XCTAssertEqual(PhraseConfirmView.columns(for: .xxxLarge), 2)
        XCTAssertEqual(PhraseConfirmView.columns(for: .accessibility3), 2)
    }

    /// Review B4 #2: a paste says what it found, and a numbered list works.
    func testPasteSaysWhatItFound() {
        let words = Array(bip39Words().prefix(24))
        let m = OnboardingModel(defaults: freshDefaults())
        XCTAssertEqual(m.paste(words.prefix(12).joined(separator: " ")), .wrongCount(12))
        XCTAssertEqual(m.recoveryWords.filter { !$0.isEmpty }.count, 0, "a wrong paste fills nothing")
        XCTAssertEqual(m.paste("  \n "), .empty)
        let numbered = words.enumerated().map { "\($0.offset + 1). \($0.element)" }.joined(separator: "\n")
        XCTAssertEqual(m.paste(numbered), .filled)
        XCTAssertEqual(m.recoveryWords, words)
        let m2 = OnboardingModel(defaults: freshDefaults())
        XCTAssertEqual(m2.paste(words.enumerated().map { "\($0.offset + 1)) \($0.element)" }.joined(separator: " ")), .filled)
    }

    /// Review B4 #2: the phrase never stays on the clipboard after a paste,
    /// whether it filled the grid or not.
    func testPasteClearsTheClipboard() throws {
        let board = try XCTUnwrap(UIPasteboard(name: UIPasteboard.Name("test.\(UUID())"), create: true))
        defer { UIPasteboard.remove(withName: board.name) }
        let words = Array(bip39Words().prefix(24))
        let m = OnboardingModel(defaults: freshDefaults())
        board.string = words.prefix(23).joined(separator: " ")
        XCTAssertEqual(RecoverPaste.take(from: board, into: m), .init(result: .wrongCount(23), cleared: true))
        XCTAssertFalse(board.hasStrings, "a failed paste left the words on the clipboard")
        board.string = words.joined(separator: " ")
        XCTAssertEqual(RecoverPaste.take(from: board, into: m), .init(result: .filled, cleared: true))
        XCTAssertFalse(board.hasStrings)
        XCTAssertEqual(RecoverPaste.take(from: board, into: m), .init(result: nil, cleared: false))
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
