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
        let m = OnboardingModel(defaults: freshDefaults(), identityExists: { false })
        m.phrase = (0..<24).map { "w\($0)" }
        XCTAssertFalse(m.canContinue)
        m.wroteItDown = true
        XCTAssertTrue(m.canContinue)
    }

    func testPhraseLostAfterRelaunch() {
        let m = OnboardingModel(defaults: freshDefaults(), identityExists: { true })
        XCTAssertNil(m.phrase)
        XCTAssertTrue(m.phraseLost)
        m.markPhraseConfirmed()
        XCTAssertFalse(m.phraseLost)
    }

    func testRecoverRejectsUnknownWord() {
        let m = OnboardingModel(defaults: freshDefaults(), identityExists: { false })
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
