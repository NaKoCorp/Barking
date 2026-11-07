import PDFKit
import XCTest
@testable import Barking
import BarkingKit

final class PhraseExportTests: XCTestCase {
    private let words = "lantern orbit maple quiet harbor velvet signal copper meadow ember tunnel violet anchor river pebble falcon winter cedar marble echo summit nectar puzzle tide".split(separator: " ").map(String.init)

    func testPasswordRules() {
        XCTAssertEqual(PhraseExport.problem("short", "short"), .tooShort)
        XCTAssertEqual(PhraseExport.problem("correct horse battery", "correct horse batterx"), .mismatch)
        XCTAssertNil(PhraseExport.problem("correct horse battery", "correct horse battery"))
        // Long enough but weak: the PDF's password check is fast to attack.
        XCTAssertEqual(PhraseExport.problem("aaaaaaaaaaaaaa", "aaaaaaaaaaaaaa"), .tooWeak)
        XCTAssertEqual(PhraseExport.problem("password1234", "password1234"), .tooWeak)
    }

    func testSuggestedPasswordIsSevenListWords() {
        let list = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"]
        let a = PhraseExport.suggestedPassword(from: list)
        let parts = a.split(separator: "-").map(String.init)
        XCTAssertEqual(parts.count, 7)
        XCTAssertTrue(parts.allSatisfy(list.contains))
        XCTAssertEqual(PhraseExport.strength(PhraseExport.suggestedPassword(from: bip39Words())), 3)
    }

    func testStrengthGrowsWithLengthAndVariety() {
        XCTAssertLessThan(PhraseExport.strength("aaaaaaaaaaaa"), PhraseExport.strength("Tr4in-blue-otter-42"))
        XCTAssertEqual(PhraseExport.strength(""), 0)
        XCTAssertEqual(PhraseExport.strength("four random words together here"), 3)
    }

    func testPrintedPageHoldsEveryWord() throws {
        let doc = try XCTUnwrap(PDFDocument(data: PhraseExport.page(words: words)))
        let text = try XCTUnwrap(doc.string)
        for w in words { XCTAssertTrue(text.contains(w), w) }
    }

    func testFileIsUnreadableWithoutThePassword() throws {
        let url = try PhraseExport.encryptedFile(words: words, password: "correct horse battery")
        defer { PhraseExport.discard(url) }
        let raw = try Data(contentsOf: url)
        XCTAssertNil(raw.range(of: Data("lantern".utf8)))
        let doc = try XCTUnwrap(PDFDocument(url: url))
        XCTAssertTrue(doc.isEncrypted)
        XCTAssertTrue(doc.isLocked)
        XCTAssertFalse(doc.unlock(withPassword: "wrong password!!"))
        XCTAssertTrue(doc.unlock(withPassword: "correct horse battery"))
        XCTAssertTrue(doc.string?.contains("lantern") ?? false)
    }

    func testDiscardRemovesTheFile() throws {
        let url = try PhraseExport.encryptedFile(words: words, password: "correct horse battery")
        PhraseExport.discard(url)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.deletingLastPathComponent().path))
    }
}
