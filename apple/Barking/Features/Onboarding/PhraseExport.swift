import Foundation
import PDFKit
import UIKit

/// Paper or a password-protected PDF for the recovery phrase. The printed
/// page never touches the disk; the PDF lives in a fresh, file-protected
/// folder only until the share sheet closes.
enum PhraseExport {
    static let minPasswordLength = 12

    enum PasswordProblem: Equatable { case tooShort, tooWeak, mismatch }

    enum ExportError: Error { case render, write }

    static func problem(_ password: String, _ confirm: String) -> PasswordProblem? {
        if password.count < minPasswordLength { return .tooShort }
        if strength(password) < 3 { return .tooWeak }
        if password != confirm { return .mismatch }
        return nil
    }

    /// 0 (empty) to 3 (strong), from a rough entropy estimate: length times
    /// the size of the character classes used.
    static func strength(_ password: String) -> Int {
        guard !password.isEmpty else { return 0 }
        var pool = 0
        if password.contains(where: \.isLowercase) { pool += 26 }
        if password.contains(where: \.isUppercase) { pool += 26 }
        if password.contains(where: \.isNumber) { pool += 10 }
        if password.contains(where: { !$0.isLetter && !$0.isNumber }) { pool += 33 }
        let bits = Double(password.count) * log2(Double(max(pool, 2)))
        // The same few characters repeated are far weaker than they look.
        if Set(password).count < 5 { return 1 }
        return bits < 50 ? 1 : bits < 70 ? 2 : 3
    }

    /// Seven random words of `list` joined by dashes: 77 bits with the
    /// 2048 BIP39 words, out of reach of an offline attack on the PDF.
    static func suggestedPassword(from list: [String]) -> String {
        var rng = SystemRandomNumberGenerator()
        return (0..<7).compactMap { _ in list.randomElement(using: &rng) }.joined(separator: "-")
    }

    /// One A4 page: title, the 24 numbered words, what they are for.
    static func page(words: [String]) -> Data {
        let bounds = CGRect(x: 0, y: 0, width: 595, height: 842)
        let mono = UIFont(name: "FiraCode-Regular", size: 15) ?? .monospacedSystemFont(ofSize: 15, weight: .regular)
        let monoSmall = UIFont(name: "FiraCode-Regular", size: 10) ?? .monospacedSystemFont(ofSize: 10, weight: .regular)
        let title = UIFont(name: "FiraCode-SemiBold", size: 22) ?? .boldSystemFont(ofSize: 22)
        let ink = UIColor.black, soft = UIColor.darkGray
        return UIGraphicsPDFRenderer(bounds: bounds).pdfData { ctx in
            ctx.beginPage()
            NSString(string: String(localized: "Barking recovery phrase"))
                .draw(at: CGPoint(x: 56, y: 60), withAttributes: [.font: title, .foregroundColor: ink])
            NSString(string: Date.now.formatted(date: .long, time: .omitted))
                .draw(at: CGPoint(x: 56, y: 96), withAttributes: [.font: monoSmall, .foregroundColor: soft])
            for (i, w) in words.enumerated() {
                let col = CGFloat(i / 8), row = CGFloat(i % 8)
                let origin = CGPoint(x: 56 + col * 165, y: 150 + row * 34)
                NSString(string: String(format: "%2d", i + 1))
                    .draw(at: CGPoint(x: origin.x, y: origin.y + 4), withAttributes: [.font: monoSmall, .foregroundColor: soft])
                NSString(string: w)
                    .draw(at: CGPoint(x: origin.x + 24, y: origin.y), withAttributes: [.font: mono, .foregroundColor: ink])
            }
            let note = String(localized: "These 24 words alone let you recover your identity on a new phone. Keep this page offline, somewhere safe. Anyone who reads it can become you.")
            NSString(string: note).draw(in: CGRect(x: 56, y: 450, width: 483, height: 80),
                                        withAttributes: [.font: UIFont.systemFont(ofSize: 12), .foregroundColor: soft])
        }
    }

    /// The page, encrypted with `password`, in a new folder of its own.
    /// The caller removes it with `discard` once it has been shared.
    static func encryptedFile(words: [String], password: String) throws -> URL {
        guard let doc = PDFDocument(data: page(words: words)) else { throw ExportError.render }
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true,
                               attributes: [.protectionKey: FileProtectionType.complete])
        let url = dir.appendingPathComponent("Barking-recovery-phrase.pdf")
        guard doc.write(to: url, withOptions: [.userPasswordOption: password, .ownerPasswordOption: password]) else {
            discard(url)
            throw ExportError.write
        }
        try fm.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
        return url
    }

    static func discard(_ url: URL) {
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }
}
