import BarkingKit
import SwiftUI
import UIKit

/// Print or encrypted PDF, each behind Face ID or the passcode.
struct PhraseExportButtons: View {
    let words: [String]
    @State private var pdfSheet = false
    @State private var failed = false

    var body: some View {
        HStack(spacing: 10) {
            button("Print", "printer") {
                guard await Self.owner() else { return }
                Self.print(words: words)
            }
            button("Encrypted PDF", "lock.doc") {
                guard await Self.owner() else { return }
                pdfSheet = true
            }
        }
        .sheet(isPresented: $pdfSheet) { PhrasePDFSheet(words: words) }
    }

    private func button(_ title: LocalizedStringKey, _ icon: String, action: @escaping () async -> Void) -> some View {
        Button { Task { await action() } } label: {
            Label(title, systemImage: icon)
                .font(BarkingFont.mono(.footnote, size: 13, weight: .semibold))
                .foregroundStyle(Color.accent)
                .frame(maxWidth: .infinity, minHeight: 44)
                .overlay(RoundedRectangle(cornerRadius: Radius.button).stroke(Color.borderStrong, lineWidth: 1))
        }
    }

    /// The phrase is already on screen: the check only guards its copies.
    static func owner() async -> Bool {
        await Owner.check(reason: String(localized: "Export your recovery phrase"))
    }

    /// Straight to the printer: the page stays in memory.
    @MainActor static func print(words: [String]) {
        let info = UIPrintInfo.printInfo()
        info.outputType = .grayscale
        info.jobName = String(localized: "Barking recovery phrase")
        let printer = UIPrintInteractionController.shared
        printer.printInfo = info
        printer.printingItem = PhraseExport.page(words: words)
        printer.present(animated: true)
    }
}

/// Chooses the password, makes the PDF, shares it, then deletes it.
struct PhrasePDFSheet: View {
    let words: [String]
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var confirm = ""
    @State private var file: URL?
    /// The suggested password, while it is the one in use (U-12).
    @State private var suggestion: String?
    @State private var revealed = true
    @State private var copied = false

    private var usingSuggestion: Bool { suggestion != nil && suggestion == password }
    private var problem: PhraseExport.PasswordProblem? { PhraseExport.problem(password, confirm) }

    var body: some View {
        NavigationStack {
            Group {
                Text("The PDF is only as safe as its password: anyone who gets the file can try passwords offline, as fast as they like.")
                    .font(.bBody).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: Space.s3) {
                    if usingSuggestion {
                        suggestedRow
                    } else {
                        BarkingTextField("Password", text: $password, error: passwordError, secure: true,
                                         trailing: .reveal, identifier: "pdf.password") { refuseIfNeeded(.password) }
                            .textContentType(.newPassword)
                        StrengthMeter(verdict: PhraseExport.verdict(password))
                    }
                    TextLink("Suggest a strong password") {
                        let p = PhraseExport.suggestedPassword(from: bip39Words())
                        password = p
                        confirm = p
                        suggestion = p
                        revealed = true
                        copied = false
                    }
                    .accessibilityIdentifier("pdf.suggest")
                }
                // The suggestion needs no second entry: it is shown and can be copied.
                if !usingSuggestion {
                    BarkingTextField("Same password again", text: $confirm, error: confirmError, secure: true,
                                     identifier: "pdf.confirm") { refuseIfNeeded(.confirm) }
                        .textContentType(.newPassword)
                }
                Text("Keep the password apart from the file, in your password manager or on paper.")
                    .font(BarkingFont.sans(.footnote, size: 13)).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .barkingScreen()
            .ctaBar {
                // Weak or different passwords are explained under the fields;
                // an empty one only here.
                PrimaryButton("Create the PDF", enabled: problem == nil,
                              reason: password.isEmpty ? "Choose a password to continue." : nil,
                              identifier: "pdf.create") {
                    file = try? PhraseExport.encryptedFile(words: words, password: password)
                }
            }
            .navigationTitle(Text("Encrypted PDF"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
        .presentationBackground(Color.surface)
        .sheet(item: $file, onDismiss: { if let f = file { PhraseExport.discard(f) } }) { url in
            ShareSheet(url: url) {
                PhraseExport.discard(url)
                file = nil
                dismiss()
            }
        }
    }

    /// Return on a password the gate refuses: an error haptic (U-25), on
    /// top of the line that says why.
    private func refuseIfNeeded(_ field: PhraseExport.PasswordField) {
        if PhraseExport.refusesOnSubmit(field, password: password, confirm: confirm) { Haptic.error.play() }
    }

    /// Too short or too weak, said under the password once one is typed.
    private var passwordError: LocalizedStringKey? {
        guard !password.isEmpty, let p = problem, p != .mismatch else { return nil }
        return Self.text(for: p)
    }

    private var confirmError: LocalizedStringKey? {
        guard !password.isEmpty, problem == .mismatch else { return nil }
        return Self.text(for: .mismatch)
    }

    /// The suggestion in Fira 15, read-only, with a reveal toggle and Copy.
    private var suggestedRow: some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            Text("Suggested password").font(.bSectionLabel).foregroundStyle(Color.fgMuted)
                .accessibilityHidden(true)
            HStack(spacing: 0) {
                Group {
                    if revealed {
                        Text(verbatim: password).foregroundStyle(Color.fg)
                    } else {
                        Text(verbatim: String(repeating: "•", count: 14)).foregroundStyle(Color.fgMuted)
                    }
                }
                .font(BarkingFont.mono(.subheadline, size: 15))
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, Space.s3).padding(.vertical, Space.s3)
                .privacySensitive()
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text("Suggested password"))
                .accessibilityValue(revealed ? Text(verbatim: password) : Text("Hidden"))
                .accessibilityIdentifier("pdf.suggested")
                iconButton(revealed ? "eye.slash" : "eye", revealed ? "Hide" : "Show") { revealed.toggle() }
                iconButton(copied ? "checkmark" : "doc.on.doc", copied ? "Copied" : "Copy") {
                    SecretPasteboard.copy(password)
                    copied = true
                    AccessibilityNotification.Announcement(String(localized: "Copied")).post()
                }
            }
            .background(Color.field, in: .rect(cornerRadius: Radius.field))
            StrengthMeter(verdict: PhraseExport.verdict(password))
            TextLink("Type my own password") {
                password = ""
                confirm = ""
                suggestion = nil
                revealed = false
            }
        }
    }

    private func iconButton(_ symbol: String, _ label: LocalizedStringKey, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol).font(.bSymbol(15, relativeTo: .body, maximum: 24))
                .foregroundStyle(Color.accent)
                .frame(width: 44, height: 44)
                .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text(label))
    }

    static func text(for p: PhraseExport.PasswordProblem) -> LocalizedStringKey {
        switch p {
        case .tooShort: "At least 12 characters."
        case .tooWeak: "Too easy to guess: use the suggestion or several random words."
        case .mismatch: "The two passwords differ."
        }
    }
}

extension URL: @retroactive Identifiable {
    public var id: String { absoluteString }
}

/// Three bars and a word that follow the gate (U-16): what the button
/// refuses is "too weak" (✗ `danger`, 1 or 2 bars), what it accepts is
/// "strong" (✓ `ok`, 3 bars). Nothing while the field is empty.
private struct StrengthMeter: View {
    let verdict: PhraseExport.Verdict
    @Environment(\.dynamicTypeSize) private var size

    var body: some View {
        if verdict != .empty {
            // At AX sizes the word goes under the bars instead of wrapping letter by letter.
            let layout = size.isAccessibilitySize
                ? AnyLayout(VStackLayout(alignment: .leading, spacing: Space.s1))
                : AnyLayout(HStackLayout(spacing: Space.s1))
            layout {
                HStack(spacing: Space.s1) {
                    ForEach(1...3, id: \.self) { i in
                        Capsule().fill(i <= bars ? color : Color.field).frame(height: 4)
                    }
                }
                HStack(spacing: Space.s1) {
                    Text(verbatim: verdict == .strong ? "✓" : "✗").font(.bSymbol(12, relativeTo: .caption, weight: .bold))
                    Text(verdict == .strong ? "strong" : "too weak").font(.bMeta)
                }
                .fixedSize()
                .foregroundStyle(color)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("Password strength"))
            .accessibilityValue(verdict == .strong ? Text("strong, accepted") : Text("too weak, not accepted"))
        }
    }

    private var bars: Int {
        switch verdict {
        case .empty: 0
        case .tooWeak(let b): b
        case .strong: 3
        }
    }

    private var color: Color { verdict == .strong ? .ok : .danger }
}

/// The system share sheet; `done` runs when it closes, shared or not.
private struct ShareSheet: UIViewControllerRepresentable {
    let url: URL
    let done: () -> Void

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let vc = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        vc.completionWithItemsHandler = { _, _, _, _ in done() }
        return vc
    }

    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
