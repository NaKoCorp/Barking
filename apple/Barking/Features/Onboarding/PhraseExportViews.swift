import BarkingKit
import LocalAuthentication
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

    /// Face ID, Touch ID or the passcode. A phone with no passcode has
    /// nothing to check: the phrase is already on screen.
    static func owner() async -> Bool {
        #if BARKING_DEV
        if ProcessInfo.processInfo.arguments.contains("-BarkingUITestReset") { return true }
        #endif
        let ctx = LAContext()
        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            return (error as? LAError)?.code == .passcodeNotSet
        }
        return (try? await ctx.evaluatePolicy(.deviceOwnerAuthentication,
                                              localizedReason: String(localized: "Export your recovery phrase"))) ?? false
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

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("The PDF is only as safe as its password: anyone who gets the file can try passwords offline, as fast as they like.")
                        .foregroundStyle(Color.fgMuted)
                    Button("Suggest a strong password") {
                        password = PhraseExport.suggestedPassword(from: bip39Words())
                        confirm = password
                    }
                    .accessibilityIdentifier("pdf.suggest")
                }
                Section {
                    SecureField("Password", text: $password).textContentType(.newPassword)
                        .accessibilityIdentifier("pdf.password")
                    SecureField("Same password again", text: $confirm).textContentType(.newPassword)
                        .accessibilityIdentifier("pdf.confirm")
                    StrengthBar(level: PhraseExport.strength(password))
                } footer: {
                    if let p = PhraseExport.problem(password, confirm), !password.isEmpty {
                        Text(Self.text(for: p)).foregroundStyle(Color.danger)
                    } else {
                        Text("Keep the password apart from the file, in your password manager or on paper.")
                    }
                }
                PrimaryButton("Create the PDF", enabled: PhraseExport.problem(password, confirm) == nil) {
                    file = try? PhraseExport.encryptedFile(words: words, password: password)
                }
                .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
                .accessibilityIdentifier("pdf.create")
            }
            .scrollContentBackground(.hidden)
            .background(Color.surface)
            .navigationTitle(Text("Encrypted PDF"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
        .sheet(item: $file, onDismiss: { if let f = file { PhraseExport.discard(f) } }) { url in
            ShareSheet(url: url) {
                PhraseExport.discard(url)
                file = nil
                dismiss()
            }
        }
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

private struct StrengthBar: View {
    let level: Int

    var body: some View {
        HStack(spacing: 4) {
            ForEach(1...3, id: \.self) { i in
                Capsule().fill(i <= level ? color : Color.field).frame(height: 4)
            }
            Text(label).font(.caption).foregroundStyle(Color.fgMuted).frame(minWidth: 60, alignment: .trailing)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(label))
    }

    private var color: Color { level >= 3 ? .ok : level == 2 ? .warnFg : .danger }
    private var label: LocalizedStringKey {
        switch level {
        case 0: ""
        case 1: "weak"
        case 2: "fair"
        default: "strong"
        }
    }
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
