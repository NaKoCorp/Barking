import BarkingKit
import SwiftUI

/// Device and display names before creating the identity.
struct CreateIdentityView: View {
    @Bindable var model: OnboardingModel
    let onCreated: () -> Void

    /// Why "Create my identity" is greyed out, said under it (U-3).
    private var reason: LocalizedStringKey? {
        if model.displayName.trimmingCharacters(in: .whitespaces).isEmpty { return "Type your name to continue." }
        if model.deviceName.trimmingCharacters(in: .whitespaces).isEmpty { return "Name this device to continue." }
        return nil
    }

    var body: some View {
        Group {
            BarkingTextField("Your name", text: $model.displayName,
                             footer: "Your name travels in your contact card. No phone number, no email.",
                             identifier: "create.name")
                .textContentType(.name)
            BarkingTextField("This device's name", text: $model.deviceName,
                             footer: "Shown on your other devices, and to your contacts in your card.",
                             identifier: "create.deviceName")
            if let e = model.errorText {
                Text(LocalizedStringKey(e)).font(.bBodySmall).foregroundStyle(Color.danger)
            }
        }
        .barkingScreen()
        .ctaBar {
            PrimaryButton("Create my identity", enabled: model.canCreate, isLoading: model.busy, reason: reason) {
                Task {
                    guard await model.create() != nil else { return }
                    Haptic.success.play()
                    onCreated()
                }
            }
        }
        .navigationTitle(Text("Create my identity"))
    }
}

/// Screen 2 of the mockup: the 24 words, once.
struct PhraseView: View {
    @Bindable var model: OnboardingModel
    let onContinue: () -> Void
    @State private var screenshotWarning = false
    @Environment(\.scenePhase) private var phase
    @Environment(\.isSceneCaptured) private var captured

    /// Hidden in the app switcher and while the screen is recorded or mirrored.
    private var hidden: Bool { phase != .active || captured }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Eyebrow("step 2 of 2")
                ScreenTitle("Your recovery phrase", size: 26)
                Text("24 words. They alone let you recover your identity on a new phone.")
                    .font(BarkingFont.sans(.body, size: 15))
                    .foregroundStyle(Color.fgMuted)
                if hidden {
                    Text("Hidden while the screen is recorded or the app is in the background.")
                        .font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fgMuted)
                        .frame(maxWidth: .infinity, minHeight: 200)
                        .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
                } else if let words = model.phrase {
                    PhraseWordsGrid(words: words, identifiers: true)
                }
                Banner(kind: .warning, title: "Write it down offline.",
                       message: "Never in a screenshot or a notes app. Recovering does not restore contacts or message history.")
                if let words = model.phrase, !hidden {
                    PhraseExportButtons(words: words)
                    Text("Shown only once: Barking does not keep the words.")
                        .font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgMuted)
                }
                Toggle(isOn: $model.wroteItDown) {
                    Text("I wrote the 24 words down").foregroundStyle(Color.fg)
                }
                .toggleStyle(CheckboxStyle())
                .accessibilityIdentifier("phrase.wroteItDown")
                PrimaryButton("Continue", enabled: model.canContinue, action: onContinue)
            }
            .padding(24)
        }
        .background(Color.surfaceWelcome)
        // A short inline title, never an empty one: with an empty title iOS 26
        // draws no bar behind the back button and the words scroll under it.
        .navigationTitle(Text("Recovery phrase"))
        .toolbarTitleDisplayMode(.inline)
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
            screenshotWarning = true
        }
        .alert(Text("Screenshot taken"), isPresented: $screenshotWarning) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Delete it: your recovery phrase should never be stored in a photo.")
        }
    }
}

/// 22 pt checkbox in the accent color.
struct CheckboxStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            HStack(spacing: 10) {
                Image(systemName: configuration.isOn ? "checkmark.square.fill" : "square")
                    .font(.bSymbol(22, relativeTo: .title2))
                    .foregroundStyle(Color.accent)
                configuration.label
            }
            .frame(minHeight: 44)
        }
        .accessibilityAddTraits(configuration.isOn ? .isSelected : [])
    }
}

/// The 24 words in 3 columns, numbered (screen 06, and "See the 24 words
/// again" from the quiz).
struct PhraseWordsGrid: View {
    let words: [String]
    /// `phrase.word.N` on each word: the UI tests read the phrase there.
    var identifiers = false

    var body: some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 6), count: 3), spacing: 6) {
            ForEach(Array(words.enumerated()), id: \.offset) { i, w in
                HStack(spacing: 4) {
                    Text(verbatim: "\(i + 1)").font(BarkingFont.mono(.caption2, size: 10.5))
                        .foregroundStyle(Color.fgSoft)
                    Text(verbatim: w).font(BarkingFont.mono(.footnote, size: 13))
                        .foregroundStyle(Color.fg)
                        .accessibilityIdentifier(ifPresent: identifiers ? "phrase.word.\(i + 1)" : nil)
                    Spacer(minLength: 0)
                }
                .padding(8)
                .background(Color.surfaceAlt, in: .rect(cornerRadius: Radius.button))
            }
        }
        .padding(12)
        .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
        .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
        .privacySensitive()
    }
}

/// "See the 24 words again" (U-24): the phrase still in memory, hidden in
/// the app switcher and while the screen is recorded, as on screen 06.
private struct PhraseWordsSheet: View {
    let words: [String]
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var phase
    @Environment(\.isSceneCaptured) private var captured

    var body: some View {
        NavigationStack {
            Group {
                if phase != .active || captured {
                    Text("Hidden while the screen is recorded or the app is in the background.")
                        .font(.bBody).foregroundStyle(Color.fgMuted)
                        .frame(maxWidth: .infinity, minHeight: 200)
                } else {
                    PhraseWordsGrid(words: words)
                }
            }
            .barkingScreen()
            .navigationTitle(Text("Recovery phrase"))
            .toolbarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
        }
        .presentationBackground(Color.surface)
    }
}

/// 3 words to confirm; "Later" keeps a banner on the chats. A wrong set
/// keeps the picks and Confirm (U-24): the error line says what to do.
struct PhraseConfirmView: View {
    @Bindable var model: OnboardingModel
    let onDone: () -> Void
    /// Wrong sets confirmed: each one is felt (U-25).
    @State private var wrongConfirms = 0
    @State private var showingWords = false
    @Environment(\.dynamicTypeSize) private var size

    /// The haptic of a Confirm: success, or an error for each wrong set.
    static func confirmFeedback(passed: Bool) -> Haptic { passed ? .success : .error }

    /// Why Confirm is greyed out (U-3).
    private var reason: LocalizedStringKey? { model.canConfirmQuiz ? nil : "Pick one word per row." }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Eyebrow("confirm")
                ScreenTitle("Check three words", size: 26)
                if let quiz = model.quiz {
                    ForEach(Array(quiz.questions.enumerated()), id: \.offset) { qi, q in
                        VStack(alignment: .leading, spacing: Space.s2) {
                            SectionLabel("Word \(q.index + 1)")
                                .accessibilityIdentifier("quiz.question.\(qi)")
                                .accessibilityValue(Text(verbatim: "\(q.index + 1)"))
                            // Four in a row; two at accessibility sizes, so a word never truncates.
                            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: Space.s2),
                                                     count: size.isAccessibilitySize ? 2 : 4),
                                      spacing: Space.s2) {
                                ForEach(q.choices, id: \.self) { c in choice(c, question: qi) }
                            }
                        }
                    }
                }
                if model.quizWrong {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text(verbatim: "✗").font(.bSymbol(13, relativeTo: .subheadline, weight: .bold))
                            .accessibilityHidden(true)
                        Text("One of the words is wrong. Check your copy.").font(.bBody)
                    }
                    .foregroundStyle(Color.danger)
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("quiz.error")
                }
                PrimaryButton("Confirm", enabled: model.canConfirmQuiz, reason: reason) { confirm() }
                if model.quizWrong, model.phrase != nil {
                    SecondaryButton("See the 24 words again") { showingWords = true }
                }
                SecondaryButton("Later", action: onDone)
            }
            .padding(24)
        }
        .background(Color.surfaceWelcome)
        // A short inline title, never an empty one (B2 rule): the headline is
        // in the content.
        .navigationTitle(Text("Recovery phrase"))
        .toolbarTitleDisplayMode(.inline)
        .sensoryFeedback(Haptic.error.feedback, trigger: wrongConfirms)
        .sheet(isPresented: $showingWords) { PhraseWordsSheet(words: model.phrase ?? []) }
        .onAppear { if model.quiz == nil { model.startQuiz() } }
    }

    private func choice(_ word: String, question qi: Int) -> some View {
        let selected = model.answers[qi] == word
        return Button { model.pick(word, for: qi) } label: {
            HStack(spacing: Space.s1) {
                if selected {
                    Text(verbatim: "✓").font(.bSymbol(11, relativeTo: .footnote, weight: .bold))
                        .accessibilityHidden(true)
                }
                Text(verbatim: word).font(BarkingFont.mono(.footnote, size: 13))
                    .lineLimit(1).minimumScaleFactor(0.8)
            }
            .padding(.horizontal, Space.s1)
            .frame(maxWidth: .infinity, minHeight: 44)
            .foregroundStyle(selected ? Color.white : Color.fg)
            .background(selected ? Color.accentFill : Color.surfaceAlt, in: .rect(cornerRadius: Radius.button))
        }
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("quiz.\(qi).\(word)")
    }

    private func confirm() {
        let passed = model.confirmQuiz()
        if passed {
            // The view leaves the screen: played now, not by a view state.
            Self.confirmFeedback(passed: true).play()
            onDone()
            return
        }
        wrongConfirms += 1
        AccessibilityNotification.Announcement(String(localized: "One of the words is wrong. Check your copy.")).post()
    }
}

/// Entry of the 24 words (U-31): a 3-column grid of tiles that mirrors the
/// written copy (one column at accessibility sizes), BIP-39 suggestions
/// above the keyboard, and Recover pinned with its count.
struct RecoverView: View {
    @Bindable var model: OnboardingModel
    let onRecovered: (CoreService) -> Void
    @FocusState private var focused: Int?
    @Environment(\.dynamicTypeSize) private var size

    /// Why Recover is greyed out (U-3).
    private var reason: LocalizedStringKey? {
        switch model.recoverBlocker {
        case .missing(let n)?: "Words left to fill in: \(n)."
        case .unknownWord(let i)?: "Word \(i) is not in the word list."
        case nil: nil
        }
    }

    var body: some View {
        Group {
            Banner(kind: .info, title: "Contacts and history are not restored")
            SecondaryButton("Paste the 24 words") {
                if let s = UIPasteboard.general.string { model.paste(s) }
            }
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: Space.s2),
                                     count: size.isAccessibilitySize ? 1 : 3),
                      spacing: Space.s2) {
                ForEach(0..<24, id: \.self) { i in tile(i) }
            }
            .privacySensitive()
            BarkingTextField("This device's name", text: $model.deviceName,
                             footer: "Shown on your other devices, and to your contacts in your card.",
                             identifier: "recover.deviceName")
            if let e = model.errorText {
                Text(LocalizedStringKey(e)).font(.bBodySmall).foregroundStyle(Color.danger)
            }
        }
        .barkingScreen()
        .ctaBar {
            PrimaryButton("Recover (\(model.filledRecoveryWords)/24)", enabled: model.canRecover,
                          isLoading: model.busy, reason: reason) {
                Task { if let core = await model.recover() { onRecovered(core) } }
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .keyboard) { suggestions }
        }
        .navigationTitle(Text("Recover with 24 words"))
    }

    /// One word: its number in a fixed 24 pt slot (Fira 11), the word in
    /// Fira 14, on the field slot with the field's focus and error rings.
    private func tile(_ i: Int) -> some View {
        let invalid = model.invalidRecoveryIndexes.contains(i)
        let tokens = FieldTokens.of(FieldState(focused: focused == i, hasError: invalid))
        let shape = RoundedRectangle(cornerRadius: Radius.button)
        return HStack(spacing: Space.s1) {
            Text(verbatim: "\(i + 1)").font(BarkingFont.mono(.caption2, size: 11))
                .foregroundStyle(Color.fgSoft)
                .frame(width: 24, alignment: .trailing)
                .accessibilityHidden(true)
            // No prompt: the number already says which word goes here.
            TextField(text: $model.recoveryWords[i], prompt: Text(verbatim: "")) { Text("Word \(i + 1)") }
                .font(BarkingFont.mono(.subheadline, size: 14))
                .foregroundStyle(invalid ? Color.danger : Color(tokens.text))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(i < 23 ? .next : .done)
                .onSubmit { focused = i < 23 ? i + 1 : nil }
                .focused($focused, equals: i)
                .accessibilityLabel(Text("Word \(i + 1)"))
                .accessibilityValue(invalid ? Text("Not in the word list") : Text(verbatim: ""))
                .accessibilityIdentifier("recover.word.\(i + 1)")
        }
        .padding(.trailing, Space.s2)
        .frame(minHeight: 44)
        .background(Color(tokens.fill), in: shape)
        .overlay { if let b = tokens.border { shape.strokeBorder(Color(b), lineWidth: tokens.borderWidth) } }
        .contentShape(shape)
        .onTapGesture { focused = i }
    }

    /// Up to four BIP-39 words for the focused tile, above the keyboard.
    @ViewBuilder private var suggestions: some View {
        if let i = focused {
            ForEach(model.suggestions(for: model.recoveryWords[i]), id: \.self) { w in
                Button(w) {
                    model.recoveryWords[i] = w
                    focused = i < 23 ? i + 1 : nil
                }
                .font(BarkingFont.mono(.subheadline, size: 14))
            }
            Spacer()
        }
    }
}
