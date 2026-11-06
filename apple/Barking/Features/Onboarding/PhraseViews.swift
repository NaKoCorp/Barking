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
                    LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 6), count: 3), spacing: 6) {
                        ForEach(Array(words.enumerated()), id: \.offset) { i, w in
                            HStack(spacing: 4) {
                                Text(verbatim: "\(i + 1)").font(BarkingFont.mono(.caption2, size: 10.5))
                                    .foregroundStyle(Color.fgSoft)
                                Text(verbatim: w).font(BarkingFont.mono(.footnote, size: 13))
                                    .foregroundStyle(Color.fg)
                                    .accessibilityIdentifier("phrase.word.\(i + 1)")
                                Spacer(minLength: 0)
                            }
                            .padding(8)
                            .background(Color.surfaceAlt, in: .rect(cornerRadius: Radius.button))
                        }
                    }
                    .padding(12)
                    .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
                    .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
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

/// 3 words to confirm; "Later" keeps a banner on the chats.
struct PhraseConfirmView: View {
    @Bindable var model: OnboardingModel
    let onDone: () -> Void

    /// nil until a word is picked on every row, then whether they are right.
    private var quizOutcome: Bool? { model.answers.allSatisfy { $0 != nil } ? model.quizPassed : nil }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Eyebrow("confirm")
                ScreenTitle("Check three words", size: 26)
                if let quiz = model.quiz {
                    ForEach(Array(quiz.questions.enumerated()), id: \.offset) { qi, q in
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Word no. \(q.index + 1)").font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold))
                                .foregroundStyle(Color.fg)
                                .accessibilityIdentifier("quiz.question.\(qi)")
                                .accessibilityValue(Text(verbatim: "\(q.index + 1)"))
                            HStack(spacing: 8) {
                                ForEach(q.choices, id: \.self) { c in
                                    let selected = model.answers[qi] == c
                                    Button { model.answers[qi] = c } label: {
                                        Text(verbatim: c).font(BarkingFont.mono(.footnote, size: 13))
                                            .frame(maxWidth: .infinity, minHeight: 44)
                                            .foregroundStyle(selected ? Color.white : Color.fg)
                                            .background(selected ? Color.accentFill : Color.surfaceAlt,
                                                        in: .rect(cornerRadius: Radius.button))
                                    }
                                    .accessibilityAddTraits(selected ? .isSelected : [])
                                    .accessibilityIdentifier("quiz.\(qi).\(c)")
                                }
                            }
                        }
                    }
                }
                if model.answers.allSatisfy({ $0 != nil }) && !model.quizPassed {
                    Text("One of the words is wrong. Check your copy.").foregroundStyle(Color.danger)
                }
                PrimaryButton("Confirm", enabled: model.quizPassed) {
                    model.markPhraseConfirmed()
                    onDone()
                }
                SecondaryButton("Later", action: onDone)
            }
            .padding(24)
        }
        .background(Color.surfaceWelcome)
        // Once the three words are picked: right or wrong, felt (U-25).
        .sensoryFeedback(trigger: quizOutcome) { _, now in
            now.map { $0 ? Haptic.success.feedback : Haptic.error.feedback }
        }
        .onAppear { if model.quiz == nil { model.startQuiz() } }
    }
}

/// Entry of the 24 words, with BIP-39 suggestions.
struct RecoverView: View {
    @Bindable var model: OnboardingModel
    let onRecovered: (CoreService) -> Void
    @FocusState private var focused: Int?

    var body: some View {
        Form {
            Section {
                Text("Contacts and history are not restored").foregroundStyle(Color.fgMuted)
                Button("Paste the 24 words") {
                    if let s = UIPasteboard.general.string { model.paste(s) }
                }
            }
            Section {
                ForEach(0..<24, id: \.self) { i in
                    HStack {
                        Text(verbatim: "\(i + 1)").font(BarkingFont.mono(.footnote, size: 12))
                            .foregroundStyle(Color.fgSoft).frame(width: 28, alignment: .trailing)
                        TextField(text: $model.recoveryWords[i]) { Text("word") }
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .focused($focused, equals: i)
                            .foregroundStyle(model.invalidRecoveryIndexes.contains(i) ? Color.danger : Color.fg)
                            .accessibilityLabel(Text("Word \(i + 1)"))
                    }
                    if focused == i {
                        let s = model.suggestions(for: model.recoveryWords[i])
                        if !s.isEmpty {
                            HStack {
                                ForEach(s, id: \.self) { w in
                                    Button(w) { model.recoveryWords[i] = w; focused = i < 23 ? i + 1 : nil }
                                        .buttonStyle(.bordered)
                                }
                            }
                        }
                    }
                }
            }
            Section {
                TextField("This device's name", text: $model.deviceName)
            }
            if let e = model.errorText { Text(LocalizedStringKey(e)).foregroundStyle(Color.danger) }
            PrimaryButton("Recover", enabled: model.canRecover && !model.busy) {
                Task { if let core = await model.recover() { onRecovered(core) } }
            }
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
        }
        .scrollContentBackground(.hidden)
        .background(Color.surface)
        .navigationTitle(Text("Recover with 24 words"))
    }
}
