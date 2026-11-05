import BarkingKit
import SwiftUI

/// Device and display names before creating the identity.
struct CreateIdentityView: View {
    @Bindable var model: OnboardingModel
    let onCreated: () -> Void

    var body: some View {
        Form {
            Section {
                TextField("Your name, as contacts see it", text: $model.displayName)
                    .textContentType(.name)
                TextField("This device's name", text: $model.deviceName)
            } footer: {
                Text("Your name travels in your contact card. No phone number, no email.")
            }
            if let e = model.errorText { Text(LocalizedStringKey(e)).foregroundStyle(Color.danger) }
            PrimaryButton("Create my identity", enabled: model.canCreate && !model.busy) {
                Task {
                    if await model.create() != nil { onCreated() }
                }
            }
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
        }
        .scrollContentBackground(.hidden)
        .background(Color.surface)
        .navigationTitle(Text("Create my identity"))
    }
}

/// Screen 2 of the mockup: the 24 words, once.
struct PhraseView: View {
    @Bindable var model: OnboardingModel
    let onContinue: () -> Void
    @State private var screenshotWarning = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Eyebrow("step 2 of 2")
                ScreenTitle("Your recovery phrase", size: 26)
                Text("24 words. They alone let you recover your identity on a new phone.")
                    .font(BarkingFont.sans(.body, size: 15))
                    .foregroundStyle(Color.fgMuted)
                if let words = model.phrase {
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
                    .font(.system(size: 22))
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
