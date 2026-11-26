import BarkingKit
import SwiftUI

/// A contact request's page (design decision 4): who they say they are,
/// the safety code that proves it, the history, then the answers. Nothing
/// of theirs is shown before it is accepted. Accepting hands over to the
/// new contact's conversation (`onAccepted`); refusing, blocking or the
/// request leaving the core goes back.
struct RequestView: View {
    let core: CoreService
    let onAccepted: (String) -> Void
    @State private var model: RequestModel
    @State private var alias = ""
    @State private var confirmRefuse = false
    @State private var confirmBlock = false
    @Environment(\.dismiss) private var dismiss

    init(core: CoreService, fingerprint: String, onAccepted: @escaping (String) -> Void) {
        self.core = core
        self.onAccepted = onAccepted
        _model = State(initialValue: RequestModel(fingerprint: fingerprint, core: core))
    }

    private var quoted: String {
        DeclaredName.quoted(model.request?.displayName ?? "", fingerprint: model.fingerprint)
    }

    var body: some View {
        Group {
            header
            if model.nameClash {
                Banner(kind: .warning, title: "Same name as one of your contacts")
                    .accessibilityIdentifier("request.clash")
            }
            codeSection
            if let request = model.request { historySection(request) }
            actions
            DangerZone {
                DangerButton("Refuse", hint: "Nothing is sent. A new invitation brings it back.",
                             identifier: "request.refuse", enabled: !model.isWorking) {
                    confirmRefuse = true
                }
                DangerButton("Block", hint: "Their invitations and messages are dropped. They are not told.",
                             identifier: "request.block", enabled: !model.isWorking) {
                    confirmBlock = true
                }
            }
        }
        .barkingScreen()
        // Kept: with an empty title iOS 26 draws no bar behind the back button.
        .navigationTitle(Text("Invitation"))
        .toolbarTitleDisplayMode(.inline)
        // The danger zone ends the page: the floating tab bar would cover it.
        .toolbar(.hidden, for: .tabBar)
        .task {
            // Subscribe before reading: a change during the load is not lost.
            let changes = await core.changes
            await model.load()
            for await change in changes { await model.handle(change) }
        }
        .onChange(of: model.vanished) { _, gone in if gone { dismiss() } }
        .confirmationDialog(Text("Refuse"), isPresented: $confirmRefuse, titleVisibility: .hidden) {
            Button("Refuse", role: .destructive) { Task { finish(await model.refuse()) } }
                .accessibilityIdentifier("request.refuse.confirm")
        }
        .confirmationDialog(Text("Block"), isPresented: $confirmBlock, titleVisibility: .hidden) {
            Button("Block", role: .destructive) { Task { finish(await model.block()) } }
                .accessibilityIdentifier("request.block.confirm")
        }
    }

    /// The avatar, the declared name in quotes, and what that name is worth.
    private var header: some View {
        VStack(alignment: .leading, spacing: Space.s3) {
            Avatar(name: model.request?.initialName ?? String(model.fingerprint.prefix(8)), fingerprint: model.fingerprint, size: 64)
            ScreenTitle(verbatim: quoted, size: 22)
            Text("Introduces themselves as \(quoted). This name is not verified.")
                .font(.bBody).foregroundStyle(Color.fgMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// The one proof of who they are: the page's rich moment.
    private var codeSection: some View {
        VStack(alignment: .leading, spacing: Space.s3) {
            SectionLabel("Safety code")
            CodeGrid(groups: model.codeGroups)
            FingerprintText(model.fingerprint).frame(maxWidth: .infinity)
            Text("Compare it aloud with the person before you accept.")
                .font(.bBody).foregroundStyle(Color.fgMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func historySection(_ request: ContactRequestInfo) -> some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            SectionLabel("History")
            ForEach(RequestHistory.long(request, now: .now), id: \.self) { line in
                Text(verbatim: line).font(.bBody).foregroundStyle(Color.fg)
            }
            if request.pendingMessages > 0 {
                Text("\(Int(request.pendingMessages)) messages waiting. You can read them once you accept.")
                    .font(.bBody).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var actions: some View {
        VStack(alignment: .leading, spacing: Space.s3) {
            BarkingTextField("Alias (optional)", text: $alias,
                             error: model.error == .aliasTaken ? "This alias is already used" : nil,
                             identifier: "request.alias")
                .submitLabel(.done)
                .onChange(of: alias) { model.aliasEdited() }
            PrimaryButton("Accept", enabled: !model.isWorking, isLoading: model.isAccepting,
                          identifier: "request.accept") {
                Task {
                    if let contact = await model.accept(alias: alias) {
                        Haptic.success.play()
                        onAccepted(contact)
                    } else if model.error != nil {
                        Haptic.error.play()
                    }
                }
            }
            SecondaryButton(model.request?.hidden == true ? "Show in the list" : "Hide", enabled: !model.isWorking) {
                Task { await model.setHidden(!(model.request?.hidden ?? false)) }
            }
            .accessibilityIdentifier("request.hide")
            if model.error == .failed {
                Banner(kind: .danger, title: "Not saved. Try again.")
            }
        }
    }

    /// Refused or blocked: back to the list. A failure stays, said by the banner.
    private func finish(_ done: Bool) {
        if done {
            Haptic.success.play()
            dismiss()
        } else if model.error != nil {
            Haptic.error.play()
        }
    }
}
