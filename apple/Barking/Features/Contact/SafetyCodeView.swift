import BarkingKit
import SwiftUI

/// Screen 6 of the mockup, plus renaming and deleting the contact. Three
/// parts (UI review U-21): Verify, Contact, and a danger zone.
struct SafetyCodeView: View {
    let core: CoreService
    @State private var model: ContactModel
    @State private var aliasDraft = ""
    @State private var aliasSaved = false
    @State private var aliasFailed = false
    /// Set once the contact is deleted: leaving then saves nothing.
    @State private var deleted = false
    @State private var confirmDelete = false
    @State private var confirmBlock = false
    @State private var blockFailed = false
    @State private var showsMismatch = false
    @State private var showsMyCode = false
    /// A resend is under way: a second tap must not start another.
    @State private var resending = false
    /// The invitation sent with the add, when shown right after it.
    private let inviteResult: AddContactModel.InviteResult?
    /// Opened from Contacts: "Send a message" opens the conversation.
    /// Nil from the conversation itself, which is already open.
    private let onMessage: (() -> Void)?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.locale) private var locale

    init(core: CoreService, contact: String, inviteResult: AddContactModel.InviteResult? = nil,
         onMessage: (() -> Void)? = nil) {
        self.core = core
        self.inviteResult = inviteResult
        self.onMessage = onMessage
        _model = State(initialValue: ContactModel(contact: contact, core: core))
    }

    var body: some View {
        Group {
            VStack(alignment: .leading, spacing: Space.s3) {
                AvatarEditor(name: model.name, fingerprint: model.contact)
                ScreenTitle("Compare with \(model.name)", size: 22)
                Text("Read the numbers aloud, in person or on a call you trust. If they match, nobody sits between you.")
                    .font(.bBody).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
                if let onMessage {
                    // Secondary: "The numbers match" stays the page's one primary action.
                    SecondaryButton("Send a message", action: onMessage)
                        .accessibilityIdentifier("contact.message")
                        .padding(.top, Space.s1)
                }
            }
            inviteNotice
            verifySection
            VStack(alignment: .leading, spacing: Space.s2) {
                SectionLabel("Contact")
                BarkingTextField("Alias", text: $aliasDraft, error: aliasFailed ? "Not saved. Try again." : nil,
                                 identifier: "contact.alias") { Task { await saveAlias() } }
                // SwiftUI has no "Save" key; Return saves, and so does leaving.
                .submitLabel(.done)
                .onChange(of: aliasDraft) { aliasSaved = false; aliasFailed = false }
                if aliasSaved {
                    HStack(spacing: Space.s1) {
                        Text(verbatim: "✓").font(.bSymbol(12, relativeTo: .caption, weight: .bold))
                            .accessibilityHidden(true)
                        Text("Saved").font(.bMeta)
                    }
                    .foregroundStyle(Color.ok)
                }
            }
            if model.showsInvite { inviteSection }
            if !model.devices.isEmpty { devicesSection }
            DangerZone {
                DangerButton("Block this contact", hint: "Their messages stop reaching you. They are not told.",
                             identifier: "contact.block") {
                    confirmBlock = true
                }
                if blockFailed { Banner(kind: .danger, title: "Not saved. Try again.") }
                DangerButton("Delete this contact", hint: "The history is kept.", identifier: "contact.delete") {
                    confirmDelete = true
                }
            }
        }
        .barkingScreen()
        // Kept: with an empty title iOS 26 draws no bar behind the back button,
        // and the scrolled content runs under the status bar unblurred.
        .navigationTitle(Text("Safety code"))
        .toolbarTitleDisplayMode(.inline)
        // Pushed from the conversation, which hides the tab bar (U-26).
        .toolbar(.hidden, for: .tabBar)
        .task {
            await model.load()
            aliasDraft = model.alias
            // An invitation answered while the page is open.
            let changes = await core.changes
            for await change in changes { await model.handle(change) }
        }
        // A match is said (banner, haptic, VoiceOver), then the screen goes
        // back to the conversation; the mark can be removed from here later.
        .task(id: model.justVerified) {
            guard model.justVerified else { return }
            Haptic.success.play()
            AccessibilityNotification.Announcement(String(localized: "Verified")).post()
            try? await Task.sleep(for: .seconds(UIAccessibility.isVoiceOverRunning ? 3 : 1.5))
            if !Task.isCancelled { dismiss() }
        }
        // Back without Return still keeps a changed alias.
        .onDisappear {
            if !deleted, aliasDraft.trimmingCharacters(in: .whitespaces) != model.alias {
                Task { await saveAlias() }
            }
        }
        // Alerts, not confirmation dialogs: on iOS 26 a dialog floats as a
        // popover at the foot of the screen, far from what it confirms.
        .alert(Text("Delete \(model.name)?"), isPresented: $confirmDelete) {
            Button("Delete", role: .destructive) { deleted = true; Task { await model.delete(); dismiss() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("\(model.name) leaves your contacts on all your devices. They are not told.")
        }
        // Blocked, the contact leaves the chats: the chats list closes its
        // conversation once the change is published.
        .alert(Text("Block \(model.name)?"), isPresented: $confirmBlock) {
            Button("Block", role: .destructive) {
                Task {
                    if await model.block() {
                        deleted = true
                        Haptic.success.play()
                        dismiss()
                    } else {
                        blockFailed = true
                        Haptic.error.play()
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Their messages will no longer reach you and they leave your chats, on all your devices. They are not told. You can unblock them in Settings.")
        }
        .sheet(isPresented: $showsMismatch) { MismatchSheet() }
        .sheet(isPresented: $showsMyCode) { myCode }
    }

    /// What came of the invitation sent with the add (design decision 5);
    /// nothing when it went.
    @ViewBuilder private var inviteNotice: some View {
        switch inviteResult {
        case .tooLarge:
            Banner(kind: .info, title: "Your card is too large for an invitation",
                   message: "Show them your code instead.",
                   action: .init(label: "Show my code", hint: "Opens your code.") { showsMyCode = true })
                .accessibilityIdentifier("contact.inviteTooLarge")
        case .tooSoon:
            Text("Invitation already sent less than 24 h ago. You can resend it from their page.")
                .font(.bBodySmall).foregroundStyle(Color.fgMuted)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("contact.inviteTooSoon")
        case .failed:
            // No invitation is recorded, so the page offers no resend: the
            // code is the way left.
            Banner(kind: .info, title: "The invitation was not sent",
                   message: "Show them your code instead.",
                   action: .init(label: "Show my code", hint: "Opens your code.") { showsMyCode = true })
                .accessibilityIdentifier("contact.inviteFailed")
        case .sent, nil:
            EmptyView()
        }
    }

    /// My code, for the contact to scan when the invitation cannot carry it.
    private var myCode: some View {
        NavigationStack {
            ScrollView { MyCodeView(core: core).padding(Space.gutter) }
                .background(Color.surface)
                .navigationTitle(Text("My code"))
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { showsMyCode = false } } }
        }
        .presentationBackground(Color.surface)
    }

    private func feelFailure() { if model.saveFailed { Haptic.error.play() } }

    /// The numbers, the fingerprint, and what the person found.
    private var verifySection: some View {
        VStack(alignment: .leading, spacing: Space.s3) {
            SectionLabel("Verify")
            CodeGrid(groups: model.groups)
            HStack {
                Rectangle().fill(Color.border).frame(height: 1)
                Text("fingerprint").font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgSoft)
                Rectangle().fill(Color.border).frame(height: 1)
            }
            FingerprintText(model.contact).frame(maxWidth: .infinity)
            Text("The same code shows on all your linked devices: verifying here is enough.")
                .font(BarkingFont.sans(.footnote, size: 13)).foregroundStyle(Color.fgSoft)
                .fixedSize(horizontal: false, vertical: true)
            // The core did not record the mark (or its removal): never silent.
            if model.saveFailed {
                Banner(kind: .danger, title: "Not saved. Try again.")
            }
            if model.justVerified {
                HStack(spacing: Space.s2) {
                    Text(verbatim: "✓").font(.bSymbol(15, relativeTo: .subheadline, weight: .bold))
                        .accessibilityHidden(true)
                    Text("Verified").font(.bBody.weight(.semibold))
                }
                .foregroundStyle(Color.ok)
                .padding(Space.s3)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.okBg, in: .rect(cornerRadius: Radius.chip))
                .accessibilityElement(children: .combine)
            } else if model.verified {
                Text("✓ verified · safety code matched").font(.bBody).foregroundStyle(Color.ok)
                SecondaryButton("Remove the verified mark") { Task { await model.undo(); feelFailure() } }
            } else {
                if model.mismatched {
                    // The advice stays once the sheet is closed.
                    Banner(kind: .danger, title: "The numbers do not match",
                           message: "Don't send anything sensitive yet. Compare again in person or on a call you trust.")
                }
                PrimaryButton("The numbers match") { Task { await model.match(); feelFailure() } }
                SecondaryButton("They don't match") {
                    model.mismatch()
                    showsMismatch = true
                }
            }
        }
    }
}

/// "They don't match": what to do now, in words the core backs (nothing is
/// blocked; the person decides). One dismiss, in the toolbar.
private struct MismatchSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.dynamicTypeSize) private var size

    var body: some View {
        NavigationStack {
            Group {
                HStack(alignment: .firstTextBaseline, spacing: Space.s2) {
                    Text(verbatim: "✗").font(.bSymbol(20, relativeTo: .title3, weight: .bold))
                        .foregroundStyle(Color.danger)
                        .accessibilityHidden(true)
                    ScreenTitle("The numbers do not match", size: 22)
                }
                Text("Don't send anything sensitive yet. Compare again in person or on a call you trust.")
                    .font(.bBodyLarge).foregroundStyle(Color.fg)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .barkingScreen()
            .navigationTitle(Text("Safety code"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
        }
        // At AX sizes the copy needs the whole height.
        .presentationDetents(size.isAccessibilitySize ? [.large] : [.medium, .large])
        .presentationBackground(Color.surface)
    }
}

extension SafetyCodeView {
    /// "Saved" only once the core holds the alias; otherwise say so.
    fileprivate func saveAlias() async {
        let wanted = aliasDraft.trimmingCharacters(in: .whitespaces)
        await model.rename(aliasDraft)
        aliasSaved = model.alias == wanted
        aliasFailed = !aliasSaved
        if aliasSaved { AccessibilityNotification.Announcement(String(localized: "Saved")).post() }
    }


    /// The last invitation and its resend (design decision 6). Redrawn each
    /// minute, so "2 h ago" and "Possible in 5 h" keep up with the clock.
    fileprivate var inviteSection: some View {
        TimelineView(.everyMinute) { context in
            VStack(alignment: .leading, spacing: Space.s2) {
                SectionLabel("Invitation")
                inviteState(now: context.date)
                    .font(.bBody).foregroundStyle(Color.fg)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("contact.invite.state")
                if model.inviteAction == .inviteAgain {
                    Text("If \(model.name) deleted you, a new invitation lets them add you back.")
                        .font(.bBodySmall).foregroundStyle(Color.fgMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                resendButton
                if model.resendTooLarge {
                    Banner(kind: .info, title: "Your card is too large for an invitation",
                           message: "Show them your code instead.",
                           action: .init(label: "Show my code", hint: "Opens your code.") { showsMyCode = true })
                        .accessibilityIdentifier("contact.invite.tooLarge")
                } else if model.resendFailed {
                    Banner(kind: .danger, title: "Not sent. Try again in a moment.")
                }
            }
        }
    }

    /// "Invitation sent · 2 h ago", "No answer · sent 8 d ago", "Accepted";
    /// the date in the app's language, as the text around it.
    @ViewBuilder fileprivate func inviteState(now: Date) -> some View {
        let ago = { (at: UInt64) in
            RequestHistory.relative(Date(timeIntervalSince1970: TimeInterval(at)), now: now, locale: locale)
        }
        switch model.invite {
        case .sent(let at): Text("Invitation sent · \(ago(at))")
        case .unanswered(let at): Text("No answer · sent \(ago(at))")
        case .accepted: Text("Accepted")
        case .none: Text("No invitation sent")
        }
    }

    /// Before the delay, the button says when it opens: "Possible in 5 h",
    /// read in words, not only dimmed. VoiceOver hears the action first.
    @ViewBuilder fileprivate var resendButton: some View {
        if let hours = model.hoursUntilRetry {
            SecondaryButton("Possible in \(hours) h", enabled: false) {}
                .accessibilityLabel(Text("Resend the invitation"))
                .accessibilityValue(Text("Possible in \(hours) h"))
                .accessibilityIdentifier("contact.invite.resend")
        } else {
            SecondaryButton(inviteLabel, enabled: !resending) {
                resending = true
                Task {
                    await model.resend()
                    resending = false
                }
            }
            .accessibilityIdentifier("contact.invite.resend")
        }
    }

    fileprivate var inviteLabel: LocalizedStringKey {
        switch model.inviteAction {
        case .send: "Send an invitation"
        case .resend: "Resend the invitation"
        case .inviteAgain: "Invite again"
        }
    }

    /// The contact's devices, with the date each was added to its card.
    fileprivate var devicesSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionLabel("Devices")
            ForEach(model.devices, id: \.id) { d in
                HStack {
                    Text(verbatim: d.name).font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold))
                        .foregroundStyle(Color.fg)
                    Spacer(minLength: 0)
                    Text("added \(Date(timeIntervalSince1970: TimeInterval(d.issuedAt)).formatted(date: .abbreviated, time: .omitted))")
                        .font(.caption).foregroundStyle(Color.fgSoft)
                }
                .frame(minHeight: 36)
                .accessibilityElement(children: .combine)
            }
        }
    }
}
