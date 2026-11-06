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
    @State private var showsMismatch = false
    @Environment(\.dismiss) private var dismiss

    init(core: CoreService, contact: String) {
        self.core = core
        _model = State(initialValue: ContactModel(contact: contact, core: core))
    }

    var body: some View {
        Group {
            VStack(alignment: .leading, spacing: Space.s3) {
                Avatar(name: model.name, fingerprint: model.contact, size: 64)
                ScreenTitle("Compare with \(model.name)", size: 22)
                Text("Read the numbers aloud, in person or on a call you trust. If they match, nobody sits between you.")
                    .font(.bBody).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
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
            if !model.devices.isEmpty { devicesSection }
            DangerZone {
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
        .task { await model.load(); aliasDraft = model.alias }
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
        .confirmationDialog(Text("Delete this contact? The history is kept."), isPresented: $confirmDelete,
                            titleVisibility: .visible) {
            Button("Delete", role: .destructive) { deleted = true; Task { await model.delete(); dismiss() } }
        }
        .sheet(isPresented: $showsMismatch) { MismatchSheet() }
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
