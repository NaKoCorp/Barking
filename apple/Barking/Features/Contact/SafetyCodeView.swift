import BarkingKit
import SwiftUI

/// Screen 6 of the mockup, plus renaming and deleting the contact.
struct SafetyCodeView: View {
    let core: CoreService
    @State private var model: ContactModel
    @State private var aliasDraft = ""
    @State private var aliasSaved = false
    @State private var aliasFailed = false
    /// Set once the contact is deleted: leaving then saves nothing.
    @State private var deleted = false
    @State private var confirmDelete = false
    @Environment(\.dismiss) private var dismiss

    init(core: CoreService, contact: String) {
        self.core = core
        _model = State(initialValue: ContactModel(contact: contact, core: core))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Avatar(name: model.name, fingerprint: model.contact, size: 64)
                ScreenTitle("Compare with \(model.name)", size: 22)
                Text("Read the numbers aloud, in person or on a call you trust. If they match, nobody sits between you.")
                    .font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fgMuted)
                CodeGrid(groups: model.groups)
                HStack {
                    Rectangle().fill(Color.border).frame(height: 1)
                    Text("fingerprint").font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgSoft)
                    Rectangle().fill(Color.border).frame(height: 1)
                }
                FingerprintText(model.contact).frame(maxWidth: .infinity)
                Text("The same code shows on all your linked devices: verifying here is enough.")
                    .font(BarkingFont.sans(.footnote, size: 13)).foregroundStyle(Color.fgSoft)
                if model.justVerified {
                    HStack {
                        Text("✓ Contact marked as verified").foregroundStyle(Color.ok)
                        Spacer()
                        Button("Undo") { Task { await model.undo() } }.foregroundStyle(Color.accent)
                    }
                    .padding(12).background(Color.okBg, in: .rect(cornerRadius: Radius.chip))
                } else if model.verified {
                    Text("✓ verified · safety code matched").foregroundStyle(Color.ok)
                    SecondaryButton("Remove the verified mark") { Task { await model.undo() } }
                } else {
                    PrimaryButton("The numbers match") { Task { await model.match() } }
                    SecondaryButton("They don't match") { model.mismatch() }
                }
                if model.mismatched {
                    Banner(kind: .danger, title: "Do not trust this contact until you meet")
                }
                if !model.devices.isEmpty { devicesSection }
                Divider().padding(.vertical, 8)
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
                Button(role: .destructive) { confirmDelete = true } label: {
                    Text("Delete this contact").frame(maxWidth: .infinity, minHeight: 44)
                }
            }
            .padding(24)
        }
        .background(Color.surface)
        // Kept: with an empty title iOS 26 draws no bar behind the back button,
        // and the scrolled content runs under the status bar unblurred.
        .navigationTitle(Text("Safety code"))
        .toolbarTitleDisplayMode(.inline)
        .task { await model.load(); aliasDraft = model.alias }
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
        .padding(.top, 8)
    }
}
