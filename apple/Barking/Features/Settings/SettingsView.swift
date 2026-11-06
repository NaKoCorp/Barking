import BarkingKit
import SwiftUI

/// Screen 8 of the mockup. The language is the phone's: the row opens
/// the iPhone's Settings › Barking, where iOS offers a per-app language.
struct SettingsView: View {
    let core: CoreService
    let openNetwork: () -> Void
    @Environment(\.openURL) private var openURL
    @State private var model: SettingsModel

    init(core: CoreService, openNetwork: @escaping () -> Void = {}) {
        self.core = core
        self.openNetwork = openNetwork
        _model = State(initialValue: SettingsModel(core: core))
    }

    var body: some View {
        NavigationStack {
            Group {
                RemovedBanner(core: core)
                VStack(alignment: .leading, spacing: Space.s2) {
                    SectionLabel("Appearance")
                    AppearanceSegments()
                }
                FormCard {
                    NavigationLink { DevicesView(core: core) } label: {
                        FormRow("Linked devices", subtitle: "receive, write, send", icon: "laptopcomputer.and.iphone") { RowGlyph() }
                    }
                    NavigationLink { MyIdentityView(core: core, model: model) } label: {
                        FormRow(title: Text("My identity"),
                                subtitle: Text(verbatim: model.fingerprintShort).font(.bMeta)
                                    .accessibilityLabel(Text(verbatim: FingerprintFormat.spoken(model.fingerprint, form: .short))),
                                icon: "key") { RowGlyph() }
                    }
                    NavigationLink { SecuritySettingsView() } label: {
                        FormRow("Security", subtitle: "Lock and erase", icon: "lock") { RowGlyph() }
                    }
                    NavigationLink { TransparencyView(core: core) } label: {
                        FormRow("Transparency", subtitle: "What this phone did, and who could see it", icon: "eye") { RowGlyph() }
                    }
                    .accessibilityIdentifier("settings.transparency")
                    Button(action: openNetwork) {
                        FormRow("Network and relays", subtitle: "Internet", icon: "dot.radiowaves.left.and.right") { RowGlyph() }
                    }
                }
                FormCard {
                    Button {
                        if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                    } label: {
                        FormRow(title: Text("Language"),
                                subtitle: Text("\(Self.languageName) · change it in the iPhone's Settings"),
                                icon: "globe") { RowGlyph(symbol: "arrow.up.forward") }
                    }
                    .accessibilityIdentifier("settings.language")
                }
                #if BARKING_DEV
                FormCard {
                    NavigationLink { DevView() } label: {
                        FormRow(title: Text("Development"), subtitle: Text(verbatim: "BARKING_DEV"), icon: "hammer") { RowGlyph() }
                    }
                }
                #endif
                VStack(spacing: Space.s2) {
                    MadeInFranceChip()
                    Text(verbatim: "Barking \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "") · NakoCorp · AGPL-3.0")
                        .font(.bMeta).foregroundStyle(Color.fgMuted)
                }
                .frame(maxWidth: .infinity)
            }
            .barkingScreen(tabRoot: true)
            .navigationTitle(Text("Settings"))
        }
        .task { await model.load() }
    }

    /// The language the app shows, in that language ("Français", "English").
    static var languageName: String {
        let code = Bundle.main.preferredLocalizations.first ?? "en"
        return Locale(identifier: code).localizedString(forLanguageCode: code)?.localizedCapitalized ?? code
    }
}

/// Fingerprint, my code and link, display name.
struct MyIdentityView: View {
    let core: CoreService
    let model: SettingsModel
    @State private var name = ""
    @State private var editing = false
    @State private var saved = false
    @State private var failed = false

    var body: some View {
        Group {
            VStack(alignment: .leading, spacing: Space.s2) {
                if editing {
                    BarkingTextField("Your name", text: $name,
                                     footer: "Your name travels in your contact card. No phone number, no email.",
                                     error: failed ? "Not saved. Try again." : nil,
                                     identifier: "identity.name", onSubmit: save)
                        .textContentType(.name)
                        .submitLabel(.done)
                    HStack(spacing: Space.s3) {
                        SecondaryButton("Cancel") { editing = false }
                        PrimaryButton("Save", enabled: SettingsModel.validName(name) != nil, action: save)
                    }
                } else {
                    SectionLabel("Your name")
                    FormCard {
                        FormRow(title: Text(verbatim: model.displayName)) {
                            TextLink("Edit") {
                                name = model.displayName
                                saved = false
                                failed = false
                                editing = true
                            }
                            .accessibilityIdentifier("identity.edit")
                        }
                    }
                    if saved {
                        HStack(spacing: Space.s1) {
                            Text(verbatim: "✓").font(.bSymbol(12, relativeTo: .caption, weight: .bold))
                                .accessibilityHidden(true)
                            Text("Saved").font(.bMeta)
                        }
                        .foregroundStyle(Color.ok)
                    }
                }
            }
            VStack(alignment: .leading, spacing: Space.s2) {
                SectionLabel("Fingerprint")
                Card { FingerprintText(model.fingerprint, form: .full) }
            }
            VStack(alignment: .leading, spacing: Space.s2) {
                SectionLabel("My code")
                MyCodeView(core: core, shareInToolbar: true)
            }
        }
        .barkingScreen()
        .navigationTitle(Text("My identity"))
    }

    /// "Saved" only once the core holds the new name.
    private func save() {
        guard let wanted = SettingsModel.validName(name) else { return }
        Task {
            await model.rename(wanted)
            saved = model.displayName == wanted
            failed = !saved
            if saved {
                editing = false
                AccessibilityNotification.Announcement(String(localized: "Saved")).post()
            }
        }
    }
}

/// Screen 9 of the mockup, without per-device switches: linking, the admin
/// transfer, removing a device, and disconnecting this one (spec §8.2).
struct DevicesView: View {
    let core: CoreService
    @Environment(AppRouter.self) private var router
    @State private var model: DevicesModel
    @State private var linking = false
    @State private var transferTarget: MyDeviceInfo?
    @State private var removeTarget: MyDeviceInfo?
    @State private var confirmingLeave = false
    @State private var confirmingErase = false
    @State private var choosingSuccessor = false
    @State private var successor: MyDeviceInfo?

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: DevicesModel(core: core))
    }

    var body: some View {
        Group {
            RemovedBanner(core: core)
            VStack(alignment: .leading, spacing: Space.s3) {
                Text("One identity on several devices.").font(.bBody).foregroundStyle(Color.fgMuted)
                FormCard {
                    ForEach(model.devices, id: \.id) { d in deviceRow(d) }
                }
                Text("\(model.count) of 8 devices").font(.bMeta).foregroundStyle(Color.fgSoft)
            }
            if model.transferFailed {
                Banner(kind: .danger, title: "The transfer could not start. Sync, then try again.")
            }
            if model.removeFailed {
                Banner(kind: .danger, title: "The removal could not start. Sync, then try again.")
            }
            departureRow
            if model.canLink {
                PrimaryButton("Link a new device") { linking = true }
            } else if model.pendingTarget != nil, model.departure == .idle {
                Text("The admin key is on its way to your other device.").font(.bBody).foregroundStyle(Color.fgMuted)
            } else if !model.removed, model.departure == .idle {
                Text("Only your admin device can link new ones").font(.bBody).foregroundStyle(Color.fgMuted)
            }
            if let me = model.devices.first(where: \.thisDevice), model.canDisconnect(me) {
                // B3 (U-2) moves this into a danger zone.
                Button("Disconnect this device", role: .destructive) { startDisconnect() }
                    .frame(maxWidth: .infinity, minHeight: 44)
                    .accessibilityIdentifier("devices.disconnect")
            }
        }
        .barkingScreen()
        .navigationTitle(Text("Linked devices"))
        .confirmationDialog("Make admin", isPresented: present($transferTarget),
                            titleVisibility: .visible, presenting: transferTarget) { d in
            Button("Make admin") { Task { await model.transfer(to: d) } }
        } message: { _ in
            Text("This device will lose the admin key once the transfer is received.")
        }
        .confirmationDialog(Text(verbatim: ""), isPresented: present($removeTarget),
                            titleVisibility: .hidden, presenting: removeTarget) { d in
            Button("Remove \(d.name)", role: .destructive) { Task { await model.remove(d) } }
        } message: { d in
            Text("\(d.name) will no longer receive or send your messages.")
        }
        .confirmationDialog(Text(verbatim: Self.disconnectTitle(myName)), isPresented: $confirmingLeave,
                            titleVisibility: .visible) {
            Button("Disconnect this device", role: .destructive) { Task { await model.disconnect() } }
        } message: {
            Text("Your other devices will remove this one, then everything on this iPhone will be erased.")
        }
        .confirmationDialog("Erase", isPresented: $confirmingErase, titleVisibility: .visible) {
            Button("Erase", role: .destructive) { Task { await model.disconnect() } }
        } message: {
            Text("Everything on this iPhone will be erased. Your contacts will not be told. To get your identity back, you will need the 24-word phrase.")
        }
        .confirmationDialog(Text(verbatim: ""), isPresented: present($successor),
                            titleVisibility: .hidden, presenting: successor) { d in
            Button("Hand over to \(d.name) and disconnect", role: .destructive) {
                Task { await model.handOver(to: d) }
            }
        } message: { d in
            Text("\(d.name) receives the admin key, then removes this device. Everything on this iPhone will then be erased.")
        }
        .sheet(isPresented: $choosingSuccessor) { successorSheet }
        .sheet(isPresented: $linking, onDismiss: { Task { await model.load() } }) {
            LinkNewDeviceView(core: core) { linking = false }
        }
        .task { await model.load() }
        .task(id: model.departure) {
            // Waits for the ack of the root key, every few seconds.
            while case .handingOver = model.departure, !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                guard !Task.isCancelled else { return }
                await model.pollHandover()
            }
        }
        .onChange(of: model.departure) { _, now in
            if now == .wiped { router.restartOnboarding() }
        }
    }

    /// Name, tags ("this device", "admin", "Transfer pending"), the date it
    /// was added, and what can be done with it.
    private func deviceRow(_ d: MyDeviceInfo) -> some View {
        HStack(alignment: .center, spacing: Space.s3) {
            VStack(alignment: .leading, spacing: Space.s1) {
                Text(verbatim: d.name).font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold))
                    .foregroundStyle(Color.fg)
                if d.thisDevice || d.admin || model.pendingTarget == d.id {
                    FlowLayout {
                        if d.thisDevice { Tag("this device", style: .accent) }
                        if d.admin { Tag(verbatim: "admin") }
                        if model.pendingTarget == d.id { Tag("Transfer pending") }
                    }
                }
                Text("added \(Date(timeIntervalSince1970: TimeInterval(d.issuedAt)).formatted(date: .abbreviated, time: .omitted))")
                    .font(.bMeta).foregroundStyle(Color.fgSoft)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            if model.canTransfer(to: d) {
                TextLink("Make admin") { transferTarget = d }
            }
            if model.canRemove(d) {
                Button(role: .destructive) { removeTarget = d } label: {
                    Text("Remove").font(BarkingFont.mono(.footnote, size: 13, weight: .medium))
                        .foregroundStyle(Color.danger)
                        .frame(minWidth: 44, minHeight: 44)
                        .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("devices.remove.\(d.id)")
            }
        }
        .padding(.horizontal, FormRowMetrics.inset)
        .padding(.vertical, Space.s2)
        .frame(minHeight: FormRowMetrics.minHeight(hasSubtitle: true))
    }

    @ViewBuilder private var departureRow: some View {
        switch model.departure {
        case .idle, .wiped:
            EmptyView()
        case .handingOver(let name):
            HStack(spacing: 10) {
                ProgressView()
                Text("Handing over to \(name)…").foregroundStyle(Color.fgMuted)
            }
            .accessibilityElement(children: .combine)
        case .handoverFailed(let name):
            VStack(alignment: .leading, spacing: 8) {
                Banner(kind: .danger, title: "The handover to \(name) did not finish. Nothing was erased: this device is still your admin.")
                Button("OK") { model.dismissDeparture() }.frame(minHeight: 44)
            }
        case .sending:
            HStack(spacing: 10) {
                ProgressView()
                Text("Sending the request to your other devices…").foregroundStyle(Color.fgMuted)
            }
            .accessibilityElement(children: .combine)
        case .notSent:
            VStack(alignment: .leading, spacing: 8) {
                Banner(kind: .danger, title: "The request has not left this iPhone yet. Nothing was erased: try again.")
                Button("Try again") { Task { await model.finishLeaving() } }.frame(minHeight: 44)
            }
        case .wipeFailed:
            VStack(alignment: .leading, spacing: 8) {
                Banner(kind: .danger, title: "Barking could not erase everything. Try again.")
                Button("Try again") { Task { await model.retryWipe() } }.frame(minHeight: 44)
            }
        case .failed:
            VStack(alignment: .leading, spacing: 8) {
                Banner(kind: .danger, title: "Something went wrong. Your data is safe.")
                Button("OK") { model.dismissDeparture() }.frame(minHeight: 44)
            }
        }
    }

    private var successorSheet: some View {
        NavigationStack {
            List {
                Text("It receives the admin key, then removes this device.").foregroundStyle(Color.fgMuted)
                if case .handOver(let candidates) = model.disconnectPlan {
                    ForEach(candidates, id: \.id) { d in
                        Button {
                            choosingSuccessor = false
                            successor = d
                        } label: {
                            Text(verbatim: d.name).font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold))
                                .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                        }
                    }
                }
            }
            .navigationTitle(Text("Choose the next admin"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { choosingSuccessor = false } }
            }
        }
        .presentationDetents([.medium])
    }

    /// The confirmation names the device (spec §8.2).
    static func disconnectTitle(_ name: String) -> String { String(localized: "Disconnect \(name)?") }

    private var myName: String {
        model.devices.first(where: \.thisDevice)?.name ?? String(localized: "This device")
    }

    private func startDisconnect() {
        switch model.disconnectPlan {
        case .leave: confirmingLeave = true
        case .erase: confirmingErase = true
        case .handOver: choosingSuccessor = true
        }
    }

    private func present<T>(_ item: Binding<T?>) -> Binding<Bool> {
        Binding(get: { item.wrappedValue != nil }, set: { if !$0 { item.wrappedValue = nil } })
    }
}
