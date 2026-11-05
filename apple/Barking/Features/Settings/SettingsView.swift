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
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    RemovedBanner(core: core)
                    section("Appearance")
                    AppearanceSegments()
                    card {
                        NavigationLink { DevicesView(core: core) } label: {
                            row("Linked devices", Text("receive, write, send"), "laptopcomputer.and.iphone")
                        }
                        divider
                        NavigationLink { MyIdentityView(core: core, model: model) } label: {
                            row("My identity", Text(verbatim: model.fingerprintShort)
                                .font(BarkingFont.mono(.caption, size: 11.5)), "key")
                        }
                        divider
                        Button(action: openNetwork) {
                            row("Network and relays", Text("Internet"), "dot.radiowaves.left.and.right")
                        }
                    }
                    .padding(.top, 10)
                    card {
                        Button {
                            if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                        } label: {
                            row("Language", Text("\(Self.languageName) · change it in the iPhone's Settings"),
                                "globe", trailing: "arrow.up.forward")
                        }
                        .accessibilityIdentifier("settings.language")
                    }
                    #if BARKING_DEV
                    card {
                        NavigationLink { DevView() } label: { row("Development", Text(verbatim: "BARKING_DEV"), "hammer") }
                    }
                    #endif
                    VStack(spacing: 8) {
                        MadeInFranceChip()
                        Text(verbatim: "Barking \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "") · NakoCorp · AGPL-3.0")
                            .font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgMuted)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.top, 24)
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 16)
            }
            .background(Color.surface)
            .navigationTitle(Text("Settings"))
        }
        .task { await model.load() }
    }

    /// The language the app shows, in that language ("Français", "English").
    static var languageName: String {
        let code = Bundle.main.preferredLocalizations.first ?? "en"
        return Locale(identifier: code).localizedString(forLanguageCode: code)?.localizedCapitalized ?? code
    }

    private func section(_ title: LocalizedStringKey) -> some View {
        Text(title).textCase(.uppercase)
            .font(.system(size: 12, weight: .semibold)).tracking(0.6)
            .foregroundStyle(Color.fgMuted)
            .accessibilityAddTraits(.isHeader)
    }

    private var divider: some View { Rectangle().fill(Color.border).frame(height: 1) }

    private func card<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(spacing: 0, content: content)
            .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
            .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
    }

    private func row(_ title: LocalizedStringKey, _ sub: Text, _ icon: String,
                     trailing: String = "chevron.right") -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon).font(.system(size: 15)).foregroundStyle(Color.accent)
                .frame(width: 32, height: 32)
                .background(Color.wash, in: .rect(cornerRadius: Radius.tile))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 15, weight: .semibold)).foregroundStyle(Color.fg)
                sub.font(.system(size: 12.5)).foregroundStyle(Color.fgMuted)
            }
            Spacer(minLength: 0)
            Image(systemName: trailing).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.fgMuted)
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 56)
        .contentShape(.rect)
    }
}

/// Fingerprint, my code and link, display name.
struct MyIdentityView: View {
    let core: CoreService
    let model: SettingsModel
    @State private var name = ""

    var body: some View {
        Form {
            Section("Display name") {
                TextField("Your name, as contacts see it", text: $name)
                    .onSubmit { Task { await model.rename(name) } }
            }
            Section("Fingerprint") {
                Text(verbatim: model.fingerprint).font(BarkingFont.mono(.footnote, size: 12)).textSelection(.enabled)
            }
            Section("My code") { MyCodeView(core: core) }
        }
        .scrollContentBackground(.hidden)
        .background(Color.surface)
        .navigationTitle(Text("My identity"))
        .task { name = model.displayName }
    }
}

/// Screen 9 of the mockup, without per-device switches.
struct DevicesView: View {
    let core: CoreService
    @State private var model: DevicesModel
    @State private var linking = false
    @State private var transferTarget: MyDeviceInfo?

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: DevicesModel(core: core))
    }

    var body: some View {
        List {
            RemovedBanner(core: core).listRowBackground(Color.clear)
            Text("One identity on several devices.").foregroundStyle(Color.fgMuted)
            ForEach(model.devices, id: \.id) { d in
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(verbatim: d.name).font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold))
                            if d.thisDevice { Text("this device").font(.caption2).foregroundStyle(Color.accent) }
                            if d.admin { Text(verbatim: "admin").font(.caption2).foregroundStyle(Color.fgSoft) }
                            if model.pendingTarget == d.id {
                                Text("Transfer pending").font(.caption2).foregroundStyle(Color.fgSoft)
                            }
                        }
                        Text("added \(Date(timeIntervalSince1970: TimeInterval(d.issuedAt)).formatted(date: .abbreviated, time: .omitted))")
                            .font(.caption).foregroundStyle(Color.fgSoft)
                    }
                    Spacer(minLength: 0)
                    if model.canTransfer(to: d) {
                        Button("Make admin") { transferTarget = d }
                            .font(.caption).buttonStyle(.borderless).foregroundStyle(Color.accent)
                    }
                }
                .frame(minHeight: 44)
            }
            if model.transferFailed {
                Banner(kind: .danger, title: "The transfer could not start. Sync, then try again.")
            }
            if model.canLink {
                PrimaryButton("Link a new device") { linking = true }
                    .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
            } else if model.pendingTarget != nil {
                Text("The admin key is on its way to your other device.").foregroundStyle(Color.fgMuted)
            } else if !model.removed {
                Text("Only your admin device can link new ones").foregroundStyle(Color.fgMuted)
            }
            Text("\(model.count) of 8 devices").font(.caption).foregroundStyle(Color.fgSoft)
        }
        .scrollContentBackground(.hidden)
        .background(Color.surface)
        .navigationTitle(Text("Linked devices"))
        .confirmationDialog("Make admin", isPresented: Binding(
            get: { transferTarget != nil }, set: { if !$0 { transferTarget = nil } }
        ), titleVisibility: .visible, presenting: transferTarget) { d in
            Button("Make admin") { Task { await model.transfer(to: d) } }
        } message: { _ in
            Text("This device will lose the admin key once the transfer is received.")
        }
        .sheet(isPresented: $linking, onDismiss: { Task { await model.load() } }) {
            LinkNewDeviceView(core: core) { linking = false }
        }
        .task { await model.load() }
    }
}
