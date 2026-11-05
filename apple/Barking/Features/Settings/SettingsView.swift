import BarkingKit
import SwiftUI

/// Screen 8 of the mockup.
struct SettingsView: View {
    let core: CoreService
    @Environment(AppSettings.self) private var settings
    @State private var model: SettingsModel

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: SettingsModel(core: core))
    }

    var body: some View {
        @Bindable var settings = settings
        NavigationStack {
            Form {
                Section("Language") {
                    Picker(selection: $settings.language) {
                        Text("System").tag(AppLanguage.system)
                        Text(verbatim: "English").tag(AppLanguage.english)
                        Text(verbatim: "Français").tag(AppLanguage.french)
                    } label: { EmptyView() }
                    .pickerStyle(.segmented)
                }
                Section("Appearance") {
                    Picker(selection: $settings.appearance) {
                        Text("System").tag(AppAppearance.system)
                        Text("Light").tag(AppAppearance.light)
                        Text("Dark").tag(AppAppearance.dark)
                    } label: { EmptyView() }
                    .pickerStyle(.segmented)
                }
                Section {
                    NavigationLink { DevicesView(core: core) } label: {
                        row("Linked devices", Text("receive, write, send"), "iphone")
                    }
                    NavigationLink { MyIdentityView(core: core, model: model) } label: {
                        row("My identity", Text(verbatim: model.fingerprintShort), "person.text.rectangle")
                    }
                }
                #if BARKING_DEV
                Section { NavigationLink("Development") { DevView() } }
                #endif
                Section {
                    Text(verbatim: "Barking \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "") · NakoCorp · AGPL-3.0")
                        .font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgSoft)
                    Text("Made in France").font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgSoft)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Color.surface)
            .navigationTitle(Text("Settings"))
        }
        .task { await model.load() }
    }

    private func row(_ title: LocalizedStringKey, _ sub: Text, _ icon: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon).foregroundStyle(Color.accent).frame(width: 32, height: 32)
                .background(Color.wash, in: .rect(cornerRadius: Radius.tile))
            VStack(alignment: .leading) {
                Text(title).foregroundStyle(Color.fg)
                sub.font(.caption).foregroundStyle(Color.fgSoft)
            }
        }
        .frame(minHeight: 56)
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

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: DevicesModel(core: core))
    }

    var body: some View {
        List {
            Text("One identity on several devices.").foregroundStyle(Color.fgMuted)
            ForEach(Array(model.devices.enumerated()), id: \.offset) { _, d in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(verbatim: d.name).font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold))
                        if d.thisDevice { Text("this device").font(.caption2).foregroundStyle(Color.accent) }
                        if d.admin { Text(verbatim: "admin").font(.caption2).foregroundStyle(Color.fgSoft) }
                    }
                    Text("added \(Date(timeIntervalSince1970: TimeInterval(d.issuedAt)).formatted(date: .abbreviated, time: .omitted))")
                        .font(.caption).foregroundStyle(Color.fgSoft)
                }
                .frame(minHeight: 44)
            }
            if model.canLink {
                PrimaryButton("Link a new device") { linking = true }
                    .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
            } else {
                Text("Only your first device can link new ones").foregroundStyle(Color.fgMuted)
            }
            Text("\(model.count) of 8 devices").font(.caption).foregroundStyle(Color.fgSoft)
        }
        .scrollContentBackground(.hidden)
        .background(Color.surface)
        .navigationTitle(Text("Linked devices"))
        .sheet(isPresented: $linking, onDismiss: { Task { await model.load() } }) {
            LinkNewDeviceView(core: core) { linking = false }
        }
        .task { await model.load() }
    }
}
