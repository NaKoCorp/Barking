#if BARKING_DEV
import BarkingKit
import SwiftUI
import UniformTypeIdentifiers
import UserNotifications

/// Development screen (spec iOS foundations §5.4): throwaway, replaced by the
/// interface of block 2. Debug and Bench builds only.
@MainActor @Observable
final class DevModel {
    var device: Device?
    var fingerprint = ""
    var recoveryPhrase: String?
    var contacts: [Contact] = []
    var selected: String?
    var messages: [Message] = []
    var status = ""

    func load() async {
        await attempt("open") {
            guard let d = try DeviceFactory.openExisting(lockTimeoutMs: 10_000) else { return }
            self.device = d
            try await self.refresh()
        }
    }

    func create(name: String) async {
        await attempt("create") {
            let created = try await DeviceCall.run("create") { try DeviceFactory.createNew(deviceName: name) }
            self.device = created.device
            self.recoveryPhrase = created.recoveryPhrase
            try await self.refresh()
        }
    }

    func refresh() async throws {
        guard let d = device else { return }
        fingerprint = try await DeviceCall.run("fingerprint") { try d.fingerprint() }
        contacts = try await DeviceCall.run("contacts") { try d.contacts() }
        if let c = selected {
            messages = try await DeviceCall.run("messages") { try d.messagesWith(contact: c) }
        }
    }

    func cardFile(displayName: String) async -> URL? {
        guard let d = device else { return nil }
        var url: URL?
        await attempt("card") {
            let card = try await DeviceCall.run("card") { try d.contactCard(displayName: displayName) }
            let file = FileManager.default.temporaryDirectory.appending(path: "\(displayName).barkingcard")
            try Data(card.utf8).write(to: file)
            url = file
        }
        return url
    }

    func importCard(from url: URL, alias: String) async {
        guard let d = device else { return }
        await attempt("import") {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let card = try String(contentsOf: url, encoding: .utf8)
            let a = alias.isEmpty ? nil : alias
            _ = try await DeviceCall.run("add") { try d.addContact(card: card, alias: a) }
            try await self.refresh()
        }
    }

    func addNode(id: String, addr: String) async {
        guard let d = device else { return }
        await attempt("node") { try await DeviceCall.run("node") { try d.addNode(id: id, addr: addr) } }
    }

    func send(_ text: String) async {
        guard let d = device, let c = selected else { return }
        await attempt("send") {
            try await DeviceCall.run("send") { try d.sendText(contact: c, text: text) }
            try await self.refresh()
        }
    }

    func sync() async {
        guard let d = device else { return }
        await attempt("sync") {
            let s = try await DeviceCall.run("sync") { try d.sync(deadlineMs: 30_000) }
            self.status = "sync: \(s.itemsReceived) items, \(s.newMessages.count) new, network \(s.networkUp ? "up" : "down")"
            try await self.refresh()
        }
    }

    private func attempt(_ what: String, _ body: () async throws -> Void) async {
        do { try await body() } catch { status = "\(what) failed: \(error)" }
    }
}

struct DevView: View {
    @State private var model = DevModel()
    @State private var name = "iPhone"
    @State private var alias = ""
    @State private var nodeId = ""
    @State private var nodeAddr = ""
    @State private var text = ""
    @State private var card: URL?
    @State private var importing = false
    private let token = PushToken.shared

    var body: some View {
        NavigationStack {
            Form {
                if model.device == nil {
                    Section("Identity") {
                        TextField("Device name", text: $name)
                        Button("Create identity") { Task { await model.create(name: name) } }
                    }
                } else {
                    Section("Identity") {
                        Text(model.fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                        if let phrase = model.recoveryPhrase {
                            Text(phrase).font(.caption).textSelection(.enabled)
                        }
                    }
                    Section("Card") {
                        if let card { ShareLink("Share my card", item: card) }
                        else { Button("Prepare my card") { Task { card = await model.cardFile(displayName: name) } } }
                        TextField("Alias for the imported contact", text: $alias)
                        Button("Import a card") { importing = true }
                    }
                    Section("Node") {
                        TextField("Identifier", text: $nodeId).autocorrectionDisabled()
                        TextField("ip:port", text: $nodeAddr).autocorrectionDisabled()
                        Button("Add node") { Task { await model.addNode(id: nodeId, addr: nodeAddr) } }
                    }
                    Section("Conversation") {
                        Picker("Contact", selection: $model.selected) {
                            Text("None").tag(String?.none)
                            ForEach(model.contacts, id: \.fingerprint) { c in
                                Text(c.alias ?? c.displayName).tag(Optional(c.fingerprint))
                            }
                        }
                        .onChange(of: model.selected) { Task { try? await model.refresh() } }
                        ForEach(Array(model.messages.enumerated()), id: \.offset) { _, m in
                            Text("\(m.outgoing ? "→" : "←") \(m.body)  [\(m.status)]")
                        }
                        TextField("Text", text: $text)
                        Button("Send") { Task { await model.send(text); text = "" } }
                        Button("Sync") { Task { await model.sync() } }
                    }
                    Section("Bench") { BenchSection(device: model.device) }
                }
                Section("APNs token") {
                    Text(token.hex ?? token.failure ?? "not registered yet").font(.caption.monospaced()).textSelection(.enabled)
                    if let hex = token.hex { Button("Copy") { UIPasteboard.general.string = hex } }
                }
                if !model.status.isEmpty { Section("Status") { Text(model.status) } }
            }
            .navigationTitle("Barking (dev)")
            .fileImporter(isPresented: $importing, allowedContentTypes: [.data, .plainText]) { result in
                if case .success(let url) = result { Task { await model.importCard(from: url, alias: alias) } }
            }
            .task {
                _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound])
                await model.load()
            }
        }
    }
}

/// Filled by the bench work (spec §6.2).
struct BenchSection: View {
    let device: Device?
    var body: some View { Text("Bench: not available yet") }
}
#endif
