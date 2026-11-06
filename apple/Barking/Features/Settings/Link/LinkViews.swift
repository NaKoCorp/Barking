import BarkingKit
import SwiftUI

/// On the existing device: offer QR, scan the request, confirm, share the file.
struct LinkNewDeviceView: View {
    let onDone: () -> Void
    @State private var model: LinkModel
    @State private var history = true
    @State private var scanning = false

    init(core: CoreService, onDone: @escaping () -> Void) {
        self.onDone = onDone
        _model = State(initialValue: LinkModel(core: core))
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                switch model.state {
                case .idle:
                    ProgressView()
                case .offer(let offer):
                    if scanning {
                        Text("Scan the new device's code").foregroundStyle(Color.fgMuted)
                        ScannerView { data in Task { await model.scannedRequest(data) } }
                    } else {
                        if let img = QRPayload.image(for: offer, scale: 8) {
                            Image(uiImage: img).interpolation(.none).resizable().scaledToFit()
                                .padding(12).background(Color.white, in: .rect(cornerRadius: Radius.card))
                        }
                        Text("Valid for 10 minutes and usable once.").foregroundStyle(Color.fgMuted)
                        PrimaryButton("Scan the new device's code") { scanning = true }
                    }
                case .confirm(let name):
                    ScreenTitle("Link \(name)?", size: 22)
                    Toggle("Transfer encrypted history", isOn: $history).toggleStyle(CheckboxStyle())
                    PrimaryButton("Link") { Task { await model.accept(history: history) } }
                case .share(let url):
                    Text("Valid for 10 minutes and usable once. Hand the file to the new device over a channel you control.")
                        .foregroundStyle(Color.fgMuted)
                    ShareLink(item: url) {
                        Text("Send the link file")
                    }
                    .buttonStyle(.barkingPrimary)
                case .refused(let text):
                    Banner(kind: .danger, title: LocalizedStringKey(text))
                    PrimaryButton("Start again") { Task { scanning = false; await model.start() } }
                }
                Spacer(minLength: 0)
            }
            .padding(20)
            .background(Color.surface)
            .navigationTitle(Text("Link a new device"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close", action: onDone) } }
        }
        .presentationBackground(Color.surface)
        .task { await model.start() }
        .onDisappear { model.cleanup() }
    }
}

/// On the new device (onboarding): scan the offer, show the request, wait
/// for the `.barkinglink` file.
struct LinkFromExistingView: View {
    @Environment(AppRouter.self) private var router
    @State private var model: NewDeviceLinkModel
    @State private var importing = false

    init(resume: CoreService? = nil) {
        _model = State(initialValue: NewDeviceLinkModel(resume: resume))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            switch model.state {
            case .scanOffer:
                BarkingTextField("This device's name", text: $model.deviceName,
                                 footer: "Shown on your other devices, and to your contacts in your card.",
                                 identifier: "link.deviceName")
                Text("On your other device: Settings, Linked devices, Link a new device. Scan its code.")
                    .font(.bBody).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
                // Linking needs the camera: the other device's code is only a QR (U-13).
                ScannerView(onBytes: { data in Task { await model.scannedOffer(data) } },
                            unavailable: "The camera is not available. Linking needs it to scan your other device's code.")
            case .request(let request):
                Text("Scan this code with your other device.").foregroundStyle(Color.fgMuted)
                if let img = QRPayload.image(for: request, scale: 5) {
                    Image(uiImage: img).interpolation(.none).resizable().scaledToFit()
                        .padding(12).background(Color.white, in: .rect(cornerRadius: Radius.card))
                }
                Text("Waiting for your other device").font(BarkingFont.mono(.footnote, size: 13))
                    .foregroundStyle(Color.fgSoft)
                SecondaryButton("Open the link file") { importing = true }
            case .waiting:
                Text("Waiting for your other device").font(BarkingFont.mono(.footnote, size: 13))
                    .foregroundStyle(Color.fgSoft)
                SecondaryButton("Open the link file") { importing = true }
                Button("Start again") { Task { await model.startAgain(); router.restartOnboarding() } }
                    .foregroundStyle(Color.accent).frame(minHeight: 44)
            case .done:
                ProgressView()
            case .refused(let text):
                Banner(kind: .danger, title: LocalizedStringKey(text))
                PrimaryButton("Start again") { Task { await model.startAgain() } }
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .background(Color.surface)
        .navigationTitle(Text("Link to an existing device"))
        .fileImporter(isPresented: $importing, allowedContentTypes: [.barkingLink, .data]) { result in
            if case .success(let url) = result { Task { await receive(url) } }
        }
        .onChange(of: router.pendingLinkFile, initial: true) { _, url in
            if let url = router.takePendingLinkFile() { Task { await receive(url) } }
        }
        .onChange(of: model.state) { _, s in
            if s == .done, let core = model.core { router.becomeReady(core: core) }
        }
    }

    private func receive(_ url: URL) async {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        // A link file is at most the core's bundle limit plus the history.
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size <= 8 * 1024 * 1024, let data = try? Data(contentsOf: url) else { return }
        await model.received(package: data)
    }
}
