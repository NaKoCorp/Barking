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
            // Scrolls: at accessibility sizes the steps, the code and the
            // button are taller than the sheet.
            Group {
                switch model.state {
                case .idle:
                    ProgressView().frame(maxWidth: .infinity)
                case .offer(let offer):
                    if scanning {
                        Text("Scan the new device's code").font(.bBody).foregroundStyle(Color.fgMuted)
                        ScannerView { data in Task { await model.scannedRequest(data) } }
                    } else {
                        LinkOfferPanel(offer: offer, onScan: { scanning = true },
                                       onNewCode: { Task { await model.start() } })
                    }
                case .confirm(let name):
                    ScreenTitle("Link \(name)?", size: 22)
                    Toggle("Transfer encrypted history", isOn: $history).toggleStyle(CheckboxStyle())
                    PrimaryButton("Link") { Task { await model.accept(history: history) } }
                case .share(let url):
                    Text("Valid for 10 minutes and usable once. Hand the file to the new device over a channel you control.")
                        .font(.bBody).foregroundStyle(Color.fgMuted)
                    ShareLink(item: url) {
                        Text("Send the link file")
                    }
                    .buttonStyle(.barkingPrimary)
                case .refused(let text):
                    Banner(kind: .danger, title: LocalizedStringKey(text))
                    PrimaryButton("Start again") { Task { scanning = false; await model.start() } }
                }
            }
            .barkingScreen()
            // Its own short title: « Lier un nouvel appareil » truncated in the
            // inline bar at AX3 (review B5 #3). The button keeps the long one.
            .navigationTitle(Text("Link a device"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close", action: onDone) } }
        }
        .presentationBackground(Color.surface)
        .task { await model.start() }
        .onDisappear { model.cleanup() }
    }
}

/// The offer (U-28): two numbered steps, the code, the time it has left
/// (a live mm:ss, or a fixed "valid until" under Reduce Motion) and, once it
/// has expired, a new code instead of the scan button.
private struct LinkOfferPanel: View {
    let offer: Data
    let onScan: () -> Void
    let onNewCode: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s3) {
            LinkStep(1, "On the new device, tap Link to an existing device and scan this code.")
            LinkStep(2, "Then tap Scan the new device's code and scan the code it shows.")
        }
        if let expiry = LinkOfferExpiry.date(of: offer) {
            if reduceMotion {
                // Redrawn once, when the offer expires: nothing ticks.
                TimelineView(.explicit([expiry])) { _ in
                    content(LinkCountdown.of(now: Date(), expiry: expiry, reduceMotion: true))
                }
            } else {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    content(LinkCountdown.of(now: context.date, expiry: expiry, reduceMotion: false))
                }
            }
        } else {
            code
            Text("Valid for 10 minutes and usable once.").font(.bBody).foregroundStyle(Color.fgMuted)
            PrimaryButton("Scan the new device's code", action: onScan)
        }
    }

    @ViewBuilder private func content(_ countdown: LinkCountdown) -> some View {
        VStack(spacing: Space.section) {
            switch countdown {
            case .live(let clock):
                code
                line(Text("Expires in \(clock) · usable once"))
                PrimaryButton("Scan the new device's code", action: onScan)
            case .until(let date):
                code
                line(Text("Valid until \(date, format: .dateTime.hour().minute()) and usable once."))
                PrimaryButton("Scan the new device's code", action: onScan)
            case .expired:
                Banner(kind: .info, title: "This code has expired.")
                PrimaryButton("New code", action: onNewCode)
            }
        }
    }

    private func line(_ text: Text) -> some View {
        text.font(BarkingFont.mono(.footnote, size: 13)).foregroundStyle(Color.fgMuted)
            .monospacedDigit()
            .frame(maxWidth: .infinity)
    }

    @ViewBuilder private var code: some View {
        if let img = QRPayload.image(for: offer, scale: 8) {
            Image(uiImage: img).interpolation(.none).resizable().scaledToFit()
                .frame(maxWidth: 320)
                .padding(12).background(Color.white, in: .rect(cornerRadius: Radius.card))
                .frame(maxWidth: .infinity)
                .accessibilityLabel(Text("Link code. The new device scans it."))
                .accessibilityIdentifier("link.code")
        }
    }
}

/// One numbered step, read as one line by VoiceOver.
private struct LinkStep: View {
    let number: Int
    let text: LocalizedStringKey
    init(_ number: Int, _ text: LocalizedStringKey) { self.number = number; self.text = text }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Space.s2) {
            Text(verbatim: "\(number).").font(BarkingFont.mono(.subheadline, size: 15, weight: .semibold))
                .foregroundStyle(Color.accent)
            Text(text).font(.bBody).foregroundStyle(Color.fgMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
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
        // Scrolls like the other forms: at AX sizes the field, its footer, the
        // steps and the camera are taller than the screen.
        Group {
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
                Text("Scan this code with your other device.").font(.bBody).foregroundStyle(Color.fgMuted)
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
        }
        .barkingScreen()
        // Short: the full "Link to an existing device" truncated in the
        // inline bar at AX3 (UI review B5 carry).
        .navigationTitle(Text("Link this device"))
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
