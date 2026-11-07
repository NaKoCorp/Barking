import BarkingKit
import SwiftUI
import VisionKit

/// Add a contact (spec §5.3): scan a QR code, or show mine; a link opens the
/// confirmation directly.
struct AddContactView: View {
    let core: CoreService
    let link: String?
    let onDone: () -> Void
    @State private var model: AddContactModel
    @State private var tab = 0
    @State private var alias = ""

    init(core: CoreService, link: String?, onDone: @escaping () -> Void) {
        self.core = core
        self.link = link
        self.onDone = onDone
        _model = State(initialValue: AddContactModel(core: core))
    }

    var body: some View {
        NavigationStack {
            Group {
                if let p = model.preview {
                    confirmation(p)
                } else {
                    VStack(spacing: Space.s4) {
                        BarkingSegmented("Add a contact", selection: $tab, options: [(0, LocalizedStringKey("Scan")), (1, LocalizedStringKey("My code"))],
                                         labelAtAXSizes: true)
                        if let e = model.error { errorText(e) }
                        if tab == 0 {
                            ScannerView(onBytes: { data in Task { await model.scanned(data) } },
                                        onText: { s in Task { await model.scannedText(s) } })
                        } else {
                            ScrollView { MyCodeView(core: core) }
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, Space.gutter)
                    .padding(.top, Space.s2)
                    .background(Color.surface)
                }
            }
            // A short inline title, never an empty one (iOS 26 then draws no
            // bar behind the toolbar): the confirmation's headline is the name.
            .navigationTitle(Text("Add a contact"))
            .toolbarTitleDisplayMode(.inline)
            .toolbar {
                // One dismiss control (U-29): Cancel discards a pending add.
                ToolbarItem(placement: .cancellationAction) {
                    if model.preview == nil { Button("Close", action: onDone) } else { Button("Cancel", action: onDone) }
                }
            }
        }
        .presentationBackground(Color.surface)
        .task { if let link { await model.opened(link: link) } }
    }

    private func errorText(_ e: AddContactModel.AddError) -> some View {
        let text: LocalizedStringKey = switch e {
        case .notACard: "This is not a Barking card"
        case .ownCard: "This is your own card"
        case .failed: "Something went wrong. Your data is safe."
        }
        return Text(text).font(.bBodySmall).foregroundStyle(Color.danger).frame(maxWidth: .infinity, alignment: .leading)
    }

    private func confirmation(_ p: CardPreview) -> some View {
        Group {
            VStack(alignment: .leading, spacing: Space.s3) {
                Avatar(name: p.displayName, fingerprint: p.fingerprint, size: 64)
                ScreenTitle(verbatim: p.displayName, size: 22)
                FingerprintText(p.fingerprint)
                Text("After adding, compare the safety code with \(p.displayName) to be sure it is them.")
                    .font(.bBody).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            BarkingTextField("Alias (optional)", text: $alias, identifier: "addContact.alias")
            if let e = model.error { errorText(e) }
        }
        .barkingScreen()
        .ctaBar {
            // One add at a time (review final #14): the spinner shows, and a
            // second tap while it runs is ignored.
            PrimaryButton("Add", isLoading: model.isAdding) {
                guard !model.isAdding else { return }
                Task {
                    guard await model.add(alias: alias) else { return }
                    Haptic.success.play()
                    onDone()
                }
            }
        }
    }
}

/// VisionKit scanner; each QR code's raw symbol is decoded as bytes.
struct ScannerView: View {
    let onBytes: (Data) -> Void
    var onText: (String) -> Void = { _ in }
    /// What to do without a camera: it differs between adding a contact and
    /// linking a device.
    var unavailable: LocalizedStringKey = "The camera is not available. Ask your contact for their link."

    var body: some View {
        if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
            // A bounded height: inside a ScrollView the camera has no size of its own.
            Representable(onBytes: onBytes, onText: onText)
                .clipShape(.rect(cornerRadius: Radius.card))
                .frame(minHeight: 280, idealHeight: 420, maxHeight: 420)
        } else {
            Text(unavailable)
                .font(.bBody).foregroundStyle(Color.fgMuted)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, Space.s4)
        }
    }

    private struct Representable: UIViewControllerRepresentable {
        let onBytes: (Data) -> Void
        let onText: (String) -> Void

        func makeUIViewController(context: Context) -> DataScannerViewController {
            let vc = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])],
                                               qualityLevel: .accurate, isHighlightingEnabled: true)
            vc.delegate = context.coordinator
            try? vc.startScanning()
            return vc
        }

        func updateUIViewController(_ vc: DataScannerViewController, context: Context) {}
        func makeCoordinator() -> Coordinator { Coordinator(onBytes: onBytes, onText: onText) }

        final class Coordinator: NSObject, DataScannerViewControllerDelegate {
            let onBytes: (Data) -> Void
            let onText: (String) -> Void
            init(onBytes: @escaping (Data) -> Void, onText: @escaping (String) -> Void) {
                self.onBytes = onBytes
                self.onText = onText
            }

            func dataScanner(_ s: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
                for case .barcode(let b) in items {
                    if let d = (b.observation.barcodeDescriptor as? CIQRCodeDescriptor).flatMap(QRPayload.bytes(from:)) {
                        onBytes(d)
                        return
                    }
                    // Not byte mode (numeric, alphanumeric…): its text decides.
                    if let s = b.payloadStringValue { onText(s); return }
                }
            }
        }
    }
}

/// My card as a QR code (white ground in both themes) and a link to share:
/// the link first, the QR at most 260 pt with "Show larger" (U-27).
struct MyCodeView: View {
    let core: CoreService
    /// Also puts "Share my link" in the navigation bar (My identity).
    var shareInToolbar = false
    @State private var card: (bytes: Data, text: String)?
    @State private var notAdmin = false
    @State private var failed = false
    @State private var larger = false

    var body: some View {
        VStack(spacing: Space.s4) {
            if let card, let img = QRPayload.image(for: card.bytes, scale: 6) {
                let link = URL(string: "barking://card#\(card.text)")!
                ShareLink(item: link) { Text("Share my link") }
                    .buttonStyle(.barkingPrimary)
                qr(img).frame(maxWidth: 260)
                TextLink("Show larger") { larger = true }
                    .sheet(isPresented: $larger) { largerCode(img) }
                    .toolbar {
                        if shareInToolbar {
                            ToolbarItem(placement: .primaryAction) {
                                ShareLink(item: link) { Label("Share my link", systemImage: "square.and.arrow.up") }
                            }
                        }
                    }
            } else if notAdmin {
                Text("Show your code from your first device").foregroundStyle(Color.fgMuted)
            } else if failed {
                Text("Something went wrong. Your data is safe.").foregroundStyle(Color.fgMuted)
                SecondaryButton("Try again") { Task { await load() } }
            } else {
                ProgressView()
            }
        }
        .frame(maxWidth: .infinity)
        .task { await load() }
    }

    private func qr(_ img: UIImage) -> some View {
        Image(uiImage: img).interpolation(.none).resizable().scaledToFit()
            .padding(12).background(Color.white, in: .rect(cornerRadius: Radius.card))
            .accessibilityLabel(Text("My QR code. A contact scans it to add you."))
    }

    private func largerCode(_ img: UIImage) -> some View {
        NavigationStack {
            qr(img)
                .padding(Space.gutter)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.surface)
                .navigationTitle(Text("My code"))
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { larger = false } } }
        }
        .presentationBackground(Color.surface)
    }

    /// Only the device holding the root signs a card: tell that apart from an error.
    private func load() async {
        failed = false
        do {
            card = try await core.myCard()
        } catch {
            let devices = (try? await core.myDevices()) ?? []
            if devices.contains(where: { $0.thisDevice && !$0.admin }) { notAdmin = true } else { failed = true }
        }
    }
}
