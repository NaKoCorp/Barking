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
            VStack(spacing: 16) {
                if let p = model.preview {
                    confirmation(p)
                } else {
                    Picker(selection: $tab) {
                        Text("Scan").tag(0)
                        Text("My code").tag(1)
                    } label: { EmptyView() }
                    .pickerStyle(.segmented)
                    if let e = model.error { errorText(e) }
                    if tab == 0 {
                        ScannerView(onBytes: { data in Task { await model.scanned(data) } },
                                    onText: { s in Task { await model.scannedText(s) } })
                    }
                    else { MyCodeView(core: core) }
                }
                Spacer(minLength: 0)
            }
            .padding(16)
            .background(Color.surface)
            .navigationTitle(Text("Add a contact"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close", action: onDone) } }
        }
        .task { if let link { await model.opened(link: link) } }
    }

    private func errorText(_ e: AddContactModel.AddError) -> some View {
        let text: LocalizedStringKey = switch e {
        case .notACard: "This is not a Barking card"
        case .ownCard: "This is your own card"
        case .failed: "Something went wrong. Your data is safe."
        }
        return Text(text).foregroundStyle(Color.danger).frame(maxWidth: .infinity, alignment: .leading)
    }

    private func confirmation(_ p: CardPreview) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Avatar(name: p.displayName, fingerprint: p.fingerprint, size: 64)
            ScreenTitle(verbatim: p.displayName, size: 22)
            Text(verbatim: String(p.fingerprint.prefix(19))).font(BarkingFont.mono(.footnote, size: 12.5))
                .foregroundStyle(Color.fgSoft)
            TextField("Alias (optional)", text: $alias).textFieldStyle(.roundedBorder)
            PrimaryButton("Add") { Task { if await model.add(alias: alias) { onDone() } } }
            SecondaryButton("Cancel") { model.reset() }
        }
    }
}

/// VisionKit scanner; each QR code's raw symbol is decoded as bytes.
struct ScannerView: View {
    let onBytes: (Data) -> Void
    var onText: (String) -> Void = { _ in }

    var body: some View {
        if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
            Representable(onBytes: onBytes, onText: onText)
                .clipShape(.rect(cornerRadius: Radius.card))
                .frame(maxHeight: 420)
        } else {
            Text("The camera is not available. Ask your contact for their link.")
                .foregroundStyle(Color.fgMuted).padding()
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

/// My card as a QR code (white ground in both themes) and a link to share.
struct MyCodeView: View {
    let core: CoreService
    @State private var card: (bytes: Data, text: String)?
    @State private var notAdmin = false
    @State private var failed = false

    var body: some View {
        VStack(spacing: 16) {
            if let card, let img = QRPayload.image(for: card.bytes, scale: 6) {
                Image(uiImage: img).interpolation(.none).resizable().scaledToFit()
                    .padding(12).background(Color.white, in: .rect(cornerRadius: Radius.card))
                    .accessibilityLabel(Text("My QR code"))
                ShareLink(item: URL(string: "barking://card#\(card.text)")!) {
                    Text("Share my link").font(BarkingFont.mono(.body, size: 15, weight: .semibold))
                        .frame(maxWidth: .infinity, minHeight: 52)
                }
                .buttonStyle(.borderedProminent).tint(Color.accentFill)
            } else if notAdmin {
                Text("Show your code from your first device").foregroundStyle(Color.fgMuted)
            } else if failed {
                Text("Something went wrong. Your data is safe.").foregroundStyle(Color.fgMuted)
                SecondaryButton("Try again") { Task { await load() } }
            } else {
                ProgressView()
            }
        }
        .task { await load() }
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
