import BarkingKit
import SwiftUI

/// Screen 7 of the mockup, Internet only.
struct NetworkView: View {
    let core: CoreService
    @State private var model: NetworkModel
    @State private var adding = false
    @State private var relayId = ""
    @State private var relayAddr = ""
    /// The add sheet's camera, and what it last read when not a relay.
    @State private var scanning = false
    @State private var notARelay = false
    /// A relay from a shared link, waiting for "Add".
    @State private var confirming: AppRouter.RelayLink?
    /// A relay shown as a QR code, for another phone to scan.
    @State private var sharing: AppRouter.RelayLink?
    @Environment(AppRouter.self) private var router
    @Environment(\.colorScheme) private var scheme
    @Environment(\.locale) private var locale

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: NetworkModel(core: core))
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Space.s2) {
                    internetCard
                    syncCard.padding(.top, Space.s3)
                    // 24 pt above a section label, 8 below (U-14).
                    SectionLabel("Internet relays").padding(.top, Space.section - Space.s2)
                    Card {
                        VStack(alignment: .leading, spacing: 12) {
                            if model.relays.isEmpty {
                                Text("No relay yet. Until public relays exist, add one by hand.")
                                    .font(.bBody).foregroundStyle(Color.fgMuted)
                            }
                            ForEach(model.relays, id: \.id) { r in relayRow(r) }
                            TextLink("+ Add a relay") { adding = true }
                        }
                    }
                }
                .padding(.horizontal, Space.gutter)
                .padding(.vertical, Space.s4)
            }
            .contentMargins(.bottom, 96, for: .scrollContent)
            .background(Color.surface)
            .navigationTitle(Text("Network"))
            .refreshable { await model.syncNow() }
            .sheet(isPresented: $adding, onDismiss: { scanning = false; notARelay = false }) { addSheet }
            .sheet(item: $sharing) { relayCode($0) }
            .alert(Text("Add this relay?"),
                   isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
                   presenting: confirming) { r in
                Button("Add") { Task { await addLinked(r) } }
                    .accessibilityIdentifier("relay.confirm")
                Button("Cancel", role: .cancel) {}
            } message: { r in
                Text("Barking will use \(r.addr) to send and receive your sealed messages.\n\(String(r.id.prefix(12)))…")
            }
        }
        // A `barking://node#…` link opened from outside: asked, never added silently.
        .onChange(of: router.pendingRelayLink, initial: true) { _, link in
            guard link != nil, let r = router.takePendingRelayLink() else { return }
            adding = false
            confirming = r
        }
        .task {
            await model.load()
            for await change in await core.changes {
                // Anything but a delivery state can move the queue or the relays.
                if case .delivery = change { continue }
                await model.load()
            }
        }
    }

    /// The transport, then its state as a glyph and a word (U-19). The ≋
    /// names the transport; the status dot is the only colour of state.
    private var internetCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Text(verbatim: "≋").font(.bSymbol(13, relativeTo: .subheadline, weight: .bold))
                    .foregroundStyle(Color.transportNet).accessibilityHidden(true)
                Text(verbatim: "Internet").font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold))
                    .foregroundStyle(Color.fg)
            }
            StatusDot(model.status.dot, label: model.status.label)
            if let at = model.lastSync {
                Text("last sync \(at.formatted(date: .omitted, time: .shortened))")
                    .font(.bMeta).foregroundStyle(Color.fgSoft)
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.surfaceCard, in: .rect(cornerRadius: Radius.card))
        .overlay(alignment: .top) { Rectangle().fill(Color.transportNet).frame(height: 3) }
        .clipShape(.rect(cornerRadius: Radius.card))
        .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
        // One VoiceOver element (U-36): "Internet, Reachable, last sync 11:58".
        .accessibilityElement(children: .combine)
    }

    /// Pending packets, "Sync now" (loading while it runs), then what the
    /// sync did, and the CLI lines in the terminal block.
    private var syncCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                // Opens "Pending" (§6.6): a 44 pt row with a chevron, also at zero.
                NavigationLink {
                    PendingView(core: core)
                } label: {
                    HStack(spacing: Space.s2) {
                        Text(verbatim: NetworkModel.pendingLine(model.pending, bundle: .strings(for: locale), locale: locale))
                            .font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold)).foregroundStyle(Color.fg)
                            .multilineTextAlignment(.leading)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        RowGlyph()
                    }
                    .frame(minHeight: 44)
                    .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("network.pending")
                PrimaryButton("Sync now", isLoading: model.syncing) { Task { await model.syncNow() } }
                if let result = model.result, !model.syncing {
                    StatusDot(result.dot, verbatim: result.text)
                        .accessibilityIdentifier("network.result")
                }
                if !model.terminal.isEmpty {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(model.terminal, id: \.self) { Text(verbatim: $0) }
                    }
                    .font(.bMeta)
                    .foregroundStyle(Color.terminalFg)
                    .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.terminalBg, in: .rect(cornerRadius: Radius.card))
                    .overlay {
                        // On Ink the block keeps an edge of its own.
                        if scheme == .dark {
                            RoundedRectangle(cornerRadius: Radius.card)
                                .strokeBorder(Color.accent.opacity(0.3), lineWidth: 1)
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
            }
        }
    }

    private func relayRow(_ r: NodeInfo) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: String(r.id.prefix(12))).font(BarkingFont.mono(.footnote, size: 13)).foregroundStyle(Color.fg)
                Text(verbatim: r.addr).font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color.fgSoft)
                if r.manual { Text("added by hand").font(.bMeta).foregroundStyle(Color.fgSoft) }
                else if r.fromCard { Text("from a contact's card").font(.bMeta).foregroundStyle(Color.fgSoft) }
            }
            Spacer()
            Text(verbatim: "\(Int(r.score * 100))%").font(BarkingFont.mono(.caption, size: 12)).foregroundStyle(Color.fgMuted)
            ZStack(alignment: .leading) {
                Capsule().fill(Color.surfaceAlt).frame(width: 64, height: 4)
                Capsule().fill(Color.transportNet).frame(width: 64 * CGFloat(r.score), height: 4)
            }
            .accessibilityHidden(true)
        }
        .contentShape(.rect)
        .contextMenu {
            if let link = NetworkModel.relayLink(id: r.id, addr: r.addr) {
                ShareLink(item: link) { Label("Share this relay", systemImage: "square.and.arrow.up") }
            }
            Button { sharing = AppRouter.RelayLink(id: r.id, addr: r.addr) } label: {
                Label("Show its QR code", systemImage: "qrcode")
            }
        }
    }

    /// A relay from a link, once confirmed. If it fails, the add sheet opens
    /// with the relay filled in and the error under it.
    private func addLinked(_ r: AppRouter.RelayLink) async {
        if await model.addRelay(id: r.id, addr: r.addr) {
            Haptic.success.play()
        } else {
            relayId = r.id; relayAddr = r.addr
            adding = true
        }
    }

    /// A relay QR code read by the add sheet's camera fills the fields; the
    /// user still taps Add.
    private func scanned(_ data: Data?, _ text: String?) {
        guard let r = NetworkModel.scannedRelay(data, text: text) else { notARelay = true; return }
        relayId = r.id; relayAddr = r.addr
        notARelay = false
        scanning = false
        Haptic.success.play()
    }

    /// The relay's link as a QR code (white ground in both themes).
    private func relayCode(_ r: AppRouter.RelayLink) -> some View {
        NavigationStack {
            VStack(spacing: Space.s4) {
                if let link = NetworkModel.relayLink(id: r.id, addr: r.addr),
                   let img = QRPayload.image(for: Data(link.absoluteString.utf8), scale: 6) {
                    Image(uiImage: img).interpolation(.none).resizable().scaledToFit()
                        .padding(12).background(Color.white, in: .rect(cornerRadius: Radius.card))
                        .frame(maxWidth: 320)
                        .accessibilityLabel(Text("Relay QR code. Another phone scans it to add this relay."))
                    Text(verbatim: r.addr).font(BarkingFont.mono(.footnote, size: 13)).foregroundStyle(Color.fgMuted)
                    ShareLink(item: link) { Text("Share this relay") }.buttonStyle(.barkingPrimary)
                }
            }
            .padding(Space.gutter)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color.surface)
            .navigationTitle(Text("Relay"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { sharing = nil } } }
        }
        .presentationBackground(Color.surface)
    }

    private var addSheet: some View {
        NavigationStack {
            Group {
                BarkingTextField("Identifier", text: $relayId, identifier: "relay.id")
                    .textInputAutocapitalization(.characters).autocorrectionDisabled()
                BarkingTextField("Address", text: $relayAddr, prompt: "ip:port", identifier: "relay.addr")
                    .keyboardType(.numbersAndPunctuation).autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                if scanning {
                    ScannerView(onBytes: { scanned($0, $1) }, onText: { scanned(nil, $0) },
                                unavailable: "The camera is not available. Paste the relay link instead.")
                    if notARelay {
                        Text("This is not a Barking relay code").font(.bBodySmall).foregroundStyle(Color.danger)
                    }
                } else {
                    SecondaryButton("Scan a relay QR code") { notARelay = false; scanning = true }
                        .accessibilityIdentifier("relay.scan")
                }
                SecondaryButton("Paste a relay link") {
                    if let s = UIPasteboard.general.string, let r = NetworkModel.parseRelay(link: s) {
                        relayId = r.id; relayAddr = r.addr
                    }
                }
                if let e = model.addError {
                    Text(LocalizedStringKey(e)).font(.bBodySmall).foregroundStyle(Color.danger)
                }
            }
            .barkingScreen()
            .navigationTitle(Text("Add a relay"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { adding = false } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") { Task { if await model.addRelay(id: relayId, addr: relayAddr) { adding = false } } }
                }
            }
        }
        .presentationBackground(Color.surface)
    }
}
