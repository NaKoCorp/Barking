import BarkingKit
import SwiftUI

/// The GIF picker (spec GIF §9.4): a medium sheet over the conversation,
/// "Search KLIPY" as Klipy requires, trending then search results in a grid
/// of muted MP4s, each fetched by the core. A tap sends, with a light
/// haptic, and closes.
struct GifPickerView: View {
    /// The provider's name, as the core gives it.
    let providerName: String
    @State private var model: GifPickerModel
    @Environment(\.dismiss) private var dismiss
    @FocusState private var searching: Bool

    private let columns = [GridItem(.adaptive(minimum: 104, maximum: 200), spacing: Space.s1)]

    init(core: CoreService, providerName: String, send: @escaping @MainActor (GifInfo) async -> Bool) {
        self.providerName = providerName
        _model = State(initialValue: GifPickerModel(core: core, send: send))
    }

    var body: some View {
        VStack(spacing: Space.s2) {
            header
            content.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(.top, Space.s4)
        .background(Color.surface)
        .accessibilityIdentifier("gifPicker")
        .presentationDetents([.medium, .large])
        .presentationBackground(Color.surface)
        .task { await model.load() }
        .onChange(of: model.done) { _, done in if done { dismiss() } }
        .onDisappear { model.stop() }
    }

    private var header: some View {
        VStack(alignment: .trailing, spacing: Space.s1) {
            HStack(spacing: Space.s2) {
                Image(systemName: "magnifyingglass").font(.bSymbol(15, weight: .semibold, maximum: 22))
                    .foregroundStyle(Color.fgMuted)
                    .accessibilityHidden(true)
                // Klipy's own wording, required by its terms.
                TextField("Search KLIPY", text: $model.query)
                    .focused($searching)
                    .submitLabel(.search)
                    .autocorrectionDisabled()
                    .onSubmit { Task { await model.retry() } }
            }
            .padding(.horizontal, Space.s4).padding(.vertical, Space.s3)
            .background(Color.surfaceAlt, in: .capsule)
            // The provider's mark, in the app's grey (not its colours).
            Text(verbatim: providerName.uppercased())
                .font(BarkingFont.mono(.caption2, size: 11, weight: .semibold))
                .foregroundStyle(Color.fgMuted)
                .accessibilityLabel(Text(verbatim: providerName))
                .accessibilityIdentifier("gifPicker.brand")
        }
        .padding(.horizontal, Space.gutter)
    }

    @ViewBuilder private var content: some View {
        switch model.state {
        case .loading:
            ProgressView().controlSize(.regular)
        case .results(let results):
            ScrollView {
                LazyVGrid(columns: columns, spacing: Space.s1) {
                    ForEach(Array(results.enumerated()), id: \.offset) { i, result in
                        cell(result, index: i)
                    }
                }
                .padding(.horizontal, Space.gutter)
                .padding(.bottom, Space.s4)
            }
            .scrollDismissesKeyboard(.immediately)
        case .empty(let query) where query.isEmpty:
            message(Text("No GIFs"))
        case .empty(let query):
            message(Text("No GIFs for “\(query)”"))
        case .offline:
            message(Text("You're offline"))
        case .unreachable:
            Button { Task { await model.retry() } } label: {
                Text("\(providerName) is unreachable · Retry").font(.bBody.weight(.semibold))
                    .foregroundStyle(Color.accent)
                    .frame(minHeight: 44)
                    .padding(.horizontal, Space.gutter)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("gifPicker.retry")
        case .rateLimited:
            message(Text("\(providerName) is busy · Try again in a minute"))
        case .notConfigured:
            message(Text("GIFs are unavailable in this version"))
        }
    }

    private func message(_ text: Text) -> some View {
        text.font(.bBody).foregroundStyle(Color.fgMuted)
            .multilineTextAlignment(.center)
            .padding(.horizontal, Space.gutter)
            .accessibilityIdentifier("gifPicker.state")
    }

    private func cell(_ result: GifResultInfo, index: Int) -> some View {
        Button {
            Haptic.send.play()
            Task { await model.send(result) }
        } label: {
            GifPreviewCell(url: result.previewMp4Url, ratio: Self.ratio(result.gif), model: model)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(result.title.isEmpty ? Text("GIF") : Text(verbatim: result.title))
        .accessibilityHint(Text("Sends this GIF."))
        .accessibilityIdentifier("gifPicker.result.\(index)")
    }

    /// The cell keeps the GIF's shape, within reason, before it loads.
    static func ratio(_ gif: GifInfo) -> CGFloat {
        guard gif.width > 0, gif.height > 0 else { return 1 }
        return min(max(CGFloat(gif.width) / CGFloat(gif.height), 0.75), 1.78)
    }
}

/// One result: a neutral slot of the reserved size, then the preview.
private struct GifPreviewCell: View {
    let url: String
    let ratio: CGFloat
    let model: GifPickerModel
    @State private var data: Data?

    var body: some View {
        Color.surfaceAlt
            .aspectRatio(ratio, contentMode: .fit)
            .frame(minWidth: 44, minHeight: 44)
            .overlay {
                if let data { GifPlayer(data: data) }
            }
            .clipShape(.rect(cornerRadius: Radius.tile))
            .contentShape(.rect)
            // Cancelled when the cell leaves: its preview is then not kept.
            .task(id: url) {
                let d = await model.preview(url)
                if !Task.isCancelled { data = d }
            }
            // Off screen, the decoder goes: many at once fail.
            .onDisappear { data = nil }
    }
}
