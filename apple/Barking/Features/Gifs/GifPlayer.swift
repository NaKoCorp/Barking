import AVFoundation
import SwiftUI
import UniformTypeIdentifiers

/// An MP4 held in memory, as an `AVURLAsset` whose bytes come from a
/// resource loader: no file is written, nothing outlives the player.
final class GifMemoryAsset: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
    /// A scheme AVFoundation cannot load itself, so it asks the delegate.
    private static let scheme = "barking-gif"
    let asset: AVURLAsset
    private let data: Data
    private let queue = DispatchQueue(label: "barking.gif.loader")

    init(data: Data) {
        self.data = data
        asset = AVURLAsset(url: URL(string: "\(Self.scheme)://memory/\(UUID().uuidString).mp4")!)
        super.init()
        // The loader holds its delegate weakly: this object keeps itself
        // alive as long as whoever holds the asset holds it.
        asset.resourceLoader.setDelegate(self, queue: queue)
    }

    func resourceLoader(_ resourceLoader: AVAssetResourceLoader,
                        shouldWaitForLoadingOfRequestedResource request: AVAssetResourceLoadingRequest) -> Bool {
        if let info = request.contentInformationRequest {
            info.contentType = UTType.mpeg4Movie.identifier
            info.contentLength = Int64(data.count)
            info.isByteRangeAccessSupported = true
        }
        if let wanted = request.dataRequest {
            let start = Int(wanted.currentOffset)
            guard start >= 0, start <= data.count else {
                request.finishLoading(with: CocoaError(.fileReadCorruptFile))
                return true
            }
            let length = wanted.requestsAllDataToEndOfResource
                ? data.count - start
                : min(wanted.requestedLength - Int(wanted.currentOffset - wanted.requestedOffset), data.count - start)
            wanted.respond(with: data.subdata(in: start..<(start + max(0, length))))
        }
        request.finishLoading()
        return true
    }
}

/// A received or picked GIF: a muted MP4 played in a loop, from memory.
/// Still on its first frame under Reduce Motion or with video autoplay off
/// (spec GIF §9.4). Never played on another screen (AirPlay).
struct GifPlayer: View {
    let data: Data
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityPlayAnimatedImages) private var playAnimatedImages

    /// Played, not still.
    static func plays(reduceMotion: Bool, videoAutoplay: Bool) -> Bool { !reduceMotion && videoAutoplay }

    var body: some View {
        PlayerLayerView(data: data,
                        playing: Self.plays(reduceMotion: reduceMotion || !playAnimatedImages,
                                            videoAutoplay: UIAccessibility.isVideoAutoplayEnabled))
            .accessibilityHidden(true)
    }
}

private struct PlayerLayerView: UIViewRepresentable {
    let data: Data
    let playing: Bool

    func makeUIView(context: Context) -> PlayerUIView {
        let view = PlayerUIView()
        view.show(data, playing: playing)
        return view
    }

    func updateUIView(_ view: PlayerUIView, context: Context) {
        view.show(data, playing: playing)
    }

    static func dismantleUIView(_ view: PlayerUIView, coordinator: ()) { view.stop() }
}

final class PlayerUIView: UIView {
    override static var layerClass: AnyClass { AVPlayerLayer.self }
    private var playerLayer: AVPlayerLayer { layer as! AVPlayerLayer }
    private var source: GifMemoryAsset?
    private var looper: AVPlayerLooper?
    private var shown: Data?
    private var playing = false

    override init(frame: CGRect) {
        super.init(frame: frame)
        playerLayer.videoGravity = .resizeAspectFill
        isUserInteractionEnabled = false
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    func show(_ data: Data, playing: Bool) {
        if data != shown {
            stop()
            shown = data
            let source = GifMemoryAsset(data: data)
            let player = AVQueuePlayer()
            player.isMuted = true
            player.allowsExternalPlayback = false
            player.preventsDisplaySleepDuringVideoPlayback = false
            player.automaticallyWaitsToMinimizeStalling = false
            looper = AVPlayerLooper(player: player, templateItem: AVPlayerItem(asset: source.asset))
            self.source = source
            playerLayer.player = player
            self.playing = !playing
        }
        guard playing != self.playing, let player = playerLayer.player else { return }
        self.playing = playing
        if playing {
            player.play()
        } else {
            // The first frame, still.
            player.pause()
            player.seek(to: .zero)
        }
    }

    /// Releases the decoder: many at once fail.
    func stop() {
        playerLayer.player?.pause()
        looper?.disableLooping()
        looper = nil
        playerLayer.player = nil
        source = nil
        shown = nil
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        if window == nil { playerLayer.player?.pause() } else if playing { playerLayer.player?.play() }
    }
}
