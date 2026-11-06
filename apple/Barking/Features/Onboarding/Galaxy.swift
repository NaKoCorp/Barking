import SwiftUI

/// The welcome screen's rings and coloured dots. The dots orbit slowly and
/// faint stars twinkle for a minute, then the picture rests; it also rests
/// while the scene is not active, and never moves under Reduce Motion.
///
/// Everything is drawn through a vertical mask that is clear over the
/// header and from the top of the text down (UI review B5, U-32), so no dot
/// ever crosses the text, at any text size.
struct Galaxy: View {
    /// The bottom of the header and the top of the text, in this view's
    /// coordinates.
    let top: CGFloat
    let bottom: CGFloat

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.scenePhase) private var scenePhase
    @State private var start = Date()
    @State private var settled = false

    struct Orbiter {
        /// Index in `rings`: a dot always rides a drawn ring.
        let ring: Int
        let angle: Double, period: Double
        /// A transport colour token (Colors.xcassets).
        let token: String
        var radius: Double { Galaxy.rings[ring].radius }
        var color: Color { Color(token) }
    }

    /// Start angles of the mockup, each dot on a drawn ring (UI review B5:
    /// the mockup's radii were off the rings by up to 22 pt). The two dots
    /// that share the middle ring share a period, so they never meet.
    static let orbiters = [
        Orbiter(ring: 1, angle: -29.7, period: 55, token: "transportBle"),
        Orbiter(ring: 1, angle: 187.2, period: 55, token: "transportLora"),
        Orbiter(ring: 2, angle: 38.7, period: 85, token: "transportWifi"),
        Orbiter(ring: 0, angle: 212.4, period: 110, token: "transportNet"),
    ]

    /// The rings, on the 390 pt grid: radius and opacity of the accent.
    static let rings: [(radius: Double, opacity: Double)] = [(70, 0.5), (130, 0.3), (190, 0.18), (250, 0.1)]

    /// Radius of a dot on the 390 pt grid.
    static let dotRadius: CGFloat = 6

    /// Fixed pseudo-random stars: (radius, angle, size, twinkle phase).
    static let stars: [(Double, Double, Double, Double)] = (0..<28).map { i in
        let x = Double(i)
        return (40 + (x * 83).truncatingRemainder(dividingBy: 220),
                (x * 137.5).truncatingRemainder(dividingBy: 360),
                1 + (x * 7).truncatingRemainder(dividingBy: 3) * 0.4,
                x * 0.9)
    }

    /// Where an orbiter is `t` seconds after the start, from the centre, on
    /// the 390 pt grid.
    static func position(_ o: Orbiter, at t: Double) -> (x: Double, y: Double) {
        let a = (o.angle + 360 * t / o.period) * .pi / 180
        return (o.radius * cos(a), o.radius * sin(a))
    }

    var body: some View {
        let paused = GalaxyClock.paused(elapsed: settled ? GalaxyClock.runFor : 0, reduceMotion: reduceMotion,
                                        active: scenePhase == .active)
        TimelineView(.animation(minimumInterval: 1 / 30, paused: paused)) { timeline in
            let t = GalaxyClock.time(elapsed: timeline.date.timeIntervalSince(start), reduceMotion: reduceMotion)
            Canvas { ctx, size in
                let layout = GalaxyLayout(size: size, top: top, bottom: bottom)
                guard layout.isShown else { return }
                let s = layout.scale
                func circle(_ x: Double, _ y: Double, _ r: Double) -> Path {
                    let c = layout.point((x, y))
                    return Path(ellipseIn: CGRect(x: c.x - r * s, y: c.y - r * s, width: 2 * r * s, height: 2 * r * s))
                }
                for (r, o) in Self.rings {
                    ctx.stroke(circle(0, 0, r), with: .color(Color.accent.opacity(o)), lineWidth: 1)
                }
                for (r, a, size, phase) in Self.stars {
                    let rad = a * .pi / 180
                    let twinkle = reduceMotion ? 0.35 : 0.15 + 0.45 * (0.5 + 0.5 * sin(t * 1.3 + phase))
                    ctx.fill(circle(r * cos(rad), r * sin(rad), size), with: .color(Color.accent.opacity(twinkle)))
                }
                for o in Self.orbiters {
                    let p = Self.position(o, at: t)
                    ctx.fill(circle(p.x, p.y, Self.dotRadius), with: .color(o.color))
                }
                ctx.fill(circle(0, 0, 10), with: .color(Color.accentFill))
                // The mask: keep only what lies inside the band.
                let stops = layout.maskStops.map { Gradient.Stop(color: .black.opacity($0.opacity), location: $0.location) }
                ctx.blendMode = .destinationIn
                ctx.fill(Path(CGRect(origin: .zero, size: size)),
                         with: .linearGradient(Gradient(stops: stops), startPoint: .zero,
                                               endPoint: CGPoint(x: 0, y: size.height)))
            }
        }
        .accessibilityHidden(true)
        .task {
            guard !reduceMotion else { return }
            try? await Task.sleep(for: .seconds(GalaxyClock.runFor))
            settled = true
        }
    }
}

/// Where the galaxy sits on Welcome and what its mask lets through
/// (U-32): centred at about (62 %, 26 %), seen only between the header and
/// the text, with a 10 % fade at each edge (the synthesis' 45 → 55 %).
struct GalaxyLayout: Equatable {
    struct MaskStop: Equatable {
        let location: CGFloat
        let opacity: Double
    }

    let size: CGSize
    let top: CGFloat
    let bottom: CGFloat

    /// The fade at each edge of the band, as a share of the height.
    static let fade: CGFloat = 0.10
    /// Below this, the band would show slivers of rings: nothing is drawn
    /// (accessibility sizes, where the text starts under the header).
    static let minBand: CGFloat = 96

    var isShown: Bool { bottom - top >= Self.minBand }

    /// The mockup's grid is 390 pt wide.
    var scale: CGFloat { size.width / 390 }

    var ramp: CGFloat { max(0, min(Self.fade * size.height, (bottom - top) / 2)) }

    var centre: CGPoint {
        let lo = top + ramp, hi = bottom - ramp
        let y = hi < lo ? (top + bottom) / 2 : min(max(0.26 * size.height, lo), hi)
        return CGPoint(x: 0.62 * size.width, y: y)
    }

    /// A point of the 390 pt grid, from the centre, in view coordinates.
    func point(_ p: (x: Double, y: Double)) -> CGPoint {
        CGPoint(x: centre.x + p.x * scale, y: centre.y + p.y * scale)
    }

    /// The mask's opacity on the row `y`: 0 over the header and the text.
    func alpha(atY y: CGFloat) -> Double {
        guard isShown, y > top, y < bottom else { return 0 }
        guard ramp > 0 else { return 1 }
        return Double(min(1, min(y - top, bottom - y) / ramp))
    }

    /// The same mask as gradient stops, top to bottom.
    var maskStops: [MaskStop] {
        let h = max(size.height, 1)
        guard isShown else { return [MaskStop(location: 0, opacity: 0), MaskStop(location: 0, opacity: 0)] }
        return [
            MaskStop(location: 0, opacity: 0),
            MaskStop(location: top / h, opacity: 0),
            MaskStop(location: (top + ramp) / h, opacity: 1),
            MaskStop(location: (bottom - ramp) / h, opacity: 1),
            MaskStop(location: bottom / h, opacity: 0),
        ]
    }
}

/// The galaxy moves for a minute, then rests (U-32).
enum GalaxyClock {
    static let runFor: TimeInterval = 60

    /// The time the picture shows: 0 under Reduce Motion, never past a minute.
    static func time(elapsed: TimeInterval, reduceMotion: Bool) -> TimeInterval {
        reduceMotion ? 0 : min(max(elapsed, 0), runFor)
    }

    static func paused(elapsed: TimeInterval, reduceMotion: Bool, active: Bool) -> Bool {
        reduceMotion || !active || elapsed >= runFor
    }
}
