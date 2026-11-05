import SwiftUI

/// The welcome screen's rings and coloured dots. The dots orbit slowly and
/// faint stars twinkle; with Reduce Motion the picture stays still.
struct Galaxy: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    struct Orbiter {
        let radius: Double, angle: Double, period: Double, color: Color
    }

    /// Positions of the mockup at t = 0 (390 pt wide grid, centre 195, 330).
    static let orbiters = [
        Orbiter(radius: 129, angle: -29.7, period: 48, color: Color(red: 0x5a / 255, green: 0xb0 / 255, blue: 1)),
        Orbiter(radius: 127, angle: 187.2, period: 62, color: Color(red: 0xd9 / 255, green: 0xa9 / 255, blue: 0x20 / 255)),
        Orbiter(radius: 192, angle: 38.7, period: 85, color: Color(red: 0x3d / 255, green: 0xbb / 255, blue: 0x85 / 255)),
        Orbiter(radius: 168, angle: 212.4, period: 110, color: Color(red: 0x9b / 255, green: 0x6b / 255, blue: 0xe0 / 255)),
    ]

    /// Fixed pseudo-random stars: (radius, angle, size, twinkle phase).
    static let stars: [(Double, Double, Double, Double)] = (0..<28).map { i in
        let x = Double(i)
        return (40 + (x * 83).truncatingRemainder(dividingBy: 220),
                (x * 137.5).truncatingRemainder(dividingBy: 360),
                1 + (x * 7).truncatingRemainder(dividingBy: 3) * 0.4,
                x * 0.9)
    }

    /// Where an orbiter is `t` seconds after the start.
    static func position(_ o: Orbiter, at t: Double) -> (x: Double, y: Double) {
        let a = (o.angle + 360 * t / o.period) * .pi / 180
        return (o.radius * cos(a), o.radius * sin(a))
    }

    var body: some View {
        TimelineView(.animation(minimumInterval: 1 / 30, paused: reduceMotion)) { timeline in
            let t = reduceMotion ? 0 : timeline.date.timeIntervalSinceReferenceDate
            Canvas { ctx, size in
                let s = size.width / 390
                let c = CGPoint(x: size.width / 2, y: size.height * 0.39)
                func circle(_ x: Double, _ y: Double, _ r: Double) -> Path {
                    Path(ellipseIn: CGRect(x: c.x + x * s - r * s, y: c.y + y * s - r * s, width: 2 * r * s, height: 2 * r * s))
                }
                for (r, o) in [(70.0, 0.5), (130, 0.3), (190, 0.18), (250, 0.1)] {
                    ctx.stroke(circle(0, 0, r), with: .color(Color.accent.opacity(o)), lineWidth: 1)
                }
                for (r, a, size, phase) in Self.stars {
                    let rad = a * .pi / 180
                    let twinkle = reduceMotion ? 0.35 : 0.15 + 0.45 * (0.5 + 0.5 * sin(t * 1.3 + phase))
                    ctx.fill(circle(r * cos(rad), r * sin(rad), size), with: .color(Color.accent.opacity(twinkle)))
                }
                for o in Self.orbiters {
                    let p = Self.position(o, at: t)
                    ctx.fill(circle(p.x, p.y, 6), with: .color(o.color))
                }
                ctx.fill(circle(0, 0, 10), with: .color(Color.accentFill))
            }
        }
        .accessibilityHidden(true)
    }
}
