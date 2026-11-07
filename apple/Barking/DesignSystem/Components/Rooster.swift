import SwiftUI

/// The French rooster of the mockup's "Made in France" chip (64 × 64 grid).
struct Rooster: View {
    @Environment(\.colorScheme) private var scheme
    var size: CGFloat = 20

    private static let blue = Color(red: 0, green: 0, blue: 0x91 / 255)
    private static let red = Color(red: 0xe1 / 255, green: 0, blue: 0x0f / 255)
    private static let yellow = Color(red: 0xf2 / 255, green: 0xc9 / 255, blue: 0x4c / 255)

    var body: some View {
        Canvas { ctx, canvas in
            let s = canvas.width / 64
            ctx.scaleBy(x: s, y: s)
            let body = Color.fg
            ctx.fill(Self.path("M38 33 C38 20 46 9 57 6 C54 15 50 25 45 35 Z"), with: .color(Self.blue))
            let white = Self.path("M41 36 C46 26 53 19 62 18 C59 27 53 34 46 40 Z")
            ctx.fill(white, with: .color(.white))
            // In dark mode the white stripe is outlined in the ground colour.
            ctx.stroke(white, with: .color(scheme == .dark ? Color.surfaceWelcome : body),
                       style: StrokeStyle(lineWidth: 1.5, lineJoin: .round))
            ctx.fill(Self.path("M42 41 C49 36 56 35 62 37 C57 44 49 48 42 47 Z"), with: .color(Self.red))
            ctx.fill(Self.path("M26 21 C30 25 34 28 40 31 C46 34 47 44 42 50 C37 56 26 56 21 51 C16 46 16 38 19 32 C20 29 20 26 19 24 Z"),
                     with: .color(body))
            ctx.fill(Path(ellipseIn: CGRect(x: 14.5, y: 12.5, width: 13, height: 13)), with: .color(body))
            ctx.fill(Self.path("M15.5 13.5 C15 9 18 8.5 19.5 11 C20 7 23.5 7 23.5 11 C25.5 8.5 28.5 10.5 26.5 14 Z"),
                     with: .color(Self.red))
            ctx.fill(Self.path("M15 17 L8 19.5 L15 21.5 Z"), with: .color(Self.yellow))
            ctx.fill(Self.path("M16 22.5 C14.5 27 17.5 28.5 19 24.5 Z"), with: .color(Self.red))
            ctx.stroke(Self.path("M27 54.5 L25 61 M34 54.5 L35 61"), with: .color(body),
                       style: StrokeStyle(lineWidth: 2, lineCap: .round))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    /// Absolute M, L, C and Z commands, the only ones the drawing uses.
    static func path(_ d: String) -> Path {
        var p = Path()
        var cmd: Character = "M"
        var nums: [CGFloat] = []
        func flush() {
            switch cmd {
            case "M" where nums.count >= 2: p.move(to: CGPoint(x: nums[0], y: nums[1]))
            case "L" where nums.count >= 2: p.addLine(to: CGPoint(x: nums[0], y: nums[1]))
            case "C" where nums.count >= 6:
                p.addCurve(to: CGPoint(x: nums[4], y: nums[5]),
                           control1: CGPoint(x: nums[0], y: nums[1]), control2: CGPoint(x: nums[2], y: nums[3]))
            default: break
            }
            nums = []
        }
        // "M38" is a command glued to its first number: split them.
        let spaced = d.map { $0.isLetter ? " \($0) " : String($0) }.joined()
        for token in spaced.split(separator: " ") {
            if let c = token.first, token.count == 1, c.isLetter {
                flush()
                cmd = c
                if c == "Z" { p.closeSubpath() }
            } else if let n = Double(token) {
                nums.append(CGFloat(n))
                let need = cmd == "C" ? 6 : 2
                if nums.count == need { flush() }
            }
        }
        return p
    }
}

/// "Made in France" with the rooster, as on the welcome and settings screens.
struct MadeInFranceChip: View {
    var body: some View {
        HStack(spacing: 8) {
            Rooster()
            Text("Made in France")
        }
        .font(BarkingFont.mono(.caption, size: 12))
        .foregroundStyle(Color.fgMuted)
        .padding(.leading, 8).padding(.trailing, 12).padding(.vertical, 5)
        .background(Color.surfaceCard, in: Capsule())
        .overlay(Capsule().stroke(Color.border, lineWidth: 1))
    }
}
