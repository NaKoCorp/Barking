import CoreImage
import CoreImage.CIFilterBuiltins
import UIKit

/// Contact cards in QR codes, in binary (spec iOS messaging §5.3): byte mode,
/// error correction L. Scanners only hand back text, so reading goes through
/// the raw symbol (`CIQRCodeDescriptor`).
public enum QRPayload {
    public static func ciImage(for data: Data) -> CIImage {
        let f = CIFilter.qrCodeGenerator()
        f.message = data
        f.correctionLevel = "L"
        return f.outputImage ?? CIImage()
    }

    /// Black on white, scaled with no smoothing.
    public static func image(for data: Data, scale: CGFloat) -> UIImage? {
        let img = ciImage(for: data).transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        guard let cg = CIContext().createCGImage(img, from: img.extent) else { return nil }
        return UIImage(cgImage: cg)
    }

    /// The bytes of a symbol whose first segment is in byte mode, every
    /// segment read up to the terminator: the generator splits some payloads
    /// into numeric or alphanumeric runs. `nil` for another first mode, a
    /// Kanji or unknown segment, or an inconsistent length.
    public static func bytes(from descriptor: CIQRCodeDescriptor) -> Data? {
        var bits = BitReader(descriptor.errorCorrectedPayload)
        // Character count bits for versions 1-9, 10-26 and 27-40.
        let size = descriptor.symbolVersion <= 9 ? 0 : descriptor.symbolVersion <= 26 ? 1 : 2
        var out = Data()
        var first = true
        while let mode = bits.read(4), mode != 0 {
            if first, mode != 0b0100 { return nil }
            first = false
            switch mode {
            case 0b0100:
                guard let count = bits.read([8, 16, 16][size]) else { return nil }
                for _ in 0..<count {
                    guard let b = bits.read(8) else { return nil }
                    out.append(UInt8(b))
                }
            case 0b0010:
                guard let count = bits.read([9, 11, 13][size]) else { return nil }
                for _ in 0..<count / 2 {
                    guard let v = bits.read(11), v < 45 * 45 else { return nil }
                    out.append(alphanumeric[v / 45])
                    out.append(alphanumeric[v % 45])
                }
                if count % 2 == 1 {
                    guard let v = bits.read(6), v < 45 else { return nil }
                    out.append(alphanumeric[v])
                }
            case 0b0001:
                guard var count = bits.read([10, 12, 14][size]) else { return nil }
                while count > 0 {
                    let digits = min(count, 3)
                    guard let v = bits.read([4, 7, 10][digits - 1]), v < [10, 100, 1000][digits - 1] else { return nil }
                    out.append(contentsOf: String(v).leftPadded(digits).utf8)
                    count -= digits
                }
            case 0b0111:
                // ECI designator: 8, 16 or 24 bits. Bytes stay as they are.
                guard let lead = bits.read(1) else { return nil }
                let rest = lead == 0 ? 7 : (bits.read(1) == 0 ? 14 : 22)
                guard bits.read(rest) != nil else { return nil }
            default:
                return nil
            }
        }
        return first ? nil : out
    }

    private static let alphanumeric = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".utf8)
}

private extension String {
    func leftPadded(_ width: Int) -> String {
        String(repeating: "0", count: max(0, width - count)) + self
    }
}

private struct BitReader {
    let data: Data
    var position = 0
    init(_ data: Data) { self.data = data }

    mutating func read(_ n: Int) -> Int? {
        guard position + n <= data.count * 8 else { return nil }
        var v = 0
        for _ in 0..<n {
            let byte = data[data.startIndex + position / 8]
            v = (v << 1) | Int((byte >> (7 - UInt8(position % 8))) & 1)
            position += 1
        }
        return v
    }
}
