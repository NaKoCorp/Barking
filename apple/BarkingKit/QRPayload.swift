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

    /// The bytes of a byte-mode symbol; `nil` for any other mode or an
    /// inconsistent length.
    public static func bytes(from descriptor: CIQRCodeDescriptor) -> Data? {
        var bits = BitReader(descriptor.errorCorrectedPayload)
        guard bits.read(4) == 0b0100 else { return nil }
        guard let count = bits.read(descriptor.symbolVersion <= 9 ? 8 : 16) else { return nil }
        var out = Data(capacity: count)
        for _ in 0..<count {
            guard let b = bits.read(8) else { return nil }
            out.append(UInt8(b))
        }
        return out
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
