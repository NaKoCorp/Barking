import BarkingKit
import UIKit
import XCTest
@testable import Barking

/// A contact's avatar (photo or emoji), kept on this iPhone through the core.
@MainActor
final class AvatarStoreTests: XCTestCase {
    private func image(_ w: CGFloat, _ h: CGFloat) -> UIImage {
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        return UIGraphicsImageRenderer(size: CGSize(width: w, height: h), format: format).image { ctx in
            UIColor.systemTeal.setFill()
            ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
        }
    }

    /// Any picked image becomes the centre square, 128 px, a JPEG small
    /// enough to reach my other devices in one packet.
    func testPhotoIsASmallSquareJPEG() throws {
        let data = try XCTUnwrap(AvatarStore.jpeg(from: image(4000, 3000)))
        XCTAssertLessThanOrEqual(data.count, AvatarStore.maxBytes)
        XCTAssertEqual(Array(data.prefix(2)), [0xFF, 0xD8], "a JPEG")
        let decoded = try XCTUnwrap(UIImage(data: data))
        XCTAssertEqual(decoded.size, CGSize(width: 128, height: 128))
    }

    /// A photo with detail everywhere still fits: the quality steps down.
    func testNoisyPhotoStillFits() throws {
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        let noisy = UIGraphicsImageRenderer(size: CGSize(width: 1200, height: 1200), format: format).image { ctx in
            var rng = SystemRandomNumberGenerator()
            for x in stride(from: 0, to: 1200, by: 4) {
                for y in stride(from: 0, to: 1200, by: 4) {
                    UIColor(red: .random(in: 0...1, using: &rng), green: .random(in: 0...1, using: &rng),
                            blue: .random(in: 0...1, using: &rng), alpha: 1).setFill()
                    ctx.fill(CGRect(x: x, y: y, width: 4, height: 4))
                }
            }
        }
        let data = try XCTUnwrap(AvatarStore.jpeg(from: noisy))
        XCTAssertLessThanOrEqual(data.count, AvatarStore.maxBytes)
    }

    /// A photo stored larger by the local-only build is made small again
    /// on load, so that it can reach my other devices.
    func testOversizePhotoIsShrunkOnLoad() async throws {
        let d = FakeDevice()
        let big = try XCTUnwrap(image(2000, 2000).jpegData(compressionQuality: 1))
        XCTAssertGreaterThan(big.count, AvatarStore.maxBytes)
        try d.setContactAvatar(contact: "a", avatar: .photo(jpeg: big))
        let store = AvatarStore(core: CoreService(device: d, runner: DirectRunner()))
        await store.reload()
        guard case .photo(let small) = d.avatars["a"] else { return XCTFail("still a photo") }
        XCTAssertLessThanOrEqual(small.count, AvatarStore.maxBytes)
        XCTAssertNotNil(store.photos["a"])
    }

    func testEmptyImageIsRefused() {
        XCTAssertNil(AvatarStore.jpeg(from: UIImage()))
    }

    func testEmojiIsSavedAndShown() async {
        let d = FakeDevice()
        let store = AvatarStore(core: CoreService(device: d, runner: DirectRunner()))
        let ok = await store.setEmoji("🦊", for: "a")
        XCTAssertTrue(ok)
        XCTAssertEqual(d.avatars["a"], .emoji(value: "🦊"))
        XCTAssertEqual(store.emoji["a"], "🦊")
        XCTAssertTrue(store.has("a"))
    }

    func testPhotoIsSavedAndShown() async throws {
        let d = FakeDevice()
        let store = AvatarStore(core: CoreService(device: d, runner: DirectRunner()))
        let png = try XCTUnwrap(image(300, 500).pngData())
        let ok = await store.setPhoto(png, for: "a")
        XCTAssertTrue(ok)
        guard case .photo(let jpeg) = d.avatars["a"] else { return XCTFail("a photo is stored") }
        XCTAssertEqual(Array(jpeg.prefix(2)), [0xFF, 0xD8])
        XCTAssertNotNil(store.photos["a"])
    }

    func testClearGoesBackToTheInitial() async {
        let d = FakeDevice()
        let store = AvatarStore(core: CoreService(device: d, runner: DirectRunner()))
        _ = await store.setEmoji("🦊", for: "a")
        let ok = await store.clear("a")
        XCTAssertTrue(ok)
        XCTAssertNil(d.avatars["a"])
        XCTAssertFalse(store.has("a"))
    }

    /// The core refuses: nothing changes on screen and the caller is told.
    func testRefusalKeepsWhatIsShown() async {
        let d = FakeDevice()
        let store = AvatarStore(core: CoreService(device: d, runner: DirectRunner()))
        _ = await store.setEmoji("🦊", for: "a")
        d.avatarError = BarkingError.Locked
        let ok = await store.setEmoji("🐻", for: "a")
        XCTAssertFalse(ok)
        XCTAssertEqual(store.emoji["a"], "🦊")
    }

    func testUnreadableImageIsRefused() async {
        let d = FakeDevice()
        let store = AvatarStore(core: CoreService(device: d, runner: DirectRunner()))
        let ok = await store.setPhoto(Data([1, 2, 3]), for: "a")
        XCTAssertFalse(ok)
        XCTAssertNil(d.avatars["a"])
    }
}
