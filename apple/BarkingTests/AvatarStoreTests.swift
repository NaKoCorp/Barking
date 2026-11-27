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

    /// Any picked image becomes the centre square, 192 px, a JPEG the core takes.
    func testPhotoIsASmallSquareJPEG() throws {
        let data = try XCTUnwrap(AvatarStore.jpeg(from: image(4000, 3000)))
        XCTAssertLessThanOrEqual(data.count, AvatarStore.maxBytes)
        XCTAssertEqual(Array(data.prefix(2)), [0xFF, 0xD8], "a JPEG")
        let decoded = try XCTUnwrap(UIImage(data: data))
        XCTAssertEqual(decoded.size, CGSize(width: 192, height: 192))
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
