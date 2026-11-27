import BarkingKit
import Observation
import UIKit

/// The avatars I gave my contacts: an emoji or a photo, kept in the core's
/// encrypted database and synchronized with my linked devices (never sent
/// to the contact).
/// Shared by every screen through the environment, so a change shows at
/// once in the lists, the conversation and the contact page.
@MainActor @Observable
final class AvatarStore {
    private let core: CoreService
    private(set) var emoji: [String: String] = [:]
    private(set) var photos: [String: UIImage] = [:]

    /// The side of a stored photo, in pixels: sharp in the lists (44 pt)
    /// and small enough to reach my other devices in one packet.
    static let side: CGFloat = 128
    /// The core's limit: a photo travels to my devices in one packet.
    static var maxBytes: Int { Int(avatarPhotoMaxBytes()) }

    init(core: CoreService) { self.core = core }

    func has(_ fingerprint: String) -> Bool { emoji[fingerprint] != nil || photos[fingerprint] != nil }

    /// Reads them all again; a failed read keeps what is shown. A photo
    /// saved larger than the core now syncs (an earlier, local-only
    /// build) is made small again, which sends it to my other devices.
    func reload() async {
        guard let entries = try? await core.contactAvatars() else { return }
        var emoji: [String: String] = [:]
        var photos: [String: UIImage] = [:]
        var oversize: [(String, Data)] = []
        for entry in entries {
            switch entry.avatar {
            case .emoji(let value): emoji[entry.fingerprint] = value
            case .photo(let jpeg):
                if let image = UIImage(data: jpeg) { photos[entry.fingerprint] = image }
                if jpeg.count > Self.maxBytes { oversize.append((entry.fingerprint, jpeg)) }
            }
        }
        self.emoji = emoji
        self.photos = photos
        for (fingerprint, jpeg) in oversize { _ = await setPhoto(jpeg, for: fingerprint) }
    }

    func setEmoji(_ value: String, for contact: String) async -> Bool {
        await save(.emoji(value: value), for: contact)
    }

    /// The picked image, cropped to its centre square and made small
    /// enough for the core. False if it could not be read or saved.
    func setPhoto(_ data: Data, for contact: String) async -> Bool {
        guard let image = UIImage(data: data), let jpeg = Self.jpeg(from: image) else { return false }
        return await save(.photo(jpeg: jpeg), for: contact)
    }

    func clear(_ contact: String) async -> Bool { await save(nil, for: contact) }

    private func save(_ avatar: ContactAvatar?, for contact: String) async -> Bool {
        guard (try? await core.setContactAvatar(contact, avatar)) != nil else { return false }
        await reload()
        return true
    }

    /// The centre square of `image`, `side` pixels wide, as a JPEG under
    /// `maxBytes`: the quality steps down until it fits. Nil if it never
    /// does or the image cannot be drawn.
    static func jpeg(from image: UIImage, side: CGFloat = side, maxBytes: Int = maxBytes) -> Data? {
        let size = image.size
        guard size.width > 0, size.height > 0 else { return nil }
        let scale = side / min(size.width, size.height)
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        format.opaque = true
        let square = UIGraphicsImageRenderer(size: CGSize(width: side, height: side), format: format).image { _ in
            let drawn = CGSize(width: size.width * scale, height: size.height * scale)
            image.draw(in: CGRect(x: (side - drawn.width) / 2, y: (side - drawn.height) / 2,
                                  width: drawn.width, height: drawn.height))
        }
        for quality in stride(from: 0.8, through: 0.2, by: -0.1) {
            if let data = square.jpegData(compressionQuality: quality), data.count <= maxBytes { return data }
        }
        return nil
    }
}
