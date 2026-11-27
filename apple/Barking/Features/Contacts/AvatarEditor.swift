import PhotosUI
import SwiftUI

/// The contact page's avatar, as a menu: a photo from the library, an
/// emoji, or back to the initial. A small pencil says it can be changed.
/// What is chosen reaches my linked devices, never the contact (`AvatarStore`).
struct AvatarEditor: View {
    let name: String
    let fingerprint: String
    var size: CGFloat = 64
    @Environment(AvatarStore.self) private var store: AvatarStore?
    @State private var pickingPhoto = false
    @State private var photoItem: PhotosPickerItem?
    @State private var pickingEmoji = false
    @State private var failed = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            Menu {
                Button { pickingPhoto = true } label: { Label("Choose a photo", systemImage: "photo") }
                Button { pickingEmoji = true } label: { Label("Choose an emoji", systemImage: "face.smiling") }
                if store?.has(fingerprint) == true {
                    Button(role: .destructive) { run { await $0.clear(fingerprint) } } label: {
                        Label("Remove the avatar", systemImage: "xmark.circle")
                    }
                }
            } label: {
                Avatar(name: name, fingerprint: fingerprint, size: size)
                    .overlay(alignment: .bottomTrailing) {
                        Image(systemName: "pencil")
                            .font(.bSymbol(11, weight: .semibold, maximum: 16))
                            .foregroundStyle(Color.fgMuted)
                            .frame(width: 24, height: 24)
                            .background(Color.surfaceCard, in: .circle)
                            .overlay(Circle().stroke(Color.border, lineWidth: 1))
                            .offset(x: 2, y: 2)
                    }
                    .contentShape(.circle)
            }
            .disabled(store == nil)
            .accessibilityLabel(Text("Avatar of \(name)"))
            .accessibilityHint(Text("Choose a photo or an emoji. Your linked devices get it, not the contact."))
            .accessibilityIdentifier("contact.avatar")
            if failed {
                Text("Not saved. Try again.").font(.bMeta).foregroundStyle(Color.danger)
            }
        }
        .photosPicker(isPresented: $pickingPhoto, selection: $photoItem, matching: .images)
        .onChange(of: photoItem) { _, item in
            guard let item else { return }
            photoItem = nil
            run { store in
                guard let data = try? await item.loadTransferable(type: Data.self) else { return false }
                return await store.setPhoto(data, for: fingerprint)
            }
        }
        .sheet(isPresented: $pickingEmoji) {
            EmojiPicker(title: "Choose an emoji") { emoji in run { await $0.setEmoji(emoji, for: fingerprint) } }
                .presentationDetents([.medium])
        }
    }

    /// Runs a change on the store and says if it failed.
    private func run(_ change: @escaping (AvatarStore) async -> Bool) {
        guard let store else { return }
        Task {
            let ok = await change(store)
            failed = !ok
            (ok ? Haptic.success : Haptic.error).play()
        }
    }
}
