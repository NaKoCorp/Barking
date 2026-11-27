import BarkingKit
import Foundation
import Observation

/// Settings › GIFs (spec GIF §9.3): the provider's consent and "Play GIFs
/// automatically", as the core holds them. One instance serves the Settings
/// row and the screen, so the row's subtitle follows a change at once.
@MainActor @Observable
final class GifSettingsModel {
    private let core: CoreService

    /// GIFs are on: a still accepted warning stands (here or synced).
    private(set) var enabled = false
    /// Play GIFs automatically; off by default, kept while GIFs are off.
    private(set) var autoLoad = false
    /// While on: the name of my other device they were turned on from
    /// ("another device" for one no longer listed); nil when turned on here.
    private(set) var enabledFrom: String?
    /// When the consent in force was given.
    private(set) var enabledAt: Date?
    /// The active provider: what the warning names and links. The value
    /// before `load` only stands in for the first frame.
    private(set) var provider = GifProviderInfo(id: 1, name: "Klipy", warningVersion: 1, privacyUrl: "")
    /// My other devices, which the consent applies to as well.
    private(set) var linkedDevices = 0
    /// The warning changed since the version accepted (spec §6.4). The FFI
    /// does not report an outdated consent yet: always false for now.
    private(set) var updated = false
    /// The last change was not stored: the screen shows what the core holds.
    private(set) var saveFailed = false

    init(core: CoreService) {
        self.core = core
    }

    func load() async {
        if let p = try? await core.gifProvider() { provider = p }
        linkedDevices = ((try? await core.myDevices()) ?? []).filter { !$0.thisDevice }.count
        await readSettings()
    }

    /// After "Use GIFs": the core records the warning version just shown.
    /// Throws when it did not store it (GIFs stay off). The settings are
    /// read in the write's own call: a read after it could wait on the sync
    /// it starts.
    func enable() async throws {
        do {
            let s = try await core.enableGifProvider(provider.id, warningVersion: provider.warningVersion)
            saveFailed = false
            if let s { apply(s) } else { enabled = true; enabledFrom = nil }
        } catch {
            saveFailed = true
            await readSettings()
            throw error
        }
    }

    /// Immediate, without confirmation.
    func disable() async {
        let previous = enabled
        enabled = false
        do {
            let s = try await core.disableGifProvider(provider.id)
            saveFailed = false
            if let s { apply(s) } else { enabledFrom = nil; enabledAt = nil }
        } catch {
            saveFailed = true
            enabled = previous
            await readSettings()
        }
    }

    func setAutoLoad(_ on: Bool) async {
        let previous = autoLoad
        autoLoad = on
        do {
            let s = try await core.setGifAutoLoad(on)
            saveFailed = false
            if let s { apply(s) }
        } catch {
            saveFailed = true
            autoLoad = previous
            await readSettings()
        }
    }

    private func readSettings() async {
        guard let s = try? await core.gifSettings() else { return }
        apply(s)
    }

    private func apply(_ s: GifSettingsInfo) {
        enabled = s.enabled
        autoLoad = s.autoLoad
        enabledFrom = s.enabled ? s.enabledFromOtherDevice : nil
        enabledAt = s.enabledAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }
}
