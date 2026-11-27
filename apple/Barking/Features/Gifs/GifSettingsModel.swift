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
    /// The active provider, as the core names it: what the warning names
    /// and links. Nil until `load` read it: nothing can be turned on then,
    /// and no settings are shown.
    private(set) var provider: GifProviderInfo?
    /// My other devices, which the consent applies to as well.
    private(set) var linkedDevices = 0
    /// The warning changed since the version accepted (spec §6.4): GIFs are
    /// off and the warning shows again with "Updated".
    private(set) var updated = false
    /// The last change was not stored: the screen shows what the core holds.
    private(set) var saveFailed = false

    init(core: CoreService) {
        self.core = core
    }

    func load() async {
        if provider == nil { provider = try? await core.gifProvider() }
        linkedDevices = ((try? await core.myDevices()) ?? []).filter { !$0.thisDevice }.count
        await readSettings()
    }

    /// The settings again, as the core holds them now (changed in Settings,
    /// or by a sync from another of my devices).
    func refresh() async {
        if provider == nil { await load() } else { await readSettings() }
    }

    /// After "Use GIFs": the core records the warning version just shown.
    /// Throws when it did not store it (GIFs stay off). The settings are
    /// read in the write's own call: a read after it could wait on the sync
    /// it starts.
    func enable() async throws {
        // Never a provider or a warning version the core did not name.
        guard let provider else { throw GifSettingsError.providerNotLoaded }
        do {
            let s = try await core.enableGifProvider(provider.id, warningVersion: provider.warningVersion)
            saveFailed = false
            if let s { apply(s) } else { enabled = true; enabledFrom = nil; updated = false }
        } catch {
            saveFailed = true
            await readSettings()
            throw error
        }
    }

    /// Immediate, without confirmation.
    func disable() async {
        guard let provider else { return }
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

    /// Only once the provider is known: the settings are its settings.
    private func readSettings() async {
        guard provider != nil, let s = try? await core.gifSettings() else { return }
        apply(s)
    }

    private func apply(_ s: GifSettingsInfo) {
        enabled = s.enabled
        autoLoad = s.autoLoad
        enabledFrom = s.enabled ? s.enabledFromOtherDevice : nil
        enabledAt = s.enabledAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
        updated = !s.enabled && s.consentOutdated
    }
}

enum GifSettingsError: Error {
    /// `enable` before `load` read the provider from the core.
    case providerNotLoaded
}
