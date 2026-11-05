import BarkingKit
import UIKit
import Foundation
import Observation

/// Linking a new device, from the existing one (spec §5.8).
@MainActor @Observable
final class LinkModel {
    enum State: Equatable {
        case idle
        case offer(Data)
        case confirm(name: String)
        case share(URL)
        case refused(String)
    }

    private let core: CoreService
    private let inspect: (Data) throws -> String
    private(set) var state: State = .idle
    private var request: Data?
    private var accepting = false

    init(core: CoreService, inspect: @escaping (Data) throws -> String = { try inspectLinkRequest(request: $0) }) {
        self.core = core
        self.inspect = inspect
    }

    static func text(for reason: LinkReason) -> String {
        switch reason {
        case .expired: "This offer has expired. Start again."
        case .used: "This offer was already used. Start again."
        case .mismatch: "These codes do not belong together. Start again."
        case .unreadable: "This is not a Barking link file."
        case .noPending: "This device is not waiting for a link."
        case .notAdmin: "Only your first device can link new ones"
        }
    }

    private func fail(_ error: Error) {
        if case BarkingError.LinkRefused(let reason) = error { state = .refused(Self.text(for: reason)) }
        else { state = .refused("Something went wrong. Your data is safe.") }
    }

    func start() async {
        do { state = .offer(try await core.linkOffer()) } catch { fail(error) }
    }

    func scannedRequest(_ data: Data) async {
        do {
            let name = try inspect(data)
            request = data
            state = .confirm(name: name)
        } catch { fail(error) }
    }

    /// Accepts once: a second tap would find the offer used.
    func accept(history: Bool) async {
        guard !accepting, let request, case .confirm(let name) = state else { return }
        accepting = true
        defer { accepting = false }
        do {
            let package = try await core.linkDevice(request: request, history: history)
            let url = FileManager.default.temporaryDirectory.appending(path: Self.fileName(for: name))
            try package.write(to: url, options: .completeFileProtection)
            state = .share(url)
        } catch { fail(error) }
    }

    /// The remote device's name never decides a path: letters, digits, `-`
    /// and `_` only, `device` when nothing is left.
    static func fileName(for name: String) -> String {
        var out = ""
        var dash = false
        for ch in name.unicodeScalars {
            if CharacterSet.alphanumerics.contains(ch) || ch == "_" {
                out.unicodeScalars.append(ch)
                dash = false
            } else if !dash, !out.isEmpty {
                out.append("-")
                dash = true
            }
        }
        while out.hasSuffix("-") { out.removeLast() }
        return (out.isEmpty ? "device" : String(out.prefix(48))) + ".barkinglink"
    }

    /// Deletes the shared package (it holds the history, encrypted with the
    /// offer's secret).
    func cleanup() {
        if case .share(let url) = state { try? FileManager.default.removeItem(at: url) }
    }
}

/// Linking this device to an existing identity (onboarding, or resumed at
/// launch when a link is pending).
@MainActor @Observable
final class NewDeviceLinkModel {
    enum State: Equatable { case scanOffer, request(Data), waiting, done, refused(String) }

    typealias Begin = (Data, String) async throws -> (CoreService, Data)

    private(set) var state: State
    private(set) var core: CoreService?
    private let begin: Begin
    private let reset: () throws -> Void
    private let defaults: UserDefaults
    private var busy = false
    var deviceName = UIDevice.current.model

    init(resume: CoreService? = nil,
         begin: @escaping Begin = NewDeviceLinkModel.beginWithFactory,
         reset: @escaping () throws -> Void = DeviceFactory.resetIdentity,
         defaults: UserDefaults = .standard) {
        self.core = resume
        self.state = resume == nil ? .scanOffer : .waiting
        self.begin = begin
        self.reset = reset
        self.defaults = defaults
    }

    static func beginWithFactory(offer: Data, name: String) async throws -> (CoreService, Data) {
        let pending = try await DeviceCall.run("begin") { try DeviceFactory.beginLink(offer: offer, deviceName: name) }
        return (CoreService(device: pending.device, runner: AppCallRunner()), pending.request)
    }

    /// Begins once: the scanner may fire again while it runs.
    func scannedOffer(_ offer: Data) async {
        guard !busy, state == .scanOffer else { return }
        busy = true
        defer { busy = false }
        do {
            let (c, request) = try await begin(offer, deviceName)
            core = c
            state = .request(request)
        } catch BarkingError.LinkRefused(let reason) {
            state = .refused(LinkModel.text(for: reason))
        } catch {
            state = .refused("Something went wrong. Your data is safe.")
        }
    }

    func received(package: Data) async {
        guard let core, !busy else { return }
        busy = true
        defer { busy = false }
        do {
            try await core.finishLink(package)
            // A linked device has no phrase of its own to write down.
            defaults.set(true, forKey: OnboardingModel.confirmedKey)
            state = .done
        } catch BarkingError.LinkRefused(let reason) {
            state = .refused(LinkModel.text(for: reason))
        } catch {
            state = .refused("Something went wrong. Your data is safe.")
        }
    }

    /// Drops the pending link (it holds nothing yet) and starts over. Its
    /// service stops first: no call may hold the files being erased.
    func startAgain() async {
        await core?.close()
        do {
            try reset()
        } catch {
            // The wipe's marker stays: a new link finishes it first.
            state = .refused("Something went wrong. Your data is safe.")
            return
        }
        core = nil
        state = .scanOffer
    }
}
