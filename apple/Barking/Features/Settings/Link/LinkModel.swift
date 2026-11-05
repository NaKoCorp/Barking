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

    init(core: CoreService, inspect: @escaping (Data) throws -> String = { try inspectLinkRequest(request: $0) }) {
        self.core = core
        self.inspect = inspect
    }

    static func text(for reason: LinkReason) -> String {
        switch reason {
        case .expired: String(localized: "This offer has expired. Start again.")
        case .used: String(localized: "This offer was already used. Start again.")
        case .mismatch: String(localized: "These codes do not belong together. Start again.")
        case .unreadable: String(localized: "This is not a Barking link file.")
        case .noPending: String(localized: "This device is not waiting for a link.")
        case .notAdmin: String(localized: "Only your first device can link new ones")
        }
    }

    private func fail(_ error: Error) {
        if case BarkingError.LinkRefused(let reason) = error { state = .refused(Self.text(for: reason)) }
        else { state = .refused(String(localized: "Something went wrong. Your data is safe.")) }
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

    func accept(history: Bool) async {
        guard let request, case .confirm(let name) = state else { return }
        do {
            let package = try await core.linkDevice(request: request, history: history)
            let url = FileManager.default.temporaryDirectory.appending(path: "\(name).barkinglink")
            try package.write(to: url, options: .completeFileProtection)
            state = .share(url)
        } catch { fail(error) }
    }
}

/// Linking this device to an existing identity (onboarding).
@MainActor @Observable
final class NewDeviceLinkModel {
    enum State: Equatable { case scanOffer, request(Data), waiting, done, refused(String) }

    private(set) var state: State = .scanOffer
    private(set) var core: CoreService?
    var deviceName = UIDevice.current.model

    func scannedOffer(_ offer: Data) async {
        let name = deviceName
        do {
            let pending = try await DeviceCall.run("begin") { try DeviceFactory.beginLink(offer: offer, deviceName: name) }
            core = CoreService(device: pending.device, runner: AppCallRunner())
            state = .request(pending.request)
        } catch BarkingError.LinkRefused(let reason) {
            state = .refused(LinkModel.text(for: reason))
        } catch {
            state = .refused(String(localized: "Something went wrong. Your data is safe."))
        }
    }

    func received(package: Data) async {
        guard let core else { return }
        do {
            try await core.finishLink(package)
            state = .done
        } catch BarkingError.LinkRefused(let reason) {
            state = .refused(LinkModel.text(for: reason))
        } catch {
            state = .refused(String(localized: "Something went wrong. Your data is safe."))
        }
    }
}
