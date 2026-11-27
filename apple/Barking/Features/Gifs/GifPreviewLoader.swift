import Foundation

/// Which picker preview URLs may be fetched: Klipy's media hosts only,
/// HTTPS on 443, no user info (spec GIF global constraints). The same rule
/// as the core's for the URLs it fetches itself.
enum GifPreviewPolicy {
    static let hosts: Set<String> = ["static.klipy.com", "static1.klipy.com", "static2.klipy.com"]

    /// The URL as given (never rewritten), if it may be fetched.
    static func url(_ string: String) -> URL? {
        guard let c = URLComponents(string: string), c.scheme == "https", let host = c.host,
              hosts.contains(host), c.port == nil || c.port == 443, c.user == nil, c.password == nil,
              let url = c.url else { return nil }
        return url
    }
}

/// Fetches the small MP4 of a picker cell. Reached only from the picker,
/// itself reachable only with GIFs on: each preview is a request to Klipy
/// that the user accepted in the warning. Nothing is kept on disk: an
/// ephemeral session without cache, cookies or credentials; what a picker
/// fetched lives in memory until that picker closes (`GifPreviewStore`).
final class GifPreviewLoader: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    static let shared = GifPreviewLoader()
    /// The core's bound for a GIF's media.
    static let maxBytes = 8 * 1024 * 1024
    static let timeout: TimeInterval = 15

    private lazy var session = URLSession(configuration: Self.configuration(), delegate: self, delegateQueue: nil)

    /// Nothing kept, nothing that identifies the phone beyond its address:
    /// the constant user agent the core sends, no language list.
    static func configuration() -> URLSessionConfiguration {
        let c = URLSessionConfiguration.ephemeral
        c.urlCache = nil
        c.httpCookieStorage = nil
        c.httpShouldSetCookies = false
        c.httpCookieAcceptPolicy = .never
        c.urlCredentialStorage = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.timeoutIntervalForRequest = timeout
        c.timeoutIntervalForResource = timeout
        c.httpMaximumConnectionsPerHost = 4
        c.httpAdditionalHeaders = ["User-Agent": "Barking", "Accept-Language": "*"]
        return c
    }

    /// The preview's bytes, or nil: a URL outside the policy, an error, a
    /// status other than 200, or more than `maxBytes`.
    func data(for string: String) async -> Data? {
        #if BARKING_DEV
        // UI tests never reach Klipy.
        if UITestNetwork.isolated { return nil }
        #endif
        guard let url = GifPreviewPolicy.url(string) else { return nil }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: Self.timeout)
        request.httpShouldHandleCookies = false
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                  http.expectedContentLength <= Self.maxBytes else { return nil }
            var data = Data()
            if http.expectedContentLength > 0 { data.reserveCapacity(Int(http.expectedContentLength)) }
            for try await byte in bytes {
                guard data.count < Self.maxBytes else { return nil }
                data.append(byte)
            }
            return data
        } catch {
            return nil
        }
    }

    /// No redirect is followed: the host would no longer be checked.
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}

/// The previews one open picker fetched, in memory; dropped with it.
@MainActor
final class GifPreviewStore {
    private var data: [String: Data] = [:]
    private var running: [String: Task<Data?, Never>] = [:]
    private let loader: GifPreviewLoader

    init(loader: GifPreviewLoader = .shared) { self.loader = loader }

    func preview(_ url: String) async -> Data? {
        if let d = data[url] { return d }
        if let t = running[url] { return await t.value }
        let loader = loader
        let task = Task { await loader.data(for: url) }
        running[url] = task
        let d = await task.value
        running[url] = nil
        if let d { data[url] = d }
        return d
    }

    func clear() {
        running.values.forEach { $0.cancel() }
        running = [:]
        data = [:]
    }
}
