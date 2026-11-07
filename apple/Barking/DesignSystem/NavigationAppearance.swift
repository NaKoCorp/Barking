import UIKit

/// Native navigation titles in Fira Code (UI review U-5): large 30 pt with
/// -0.5 tracking, inline 17 pt, both in `fg` and scaled with Dynamic Type.
/// The bars keep their native collapse, back titles and VoiceOver headers.
/// Called at launch and again when the text size changes.
enum BarkingNavigationAppearance {
    @MainActor private static var observer: NSObjectProtocol?

    @MainActor
    static func apply() {
        let large = font(size: 30, style: .largeTitle, maximum: 48)
        let inline = font(size: 17, style: .headline, maximum: 28)
        let fg = UIColor(named: "fg") ?? .label
        let largeAttributes: [NSAttributedString.Key: Any] = [.font: large, .foregroundColor: fg, .kern: CGFloat(-0.5)]
        let inlineAttributes: [NSAttributedString.Key: Any] = [.font: inline, .foregroundColor: fg]

        // Only the titles change: the background stays the system's, so the
        // scroll edge effect still softens content passing under the bar
        // (with no scroll-edge appearance, UIKit derives it from this one).
        let standard = UINavigationBarAppearance()
        standard.largeTitleTextAttributes = largeAttributes
        standard.titleTextAttributes = inlineAttributes

        let proxy = UINavigationBar.appearance()
        proxy.standardAppearance = standard
        proxy.compactAppearance = standard

        // Bars already on screen do not read the proxy again.
        for scene in UIApplication.shared.connectedScenes {
            for window in (scene as? UIWindowScene)?.windows ?? [] {
                for bar in navigationBars(in: window) {
                    bar.standardAppearance = standard
                    bar.compactAppearance = standard
                }
            }
        }

        if observer == nil {
            observer = NotificationCenter.default.addObserver(
                forName: UIContentSizeCategory.didChangeNotification, object: nil, queue: .main
            ) { _ in MainActor.assumeIsolated { apply() } }
        }
    }

    private static func font(size: CGFloat, style: UIFont.TextStyle, maximum: CGFloat) -> UIFont {
        let base = UIFont(name: "FiraCode-SemiBold", size: size) ?? .systemFont(ofSize: size, weight: .semibold)
        return UIFontMetrics(forTextStyle: style).scaledFont(for: base, maximumPointSize: maximum)
    }

    private static func navigationBars(in view: UIView) -> [UINavigationBar] {
        (view as? UINavigationBar).map { [$0] } ?? view.subviews.flatMap(navigationBars(in:))
    }
}
