import Foundation

@MainActor
protocol TunPermissionRepository: AnyObject {
    func hasRequiredPermissions(binaryPath: String) -> Bool
    func validateCurrentPermissions(binaryPath: String) throws
    func grantPermissions(binaryPath: String) async throws
    /// True when an older ClashBar left a setuid-root bit on the user-managed
    /// core. The app uses this to offer a one-click cleanup.
    func legacySetuidPresent(binaryPath: String) -> Bool
}
