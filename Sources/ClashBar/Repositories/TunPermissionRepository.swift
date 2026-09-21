import Foundation

@MainActor
protocol TunPermissionRepository: AnyObject {
    func hasRequiredPermissions(binaryPath: String) -> Bool
    func validateCurrentPermissions(binaryPath: String) throws
    func grantPermissions(binaryPath: String) async throws
    /// True when an older ClashBar left a setuid-root bit on the user-managed
    /// core. The app surfaces this so the user can clean it up.
    func legacySetuidPresent(binaryPath: String) -> Bool
    /// The command the user runs to install the privileged core. The app never
    /// performs root file operations itself.
    func installCommand(binaryPath: String) -> String
    func legacyCleanupCommand(binaryPath: String) -> String
}
