import Foundation

@MainActor
protocol TunPermissionRepository: AnyObject {
    func hasRequiredPermissions(binaryPath: String) -> Bool
    func validateCurrentPermissions(binaryPath: String) throws
    /// Installs the privileged core through the helper, behind an administrator
    /// prompt. Returns the SHA-256 of the installed bytes.
    @discardableResult
    func installPrivilegedCore(binaryPath: String) async throws -> String
    /// True when an older ClashBar left a setuid-root bit on the user-managed
    /// core. The app surfaces this so the user can clean it up.
    func legacySetuidPresent(binaryPath: String) -> Bool
    /// Fallback instructions for when the helper is unreachable. The app never
    /// performs root file operations itself.
    func installCommand(binaryPath: String) -> String
    func legacyCleanupCommand(binaryPath: String) -> String
}
