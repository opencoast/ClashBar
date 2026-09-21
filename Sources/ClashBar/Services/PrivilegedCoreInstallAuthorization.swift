import Foundation
import ProxyHelperShared
import Security

enum PrivilegedInstallAuthorizationError: LocalizedError {
    case cancelled
    case denied(OSStatus)
    case unavailable(OSStatus)

    var errorDescription: String? {
        switch self {
        case .cancelled:
            "Administrator authorization was cancelled."
        case let .denied(status):
            "Administrator authorization was denied (OSStatus \(status))."
        case let .unavailable(status):
            "Could not start administrator authorization (OSStatus \(status))."
        }
    }
}

/// Raises the system password dialog for the install right and serialises the
/// resulting authorization so the helper can verify it.
///
/// This prompt is the anchor of the whole trust chain, not a formality. The
/// managed core lives in a user-writable directory, so "install whatever is at
/// that path as root" would otherwise be a root privilege escalation for any
/// local process running as the user: overwrite the core, wait for the user to
/// toggle TUN, done. The one thing such an attacker cannot produce is the
/// user's password.
///
/// Consequently the right is registered with `timeout: 0`, so the credential is
/// never cached and installing different bytes always re-prompts.
enum PrivilegedCoreInstallAuthorization {
    /// Blocks on the system dialog; call off the main thread.
    static func requestExternalForm() throws -> Data {
        var authRef: AuthorizationRef?
        let createStatus = AuthorizationCreate(nil, nil, [], &authRef)
        guard createStatus == errAuthorizationSuccess, let authRef else {
            throw PrivilegedInstallAuthorizationError.unavailable(createStatus)
        }
        defer { AuthorizationFree(authRef, []) }

        var copyStatus: OSStatus = errAuthorizationInternal
        ProxyHelperConstants.installCoreRightName.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                copyStatus = AuthorizationCopyRights(
                    authRef,
                    &rights,
                    nil,
                    [.interactionAllowed, .extendRights, .preAuthorize],
                    nil)
            }
        }

        switch copyStatus {
        case errAuthorizationSuccess:
            break
        case errAuthorizationCanceled:
            throw PrivilegedInstallAuthorizationError.cancelled
        default:
            throw PrivilegedInstallAuthorizationError.denied(copyStatus)
        }

        var externalForm = AuthorizationExternalForm()
        let formStatus = AuthorizationMakeExternalForm(authRef, &externalForm)
        guard formStatus == errAuthorizationSuccess else {
            throw PrivilegedInstallAuthorizationError.unavailable(formStatus)
        }
        return withUnsafeBytes(of: externalForm) { Data($0) }
    }
}
