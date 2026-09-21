import CryptoKit
import Darwin
import Foundation
import ProxyHelperShared

enum TunPermissionServiceError: LocalizedError {
    case coreBinaryNotFound
    case coreBinaryNotExecutable
    /// No privileged core installed yet. Carries the command the user must run.
    case permissionMissing(command: String)
    /// A privileged core exists but its bytes differ from the managed core.
    case privilegedCoreStale(command: String)
    /// Installed but fails a trust check (wrong owner, group/world writable,
    /// symlink, unexpected setuid bit).
    case privilegedCoreNotTrusted(String)
    case hashingFailed(String)

    var errorDescription: String? {
        switch self {
        case .coreBinaryNotFound:
            "mihomo binary not found."
        case .coreBinaryNotExecutable:
            "mihomo binary is not executable."
        case let .permissionMissing(command):
            "TUN mode needs a root-owned copy of the core. Run:\n\(command)"
        case let .privilegedCoreStale(command):
            "The privileged core is out of date. Run:\n\(command)"
        case let .privilegedCoreNotTrusted(reason):
            "The installed privileged core is not trustworthy: \(reason)"
        case let .hashingFailed(message):
            "Failed to hash the mihomo core: \(message)"
        }
    }
}

/// Verifies the *privileged* copy of the mihomo core. **Performs no privileged
/// operations of its own.**
///
/// History worth keeping, because it is the whole point of this file:
///
/// 1. Upstream made the user-owned core setuid-root in place. That left a
///    root-executable binary inside a user-writable directory reading a
///    user-writable config — any local process running as that user could invoke
///    it with arguments of its own choosing.
/// 2. The first attempt at a fix copied the core into a root-owned directory via
///    one `osascript ... with administrator privileges` prompt. That was **worse**:
///    `/Library/Application Support` is `root:admin 0775` and the console user is
///    normally in `admin`, so an attacker could pre-create
///    `…/ClashBar/core` as a symlink. `chmod` follows symlinks and
///    `install` writes through them, so one approved prompt yielded a root-owned
///    `0755` write to an attacker-chosen path. An inline `sh -c` running as root
///    cannot be made safe against a local attacker who can loop — `test -L`
///    only narrows the race.
///
/// So this type now does **zero** root file operations. Installation is an
/// explicit, user-run `install(1)` command; the app only reports whether the
/// result is trustworthy. A proper in-helper installer (an `openat`/`mkdirat`
/// chain gated on an Authorization Services right) is the follow-up, and it is
/// the only version that can be both automatic and safe.
struct TunPermissionService {
    // MARK: - The command the user runs

    /// Single source of truth for the install step, so the error text, the log
    /// line and the docs cannot drift apart.
    static func installCommand(managedBinaryPath: String) -> String {
        let core = ProxyHelperConstants.privilegedCoreBinaryPath
        let root = ProxyHelperConstants.privilegedRootPath
        return """
        sudo mkdir -p \(shellQuoted(ProxyHelperConstants.privilegedCoreDirectoryPath)) && \\
        sudo chown -R root:wheel \(shellQuoted(root)) && \\
        sudo chmod 755 \(shellQuoted(root)) \(shellQuoted(ProxyHelperConstants.privilegedCoreDirectoryPath)) && \\
        sudo install -o root -g wheel -m 755 \(shellQuoted(managedBinaryPath)) \(shellQuoted(core))
        """
    }

    /// Clears a setuid bit left by an older ClashBar. Also user-run: dropping a
    /// setuid bit needs root, and we no longer take root for file operations.
    static func legacyCleanupCommand(managedBinaryPath: String) -> String {
        "sudo chmod u-s \(shellQuoted(managedBinaryPath)) && " +
            "sudo chown \(getuid()):\(getgid()) \(shellQuoted(managedBinaryPath))"
    }

    // MARK: - Queries

    func hasRequiredPermissions(binaryPath: String) -> Bool {
        (try? self.validateCurrentPermissions(binaryPath: binaryPath)) != nil
    }

    func validateCurrentPermissions(binaryPath: String) throws {
        let managedPath = try self.validateBinaryPath(binaryPath)
        let command = Self.installCommand(managedBinaryPath: managedPath)

        try self.validatePrivilegedCoreTrust(installCommand: command)

        let managedDigest = try self.sha256Hex(ofFileAt: managedPath)
        let privilegedDigest = try self.sha256Hex(ofFileAt: ProxyHelperConstants.privilegedCoreBinaryPath)
        guard managedDigest == privilegedDigest else {
            throw TunPermissionServiceError.privilegedCoreStale(command: command)
        }
    }

    /// True when an older ClashBar left a setuid bit, or left the managed core
    /// owned by root. Either state is a local privilege-escalation primitive the
    /// user should be told about even if they never enable TUN again.
    func legacySetuidPresent(binaryPath: String) -> Bool {
        let path = binaryPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty else { return false }
        var st = stat()
        guard lstat(path, &st) == 0 else { return false }
        return (st.st_mode & mode_t(S_ISUID)) != 0 || st.st_uid == 0
    }

    /// Installs the privileged core via the helper, behind an administrator
    /// prompt.
    ///
    /// Note what this method does **not** do: it performs no file operations
    /// itself. The app is unprivileged, the helper is already root, and the
    /// password dialog is what authorises *these bytes* to run as root. See the
    /// type comment for why doing the copy here — as the earlier `osascript`
    /// version did — is unsafe at any level of shell hardening.
    func installPrivilegedCore(binaryPath: String, service: PrivilegedCoreService) async throws -> String {
        let managedPath = try self.validateBinaryPath(binaryPath)
        let digest = try await service.installPrivilegedCore()
        // Confirm the helper really produced a core we would be willing to run.
        try self.validateCurrentPermissions(binaryPath: managedPath)
        return digest
    }

    // MARK: - Trust checks

    private func validatePrivilegedCoreTrust(installCommand: String) throws {
        for directory in [
            ProxyHelperConstants.privilegedRootPath,
            ProxyHelperConstants.privilegedCoreDirectoryPath,
        ] {
            var st = stat()
            guard lstat(directory, &st) == 0 else {
                throw TunPermissionServiceError.permissionMissing(command: installCommand)
            }
            guard (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR) else {
                throw TunPermissionServiceError.privilegedCoreNotTrusted("\(directory) is not a directory")
            }
            guard st.st_uid == 0 else {
                throw TunPermissionServiceError.privilegedCoreNotTrusted("\(directory) is not owned by root")
            }
            // This is the check that would have caught the pre-created-symlink
            // attack: `root:admin 0775` fails it.
            guard (st.st_mode & mode_t(S_IWGRP | S_IWOTH)) == 0 else {
                throw TunPermissionServiceError.privilegedCoreNotTrusted("\(directory) is group/world writable")
            }
        }

        let path = ProxyHelperConstants.privilegedCoreBinaryPath
        var st = stat()
        guard lstat(path, &st) == 0 else {
            throw TunPermissionServiceError.permissionMissing(command: installCommand)
        }
        guard (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw TunPermissionServiceError.privilegedCoreNotTrusted("not a regular file")
        }
        guard st.st_uid == 0 else {
            throw TunPermissionServiceError.privilegedCoreNotTrusted("owner is uid \(st.st_uid), expected root")
        }
        guard (st.st_mode & mode_t(S_IWGRP | S_IWOTH)) == 0 else {
            throw TunPermissionServiceError.privilegedCoreNotTrusted("writable by group or others")
        }
        guard (st.st_mode & mode_t(S_IXUSR)) != 0 else {
            throw TunPermissionServiceError.privilegedCoreNotTrusted("not executable")
        }
        guard (st.st_mode & mode_t(S_ISUID)) == 0 else {
            throw TunPermissionServiceError.privilegedCoreNotTrusted("unexpected setuid bit")
        }
    }

    private func validateBinaryPath(_ binaryPath: String) throws -> String {
        let resolved = binaryPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !resolved.isEmpty else { throw TunPermissionServiceError.coreBinaryNotFound }
        guard FileManager.default.fileExists(atPath: resolved) else {
            throw TunPermissionServiceError.coreBinaryNotFound
        }
        guard FileManager.default.isExecutableFile(atPath: resolved) else {
            throw TunPermissionServiceError.coreBinaryNotExecutable
        }
        return resolved
    }

    // MARK: - Hashing

    private func sha256Hex(ofFileAt path: String) throws -> String {
        guard let handle = FileHandle(forReadingAtPath: path) else {
            throw TunPermissionServiceError.hashingFailed("cannot open \(path)")
        }
        defer { try? handle.close() }

        var hasher = SHA256()
        do {
            while let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty {
                hasher.update(data: chunk)
            }
        } catch {
            throw TunPermissionServiceError.hashingFailed(error.localizedDescription)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func shellQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\"'\"'"))'"
    }
}

@MainActor
final class DefaultTunPermissionRepository: TunPermissionRepository {
    private let service: TunPermissionService
    private let privilegedCoreService: PrivilegedCoreService

    init(service: TunPermissionService, privilegedCoreService: PrivilegedCoreService = PrivilegedCoreService()) {
        self.service = service
        self.privilegedCoreService = privilegedCoreService
    }

    func hasRequiredPermissions(binaryPath: String) -> Bool {
        self.service.hasRequiredPermissions(binaryPath: binaryPath)
    }

    func validateCurrentPermissions(binaryPath: String) throws {
        try self.service.validateCurrentPermissions(binaryPath: binaryPath)
    }

    @discardableResult
    func installPrivilegedCore(binaryPath: String) async throws -> String {
        try await self.service.installPrivilegedCore(
            binaryPath: binaryPath,
            service: self.privilegedCoreService)
    }

    func legacySetuidPresent(binaryPath: String) -> Bool {
        self.service.legacySetuidPresent(binaryPath: binaryPath)
    }

    func installCommand(binaryPath: String) -> String {
        TunPermissionService.installCommand(managedBinaryPath: binaryPath)
    }

    func legacyCleanupCommand(binaryPath: String) -> String {
        TunPermissionService.legacyCleanupCommand(managedBinaryPath: binaryPath)
    }
}
