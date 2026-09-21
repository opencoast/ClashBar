import CryptoKit
import Darwin
import Foundation
import ProxyHelperShared

enum TunPermissionServiceError: LocalizedError {
    case coreBinaryNotFound
    case coreBinaryNotExecutable
    case permissionMissing
    case authorizationCancelled
    case authorizationFailed(String)
    case permissionVerificationFailed
    /// A privileged core is installed but its bytes no longer match the core the
    /// app manages, i.e. the user updated `~/.../clashbar/core/mihomo`.
    case privilegedCoreStale
    /// The privileged core exists but fails a trust check (wrong owner, group or
    /// world writable, symlink, unexpected setuid bit).
    case privilegedCoreNotTrusted(String)
    case hashingFailed(String)

    var errorDescription: String? {
        switch self {
        case .coreBinaryNotFound:
            "mihomo binary not found."
        case .coreBinaryNotExecutable:
            "mihomo binary is not executable."
        case .permissionMissing:
            "No privileged mihomo core is installed for TUN mode."
        case .authorizationCancelled:
            "Administrator authorization was cancelled."
        case let .authorizationFailed(message):
            "Failed to install the privileged mihomo core: \(message)"
        case .permissionVerificationFailed:
            "The privileged mihomo core was not installed successfully."
        case .privilegedCoreStale:
            "The installed privileged core is older than the managed core."
        case let .privilegedCoreNotTrusted(reason):
            "The installed privileged core is not trustworthy: \(reason)"
        case let .hashingFailed(message):
            "Failed to hash the mihomo core: \(message)"
        }
    }
}

/// Installs and validates the *privileged* copy of the mihomo core.
///
/// The previous implementation made the user-owned core setuid-root in place.
/// That left a root-executable binary inside a user-writable directory reading a
/// user-writable config, which any local process running as that user could
/// invoke with arguments of its own choosing.
///
/// Instead we copy the core, once per version, into a root-owned directory under
/// `/Library/Application Support/ClashBar`, and let the privileged helper spawn
/// it with a fixed argument vector. The admin prompt is the user's consent to
/// trust *those bytes*; it no longer grants blanket setuid.
struct TunPermissionService {
    // Deliberately property-free: `grantPermissions` hands the install work to
    // `Task.detached`, whose closure is `@Sendable`. A stored `FileManager`
    // (which is not `Sendable`) would strip this struct's implicit `Sendable`
    // conformance and break that call site.

    // MARK: - Queries

    func hasRequiredPermissions(binaryPath: String) -> Bool {
        (try? self.validateCurrentPermissions(binaryPath: binaryPath)) != nil
    }

    func validateCurrentPermissions(binaryPath: String) throws {
        let managedPath = try self.validateBinaryPath(binaryPath)

        try self.validatePrivilegedCoreTrust()

        let managedDigest = try self.sha256Hex(ofFileAt: managedPath)
        let privilegedDigest = try self.sha256Hex(ofFileAt: ProxyHelperConstants.privilegedCoreBinaryPath)
        guard managedDigest == privilegedDigest else {
            throw TunPermissionServiceError.privilegedCoreStale
        }
    }

    /// True when a previous ClashBar version left a setuid bit on the
    /// user-managed core. Surfacing this lets the app offer to clean it up
    /// instead of silently leaving a local privilege-escalation primitive behind.
    func legacySetuidPresent(binaryPath: String) -> Bool {
        let path = binaryPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty else { return false }
        var st = stat()
        guard lstat(path, &st) == 0 else { return false }
        return (st.st_mode & mode_t(S_ISUID)) != 0 || st.st_uid == 0
    }

    // MARK: - Mutations

    func grantPermissions(binaryPath: String) async throws {
        let resolved = try self.validateBinaryPath(binaryPath)
        try await Task.detached(priority: .userInitiated) {
            try self.installPrivilegedCoreSynchronously(managedBinaryPath: resolved)
        }.value
    }

    // MARK: - Trust checks

    private func validatePrivilegedCoreTrust() throws {
        for directory in [
            ProxyHelperConstants.privilegedRootPath,
            ProxyHelperConstants.privilegedCoreDirectoryPath,
        ] {
            var st = stat()
            guard lstat(directory, &st) == 0 else {
                throw TunPermissionServiceError.permissionMissing
            }
            guard (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR) else {
                throw TunPermissionServiceError.privilegedCoreNotTrusted("\(directory) is not a directory")
            }
            guard st.st_uid == 0 else {
                throw TunPermissionServiceError.privilegedCoreNotTrusted("\(directory) is not owned by root")
            }
            guard (st.st_mode & mode_t(S_IWGRP | S_IWOTH)) == 0 else {
                throw TunPermissionServiceError.privilegedCoreNotTrusted("\(directory) is group/world writable")
            }
        }

        let path = ProxyHelperConstants.privilegedCoreBinaryPath
        var st = stat()
        guard lstat(path, &st) == 0 else {
            throw TunPermissionServiceError.permissionMissing
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

    // MARK: - Install

    private func installPrivilegedCoreSynchronously(managedBinaryPath: String) throws {
        let uid = getuid()
        let gid = getgid()

        let root = ProxyHelperConstants.privilegedRootPath
        let coreDir = ProxyHelperConstants.privilegedCoreDirectoryPath
        let runDir = ProxyHelperConstants.privilegedRunDirectoryPath
        let logDir = ProxyHelperConstants.privilegedLogDirectoryPath
        let corePath = ProxyHelperConstants.privilegedCoreBinaryPath
        let runtimeConfig = ProxyHelperConstants.privilegedRuntimeConfigPath

        // One prompt, one inline command. Deliberately not a temp script file:
        // a script read by root out of a user-writable path is swappable between
        // write and exec.
        let steps = [
            "/bin/mkdir -p \(q(coreDir)) \(q(runDir)) \(q(logDir))",
            "/usr/sbin/chown -R root:wheel \(q(root))",
            "/bin/chmod 755 \(q(root)) \(q(coreDir)) \(q(logDir))",
            "/bin/chmod 700 \(q(runDir))",
            "/usr/bin/install -o root -g wheel -m 755 \(q(managedBinaryPath)) \(q(corePath))",
            // Undo any setuid left by ClashBar <= 0.x and hand the managed copy
            // back to the user so the app can keep updating it normally.
            "/bin/chmod u-s \(q(managedBinaryPath))",
            "/usr/sbin/chown \(uid):\(gid) \(q(managedBinaryPath))",
            // A staged config from a previous core version must not be reused.
            "/bin/rm -f \(q(runtimeConfig))",
        ]

        try self.runAppleScriptSynchronously(
            "do shell script \"\(self.appleScriptEscaped(steps.joined(separator: " && ")))\" " +
                "with administrator privileges")

        do {
            try self.validateCurrentPermissions(binaryPath: managedBinaryPath)
        } catch {
            throw TunPermissionServiceError.permissionVerificationFailed
        }
    }

    private func runAppleScriptSynchronously(_ script: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            throw TunPermissionServiceError.authorizationFailed(error.localizedDescription)
        }

        guard process.terminationStatus == 0 else {
            let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let message = [stderr, stdout].first(where: { !$0.isEmpty }) ?? "Unknown authorization error."
            let lowered = message.lowercased()
            if lowered.contains("user canceled") || lowered.contains("user cancelled") || lowered.contains("(-128)") {
                throw TunPermissionServiceError.authorizationCancelled
            }
            throw TunPermissionServiceError.authorizationFailed(message)
        }
    }

    // MARK: - Hashing

    private func sha256Hex(ofFileAt path: String) throws -> String {
        guard let handle = FileHandle(forReadingAtPath: path) else {
            throw TunPermissionServiceError.hashingFailed("cannot open \(path)")
        }
        defer { try? handle.close() }

        var hasher = SHA256()
        let chunkSize = 1 << 20
        do {
            while let chunk = try handle.read(upToCount: chunkSize), !chunk.isEmpty {
                hasher.update(data: chunk)
            }
        } catch {
            throw TunPermissionServiceError.hashingFailed(error.localizedDescription)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Quoting

    private func q(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\"'\"'"))'"
    }

    private func appleScriptEscaped(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}

@MainActor
final class DefaultTunPermissionRepository: TunPermissionRepository {
    private let service: TunPermissionService

    init(service: TunPermissionService) {
        self.service = service
    }

    func hasRequiredPermissions(binaryPath: String) -> Bool {
        self.service.hasRequiredPermissions(binaryPath: binaryPath)
    }

    func validateCurrentPermissions(binaryPath: String) throws {
        try self.service.validateCurrentPermissions(binaryPath: binaryPath)
    }

    func grantPermissions(binaryPath: String) async throws {
        try await self.service.grantPermissions(binaryPath: binaryPath)
    }

    func legacySetuidPresent(binaryPath: String) -> Bool {
        self.service.legacySetuidPresent(binaryPath: binaryPath)
    }
}
