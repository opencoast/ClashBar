import CryptoKit
import Darwin
import Foundation
import ProxyHelperShared
import Security

enum PrivilegedInstallError: LocalizedError {
    case authorizationMalformed
    case authorizationDenied(OSStatus)
    case sourceUnreadable(reason: String)
    case sourceNotExecutable
    case sourceTooSmall
    case targetPathUnsafe(component: String, reason: String)
    case writeFailed(reason: String)

    var errorDescription: String? {
        switch self {
        case .authorizationMalformed:
            "Authorization blob is not an AuthorizationExternalForm."
        case let .authorizationDenied(status):
            "Administrator authorization was not granted (OSStatus \(status))."
        case let .sourceUnreadable(reason):
            "Cannot read the managed mihomo core: \(reason)"
        case .sourceNotExecutable:
            "The managed mihomo core is not executable."
        case .sourceTooSmall:
            "The managed mihomo core is implausibly small; refusing to install it."
        case let .targetPathUnsafe(component, reason):
            "Refusing to install into '\(component)': \(reason)"
        case let .writeFailed(reason):
            "Failed to write the privileged core: \(reason)"
        }
    }
}

/// Installs the root-owned core, in-process, as root.
///
/// The first attempt at this feature shelled out as root via
/// `osascript ... with administrator privileges`. That was a root local
/// privilege escalation: `/Library/Application Support` is `root:admin 0775` and
/// the console user is normally in `admin`, so an attacker could pre-create
/// `…/ClashBar/core` as a symlink — `chmod` follows symlinks and `install`
/// writes through them. An inline `sh -c` running as root cannot be made safe
/// against a local attacker who can retry in a loop.
///
/// So every path component here is opened relative to a verified directory
/// descriptor with `O_NOFOLLOW`, and the payload lands via
/// `O_CREAT|O_EXCL` + `renameat`. There is no window in which a name can be
/// swapped for a symlink.
enum PrivilegedCoreInstaller {
    /// mihomo is tens of MB; anything tiny is a mistake or a decoy.
    private static let minimumPlausibleCoreBytes: off_t = 1 << 20

    // MARK: - Authorization

    /// Registers the right so the prompt carries our wording and never caches the
    /// credential. Best-effort: an unregistered right falls back to the system
    /// default rule, which also requires admin authentication, so failure here
    /// weakens the prompt's wording rather than the gate itself.
    static func registerRightIfNeeded() {
        var existing: CFDictionary?
        if AuthorizationRightGet(ProxyHelperConstants.installCoreRightName, &existing) == errAuthorizationSuccess {
            return
        }

        var authRef: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authRef) == errAuthorizationSuccess,
              let authRef
        else { return }
        defer { AuthorizationFree(authRef, []) }

        let definition: [String: Any] = [
            "class": "user",
            "group": "admin",
            // Do not let this credential satisfy any other right.
            "shared": false,
            // No caching: installing different bytes must always re-prompt.
            "timeout": 0,
            "comment": "ClashBar: install the root-owned mihomo core used for TUN mode.",
        ]
        _ = AuthorizationRightSet(
            authRef,
            ProxyHelperConstants.installCoreRightName,
            definition as CFDictionary,
            "ClashBar needs to install the privileged mihomo core for TUN mode." as CFString,
            nil,
            nil)
    }

    /// Independently verifies that the caller really holds the right. Note the
    /// absence of `.interactionAllowed`: the helper has no UI, and the credential
    /// must already be present in the passed-in reference.
    static func verifyAuthorization(_ blob: Data) throws {
        guard blob.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw PrivilegedInstallError.authorizationMalformed
        }

        var externalForm = AuthorizationExternalForm()
        blob.withUnsafeBytes { source in
            withUnsafeMutableBytes(of: &externalForm) { destination in
                destination.copyMemory(from: source)
            }
        }

        var authRef: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&externalForm, &authRef) == errAuthorizationSuccess,
              let authRef
        else {
            throw PrivilegedInstallError.authorizationMalformed
        }
        defer { AuthorizationFree(authRef, []) }

        var status: OSStatus = errAuthorizationInternal
        ProxyHelperConstants.installCoreRightName.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                status = AuthorizationCopyRights(authRef, &rights, nil, [.extendRights], nil)
            }
        }
        guard status == errAuthorizationSuccess else {
            throw PrivilegedInstallError.authorizationDenied(status)
        }
    }

    // MARK: - Install

    /// - Returns: the SHA-256 of the installed bytes.
    static func install(clientUID: uid_t, sourceFD: Int32) throws -> String {
        var st = stat()
        guard fstat(sourceFD, &st) == 0 else {
            throw PrivilegedInstallError.sourceUnreadable(reason: "fstat failed (errno \(errno))")
        }
        guard (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw PrivilegedInstallError.sourceUnreadable(reason: "not a regular file")
        }
        guard st.st_uid == clientUID else {
            throw PrivilegedInstallError.sourceUnreadable(
                reason: "owned by uid \(st.st_uid), expected \(clientUID)")
        }
        guard (st.st_mode & mode_t(S_IXUSR)) != 0 else {
            throw PrivilegedInstallError.sourceNotExecutable
        }
        guard st.st_size >= self.minimumPlausibleCoreBytes else {
            throw PrivilegedInstallError.sourceTooSmall
        }

        let handle = FileHandle(fileDescriptor: sourceFD, closeOnDealloc: false)
        guard let payload = try handle.readToEnd(), !payload.isEmpty else {
            throw PrivilegedInstallError.sourceUnreadable(reason: "read returned no bytes")
        }
        let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()

        let coreDirFD = try self.openVerifiedTargetDirectory()
        defer { close(coreDirFD) }

        try self.writeAtomically(
            payload,
            into: coreDirFD,
            finalName: "mihomo",
            temporaryName: ".mihomo.incoming",
            mode: 0o755)
        try self.writeAtomically(
            Data("\(digest)\n".utf8),
            into: coreDirFD,
            finalName: "mihomo.sha256",
            temporaryName: ".mihomo.sha256.incoming",
            mode: 0o644)

        return digest
    }

    /// Walks `/Library/Application Support/ClashBar/core`, creating and verifying
    /// each component relative to the previous descriptor.
    private static func openVerifiedTargetDirectory() throws -> Int32 {
        // `/Library/Application Support` itself is `root:admin 0775` on stock
        // macOS. We cannot demand that it be non-group-writable, but we never
        // write into it directly either: we only descend one further component,
        // with O_NOFOLLOW, and require *that* one to be root-owned and not
        // group/world writable.
        var dirFD = open("/Library/Application Support", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard dirFD >= 0 else {
            throw PrivilegedInstallError.targetPathUnsafe(
                component: "/Library/Application Support",
                reason: "open failed (errno \(errno))")
        }

        for component in ["ClashBar", "core"] {
            do {
                let next = try self.openOrCreateVerifiedChild(of: dirFD, named: component, mode: 0o755)
                close(dirFD)
                dirFD = next
            } catch {
                close(dirFD)
                throw error
            }
        }
        return dirFD
    }

    private static func openOrCreateVerifiedChild(
        of parentFD: Int32,
        named component: String,
        mode: mode_t) throws -> Int32
    {
        // mkdirat is racy only in the benign direction: EEXIST simply means we
        // verify what is already there, and the verification is what matters.
        if mkdirat(parentFD, component, mode) != 0, errno != EEXIST {
            throw PrivilegedInstallError.targetPathUnsafe(
                component: component,
                reason: "mkdirat failed (errno \(errno))")
        }

        let fd = openat(parentFD, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            throw PrivilegedInstallError.targetPathUnsafe(
                component: component,
                reason: errno == ELOOP
                    ? "is a symbolic link — refusing to install through it"
                    : "openat failed (errno \(errno))")
        }

        var st = stat()
        guard fstat(fd, &st) == 0 else {
            close(fd)
            throw PrivilegedInstallError.targetPathUnsafe(component: component, reason: "fstat failed")
        }
        // A pre-existing directory could have been created by the attacker with
        // permissive modes; normalise before trusting it.
        if st.st_uid != 0 || st.st_gid != 0 {
            _ = fchown(fd, 0, 0)
        }
        if (st.st_mode & mode_t(S_IWGRP | S_IWOTH)) != 0 {
            _ = fchmod(fd, mode)
        }
        guard fstat(fd, &st) == 0 else {
            close(fd)
            throw PrivilegedInstallError.targetPathUnsafe(component: component, reason: "fstat failed")
        }
        guard st.st_uid == 0, (st.st_mode & mode_t(S_IWGRP | S_IWOTH)) == 0 else {
            close(fd)
            throw PrivilegedInstallError.targetPathUnsafe(
                component: component,
                reason: "still not root-owned and group/world-unwritable after normalising")
        }
        return fd
    }

    private static func writeAtomically(
        _ payload: Data,
        into dirFD: Int32,
        finalName: String,
        temporaryName: String,
        mode: mode_t) throws
    {
        // Clear any leftover temp name first; O_EXCL below would otherwise fail,
        // and a leftover could itself be a symlink planted earlier.
        _ = unlinkat(dirFD, temporaryName, 0)

        let fd = openat(dirFD, temporaryName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard fd >= 0 else {
            throw PrivilegedInstallError.writeFailed(reason: "openat(O_EXCL) failed (errno \(errno))")
        }

        do {
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
            try handle.write(contentsOf: payload)
            try handle.synchronize()
            guard fchown(fd, 0, 0) == 0 else {
                throw PrivilegedInstallError.writeFailed(reason: "fchown failed (errno \(errno))")
            }
            guard fchmod(fd, mode) == 0 else {
                throw PrivilegedInstallError.writeFailed(reason: "fchmod failed (errno \(errno))")
            }
            close(fd)
        } catch {
            close(fd)
            _ = unlinkat(dirFD, temporaryName, 0)
            if let error = error as? PrivilegedInstallError { throw error }
            throw PrivilegedInstallError.writeFailed(reason: error.localizedDescription)
        }

        // renameat replaces the target atomically, so nothing ever observes a
        // half-written core, and a symlink at `finalName` is replaced rather than
        // followed.
        guard renameat(dirFD, temporaryName, dirFD, finalName) == 0 else {
            _ = unlinkat(dirFD, temporaryName, 0)
            throw PrivilegedInstallError.writeFailed(reason: "renameat failed (errno \(errno))")
        }
    }

    /// Digest the user authorised, as recorded next to the binary.
    static func recordedDigest() -> String? {
        guard let raw = try? String(contentsOfFile: ProxyHelperConstants.privilegedCoreDigestPath, encoding: .utf8)
        else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard trimmed.count == 64, trimmed.allSatisfy(\.isHexDigit) else { return nil }
        return trimmed
    }
}
