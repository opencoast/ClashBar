import CryptoKit
import Darwin
// `proc_pidpath` is declared in <libproc.h>, an explicit Darwin submodule that
// `import Darwin` does not always re-export.
import Darwin.libproc
import Foundation
import ProxyHelperShared

enum PrivilegedCoreError: LocalizedError {
    case invalidConfigFileName
    case invalidControllerHost
    case invalidControllerPort
    case untrustedClientUID(uid_t)
    case coreNotInstalled(path: String)
    case coreNotTrusted(path: String, reason: String)
    case directoryNotTrusted(path: String, reason: String)
    case configUnreadable(path: String, reason: String)
    case configTooLarge(limit: Int)
    case stagingFailed(reason: String)
    case launchFailed(reason: String)
    case alreadyRunning(pid: Int)
    case pathNotTrusted(component: String, reason: String)
    case configOwnerMismatch(expected: uid_t, actual: uid_t)

    var errorDescription: String? {
        switch self {
        case .invalidConfigFileName:
            "Config name must be a bare .yaml/.yml filename with no path separators."
        case .invalidControllerHost:
            "Controller host must be a loopback literal (127.0.0.1 or ::1)."
        case .invalidControllerPort:
            "Controller port must be in 1...65535."
        case let .untrustedClientUID(uid):
            "Refusing to resolve a config directory for uid \(uid)."
        case let .coreNotInstalled(path):
            "No privileged core installed at \(path)."
        case let .coreNotTrusted(path, reason):
            "Privileged core at \(path) is not trustworthy: \(reason)"
        case let .directoryNotTrusted(path, reason):
            "Privileged directory \(path) is not trustworthy: \(reason)"
        case let .configUnreadable(path, reason):
            "Unable to read config at \(path): \(reason)"
        case let .configTooLarge(limit):
            "Config exceeds \(limit) bytes."
        case let .stagingFailed(reason):
            "Failed to stage runtime config: \(reason)"
        case let .launchFailed(reason):
            "Failed to launch privileged core: \(reason)"
        case let .alreadyRunning(pid):
            "Privileged core is already running (pid \(pid))."
        case let .pathNotTrusted(component, reason):
            "Refusing to traverse '\(component)': \(reason)"
        case let .configOwnerMismatch(expected, actual):
            "Config is owned by uid \(actual), expected \(expected)."
        }
    }
}

/// Owns the one and only privileged `mihomo` process.
///
/// Every input that could widen privilege is either fixed at compile time (the
/// executable path, the data directory, the argument vector shape) or validated
/// here against a whitelist. The client chooses a config *filename* and a
/// loopback port; nothing else.
final class PrivilegedCoreRunner: @unchecked Sendable {
    static let shared = PrivilegedCoreRunner()

    /// gid 20 on macOS. The console user belongs to it, so `0640 root:staff`
    /// lets the app read the core log while other accounts cannot.
    private static let staffGID: gid_t = 20

    private let lock = NSLock()
    private var process: Process?
    private var logHandle: FileHandle?
    private var lastExitCode = ProxyHelperConstants.unknownExitCode
    private var intentionalStop = false
    /// Secret of the core currently running. Survives helper reconnects for as
    /// long as the helper process lives, and is handed back via `coreStatus`.
    private var currentSecret: String?

    private init() {}

    // MARK: - Public surface

    /// - Returns: the pid, plus the controller secret the helper generated and
    ///   injected into the staged config. The caller must use it as the bearer
    ///   token; without it the API is unreachable, which is the point.
    func start(
        configFileName: String,
        controllerHost: String,
        controllerPort: Int,
        clientUID: uid_t) throws -> (pid: Int, secret: String)
    {
        // A core left over from a previous session (helper recycled, app crashed)
        // must not wedge every future start. We can prove it is ours -- the
        // pidfile lives in a root-only directory and `isOurCore` compares the
        // executable path -- so stop it and start clean rather than throwing.
        if let running = self.currentRunningPID() {
            Self.appendHelperNote("[helper] reclaiming leftover privileged core pid=\(running)")
            try self.stop()
            if let stillRunning = self.currentRunningPID() {
                throw PrivilegedCoreError.alreadyRunning(pid: stillRunning)
            }
        }

        let uid = try CoreLaunchValidation.validatedClientUID(UInt32(clientUID))
        let name = try CoreLaunchValidation.validatedConfigFileName(configFileName)
        let host = try CoreLaunchValidation.validatedControllerHost(controllerHost)
        let port = try CoreLaunchValidation.validatedControllerPort(controllerPort)

        try Self.ensurePrivilegedLayout()
        try Self.validatePrivilegedBinary()

        // Read through an openat chain rather than a path: every component of
        // the user's home is user-controlled, so a leaf-only O_NOFOLLOW would let
        // a symlinked `config/` directory point the root helper at any file.
        let configData = try Self.readUserConfig(clientUID: uid_t(uid), fileName: name)

        // The user's config is not a trusted input to a root process. Strip the
        // control-plane and inbound-exposure keys, then inject a secret so the
        // root core's API is not open to every local process.
        let secret = Self.generateSecret()
        let sanitized = ConfigSanitizer.sanitize(
            yaml: String(decoding: configData, as: UTF8.self),
            injectedSecret: secret)
        if !sanitized.removedKeys.isEmpty {
            Self.appendHelperNote(
                "[helper] stripped unsafe top-level keys from staged config: " +
                    sanitized.removedKeys.joined(separator: ", "))
        }
        try Self.stageRuntimeConfig(Data(sanitized.yaml.utf8))

        let runDirectoryURL = URL(fileURLWithPath: ProxyHelperConstants.privilegedRunDirectoryPath, isDirectory: true)
        let handle = try Self.openCoreLogHandle()

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: ProxyHelperConstants.privilegedCoreBinaryPath)
        proc.currentDirectoryURL = runDirectoryURL
        proc.arguments = [
            "-d", ProxyHelperConstants.privilegedRunDirectoryPath,
            "-f", ProxyHelperConstants.privilegedRuntimeConfigPath,
            "-ext-ctl", "\(host):\(port)",
        ]
        // Do not inherit launchd's environment wholesale.
        proc.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        // Straight to a file: the helper never buffers core output, so a core
        // spinning on a dead TUN fd cannot grow the helper's memory.
        proc.standardOutput = handle
        proc.standardError = handle
        proc.standardInput = FileHandle.nullDevice

        proc.terminationHandler = { [weak self] terminated in
            self?.handleTermination(terminated)
        }

        do {
            try proc.run()
        } catch {
            try? handle.close()
            throw PrivilegedCoreError.launchFailed(reason: error.localizedDescription)
        }

        let pid = Int(proc.processIdentifier)
        self.lock.withLock {
            self.process = proc
            self.logHandle = handle
            self.intentionalStop = false
            self.lastExitCode = ProxyHelperConstants.unknownExitCode
            self.currentSecret = secret
        }
        Self.writePIDFile(pid)
        // Never log the secret.
        Self.appendHelperNote("[helper] started privileged core pid=\(pid) controller=\(host):\(port) config=\(name)")
        return (pid: pid, secret: secret)
    }

    private static func generateSecret() -> String {
        // SystemRandomNumberGenerator is the platform CSPRNG.
        (0..<32).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
    }

    func stop() throws {
        let owned: Process? = self.lock.withLock {
            self.intentionalStop = true
            return self.process
        }

        if let owned {
            if owned.isRunning {
                owned.terminate()
                if !Self.waitForExit(of: pid_t(owned.processIdentifier), timeout: 3.0) {
                    _ = Darwin.kill(owned.processIdentifier, SIGKILL)
                    _ = Self.waitForExit(of: pid_t(owned.processIdentifier), timeout: 1.0)
                }
            }
            self.finishStop()
            return
        }

        // The helper may have been restarted while a core it spawned kept
        // running; launchd reparented it but we no longer hold a Process.
        if let orphan = Self.readPIDFile(), Self.isAlive(orphan), Self.isOurCore(pid: pid_t(orphan)) {
            _ = Darwin.kill(pid_t(orphan), SIGTERM)
            if !Self.waitForExit(of: pid_t(orphan), timeout: 3.0) {
                _ = Darwin.kill(pid_t(orphan), SIGKILL)
                _ = Self.waitForExit(of: pid_t(orphan), timeout: 1.0)
            }
            Self.appendHelperNote("[helper] stopped orphaned privileged core pid=\(orphan)")
        }
        self.finishStop()
    }

    func status() -> (running: Bool, pid: Int, lastExitCode: Int, secret: String?) {
        let snapshot: (Process?, Int, String?) = self.lock
            .withLock { (self.process, self.lastExitCode, self.currentSecret) }

        if let proc = snapshot.0, proc.isRunning {
            return (true, Int(proc.processIdentifier), snapshot.1, snapshot.2)
        }
        if let orphan = Self.readPIDFile(), Self.isAlive(orphan), Self.isOurCore(pid: pid_t(orphan)) {
            // Reparented to launchd but still ours; the secret is only known if
            // this helper process started it.
            return (true, orphan, snapshot.1, snapshot.2)
        }
        return (false, 0, snapshot.1, nil)
    }

    func installedCoreSHA256() -> String? {
        guard (try? Self.validatePrivilegedBinary()) != nil else { return nil }
        guard let data = FileManager.default.contents(atPath: ProxyHelperConstants.privilegedCoreBinaryPath) else {
            return nil
        }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Termination bookkeeping

    private func handleTermination(_ terminated: Process) {
        let shouldReport: Bool = self.lock.withLock {
            guard let current = self.process, current === terminated else { return false }
            self.lastExitCode = Int(terminated.terminationStatus)
            self.process = nil
            try? self.logHandle?.close()
            self.logHandle = nil
            let wasIntentional = self.intentionalStop
            self.intentionalStop = false
            self.currentSecret = nil
            return !wasIntentional
        }
        Self.removePIDFile()
        if shouldReport {
            Self.appendHelperNote("[helper] privileged core exited unexpectedly code=\(terminated.terminationStatus)")
        }
    }

    private func finishStop() {
        self.lock.withLock {
            self.process = nil
            try? self.logHandle?.close()
            self.logHandle = nil
            self.intentionalStop = false
            self.currentSecret = nil
        }
        Self.removePIDFile()
    }

    private func currentRunningPID() -> Int? {
        let status = self.status()
        return status.running ? status.pid : nil
    }

    // MARK: - Safe path traversal
    //
    // `getpwuid` gives us the home directory from the passwd database (not from
    // the client), but everything below it belongs to the user. We therefore
    // descend one component at a time with O_NOFOLLOW|O_DIRECTORY, so a symlink
    // anywhere in the chain fails with ELOOP instead of redirecting a root read.

    private static let userConfigPathComponents = ["Library", "Application Support", "clashbar", "config"]
    private static let userCorePathComponents = ["Library", "Application Support", "clashbar", "core"]

    /// Opens a file under the caller's home directory, verifying every component
    /// on the way down. Callers own the returned descriptor.
    ///
    /// Used for both the config and the core binary: each is read by root out of
    /// a user-controlled tree, so neither may be reached by a plain path.
    static func openUserFile(
        clientUID: uid_t,
        components: [String],
        fileName: String) throws -> Int32
    {
        guard let entry = getpwuid(clientUID) else {
            throw PrivilegedCoreError.untrustedClientUID(clientUID)
        }
        let home = String(cString: entry.pointee.pw_dir)
        guard !home.isEmpty, home != "/" else {
            throw PrivilegedCoreError.untrustedClientUID(clientUID)
        }

        // The home root comes from the passwd DB, so following it is acceptable;
        // its ownership is still checked.
        var dirFD = open(home, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard dirFD >= 0 else {
            throw PrivilegedCoreError.pathNotTrusted(component: home, reason: "open failed (errno \(errno))")
        }
        try Self.verifyDirectoryFD(dirFD, component: home, expectedUID: clientUID)

        for component in components {
            let next = openat(dirFD, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else {
                // ELOOP here means the component is a symlink, which is exactly
                // the attack we are refusing.
                let captured = errno
                close(dirFD)
                throw PrivilegedCoreError.pathNotTrusted(
                    component: component,
                    reason: captured == ELOOP ? "is a symbolic link" : "openat failed (errno \(captured))")
            }
            close(dirFD)
            dirFD = next
            do {
                try Self.verifyDirectoryFD(dirFD, component: component, expectedUID: clientUID)
            } catch {
                close(dirFD)
                throw error
            }
        }

        let fileFD = openat(dirFD, fileName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        let captured = errno
        close(dirFD)
        guard fileFD >= 0 else {
            throw PrivilegedCoreError.configUnreadable(
                path: fileName,
                reason: captured == ELOOP ? "is a symbolic link" : "openat failed (errno \(captured))")
        }
        return fileFD
    }

    /// Opens the user's managed core for the installer.
    static func openUserManagedCore(clientUID: uid_t) throws -> Int32 {
        try self.openUserFile(
            clientUID: clientUID,
            components: Self.userCorePathComponents,
            fileName: "mihomo")
    }

    private static func readUserConfig(clientUID: uid_t, fileName: String) throws -> Data {
        let fileFD = try self.openUserFile(
            clientUID: clientUID,
            components: Self.userConfigPathComponents,
            fileName: fileName)
        defer { close(fileFD) }

        var st = stat()
        guard fstat(fileFD, &st) == 0 else {
            throw PrivilegedCoreError.configUnreadable(path: fileName, reason: "fstat failed (errno \(errno))")
        }
        guard (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw PrivilegedCoreError.configUnreadable(path: fileName, reason: "not a regular file")
        }
        // A hardlink to someone else's file would survive the symlink checks, so
        // require the config to actually belong to the calling user.
        guard st.st_uid == clientUID else {
            throw PrivilegedCoreError.configOwnerMismatch(expected: clientUID, actual: st.st_uid)
        }
        guard st.st_size > 0 else {
            throw PrivilegedCoreError.configUnreadable(path: fileName, reason: "empty file")
        }
        guard st.st_size <= off_t(ProxyHelperConstants.maximumConfigBytes) else {
            throw PrivilegedCoreError.configTooLarge(limit: ProxyHelperConstants.maximumConfigBytes)
        }

        let handle = FileHandle(fileDescriptor: fileFD, closeOnDealloc: false)
        guard let data = try handle.readToEnd(), !data.isEmpty else {
            throw PrivilegedCoreError.configUnreadable(path: fileName, reason: "read returned no bytes")
        }
        return data
    }

    private static func verifyDirectoryFD(_ fd: Int32, component: String, expectedUID: uid_t) throws {
        var st = stat()
        guard fstat(fd, &st) == 0 else {
            throw PrivilegedCoreError.pathNotTrusted(component: component, reason: "fstat failed (errno \(errno))")
        }
        guard (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR) else {
            throw PrivilegedCoreError.pathNotTrusted(component: component, reason: "not a directory")
        }
        guard st.st_uid == expectedUID || st.st_uid == 0 else {
            throw PrivilegedCoreError.pathNotTrusted(
                component: component,
                reason: "owned by uid \(st.st_uid), expected \(expectedUID) or root")
        }
        guard (st.st_mode & mode_t(S_IWOTH)) == 0 else {
            throw PrivilegedCoreError.pathNotTrusted(component: component, reason: "world writable")
        }
    }

    // MARK: - Trust checks

    private static func lstatPath(_ path: String) -> stat? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        return st
    }

    private static func validatePrivilegedBinary() throws {
        try self.validateDirectory(ProxyHelperConstants.privilegedRootPath)
        try self.validateDirectory(ProxyHelperConstants.privilegedCoreDirectoryPath)

        let path = ProxyHelperConstants.privilegedCoreBinaryPath
        guard let st = lstatPath(path) else {
            throw PrivilegedCoreError.coreNotInstalled(path: path)
        }
        guard (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw PrivilegedCoreError.coreNotTrusted(path: path, reason: "not a regular file (symlink?)")
        }
        guard st.st_uid == 0 else {
            throw PrivilegedCoreError.coreNotTrusted(path: path, reason: "owner uid is \(st.st_uid), expected 0")
        }
        guard (st.st_mode & mode_t(S_IWGRP | S_IWOTH)) == 0 else {
            throw PrivilegedCoreError.coreNotTrusted(path: path, reason: "writable by group or others")
        }
        guard (st.st_mode & mode_t(S_IXUSR)) != 0 else {
            throw PrivilegedCoreError.coreNotTrusted(path: path, reason: "not executable")
        }
        // We spawn as root ourselves, so setuid must not be present. If it is,
        // something other than this helper put it there.
        guard (st.st_mode & mode_t(S_ISUID)) == 0 else {
            throw PrivilegedCoreError.coreNotTrusted(path: path, reason: "unexpected setuid bit")
        }

        // The digest sidecar records what the user actually authorised. Checking
        // it here is what turns the hash from decoration into a gate: the file is
        // root-owned in a root-owned directory, so the app cannot forge it, and a
        // core swapped in by any other means fails to start.
        guard let recorded = PrivilegedCoreInstaller.recordedDigest() else {
            throw PrivilegedCoreError.coreNotTrusted(
                path: path,
                reason: "no authorised digest recorded; reinstall the privileged core")
        }
        guard let data = FileManager.default.contents(atPath: path) else {
            throw PrivilegedCoreError.coreNotTrusted(path: path, reason: "cannot read for digest verification")
        }
        let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard actual == recorded else {
            throw PrivilegedCoreError.coreNotTrusted(
                path: path,
                reason: "digest does not match the authorised core; reinstall it")
        }
    }

    private static func validateDirectory(_ path: String) throws {
        guard let st = lstatPath(path) else {
            throw PrivilegedCoreError.directoryNotTrusted(path: path, reason: "missing")
        }
        guard (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR) else {
            throw PrivilegedCoreError.directoryNotTrusted(path: path, reason: "not a directory (symlink?)")
        }
        guard st.st_uid == 0 else {
            throw PrivilegedCoreError.directoryNotTrusted(path: path, reason: "owner uid is \(st.st_uid), expected 0")
        }
        guard (st.st_mode & mode_t(S_IWGRP | S_IWOTH)) == 0 else {
            throw PrivilegedCoreError.directoryNotTrusted(path: path, reason: "writable by group or others")
        }
    }

    private static func ensurePrivilegedLayout() throws {
        // The installer (one admin prompt from the app) creates these. We only
        // create the two we are allowed to own outright, and never with mkdir -p
        // semantics that would follow a symlinked parent.
        try self.validateDirectory(ProxyHelperConstants.privilegedRootPath)
        for (path, mode) in [
            (ProxyHelperConstants.privilegedRunDirectoryPath, mode_t(0o700)),
            // 0750 root:staff -- the console user is in `staff`, so the app can
            // still tail the log, but other local accounts cannot read the DNS
            // queries and connection destinations a root core writes there.
            (ProxyHelperConstants.privilegedLogDirectoryPath, mode_t(0o750)),
        ] {
            if lstatPath(path) == nil {
                guard mkdir(path, mode) == 0 else {
                    throw PrivilegedCoreError.directoryNotTrusted(
                        path: path,
                        reason: "mkdir failed (errno \(errno))")
                }
                let gid: gid_t = mode == mode_t(0o750) ? Self.staffGID : 0
                _ = chown(path, 0, gid)
                _ = chmod(path, mode)
            }
            try self.validateDirectory(path)
        }
    }

    // MARK: - Config staging

    private static func stageRuntimeConfig(_ data: Data) throws {
        let path = ProxyHelperConstants.privilegedRuntimeConfigPath
        // Parent is root-owned 0700 (validated above), so O_NOFOLLOW on the final
        // component is sufficient here.
        let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            throw PrivilegedCoreError.stagingFailed(reason: "open failed (errno \(errno))")
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            throw PrivilegedCoreError.stagingFailed(reason: error.localizedDescription)
        }
        _ = chown(path, 0, 0)
        _ = chmod(path, 0o600)
    }

    // MARK: - Logging

    private static func openCoreLogHandle() throws -> FileHandle {
        let path = ProxyHelperConstants.privilegedCoreLogPath
        let fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0o640)
        guard fd >= 0 else {
            throw PrivilegedCoreError.stagingFailed(reason: "open core log failed (errno \(errno))")
        }
        var st = stat()
        if fstat(fd, &st) == 0, st.st_size > off_t(ProxyHelperConstants.maximumCoreLogBytes) {
            _ = ftruncate(fd, 0)
        }
        _ = fchown(fd, 0, Self.staffGID)
        _ = fchmod(fd, 0o640)
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    private static func appendHelperNote(_ line: String) {
        let path = ProxyHelperConstants.privilegedCoreLogPath
        let fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0o640)
        guard fd >= 0 else { return }
        defer { close(fd) }
        _ = fchown(fd, 0, Self.staffGID)
        _ = fchmod(fd, 0o640)
        let stamp = ISO8601DateFormatter().string(from: Date())
        if let data = "\(stamp) \(line)\n".data(using: .utf8) {
            _ = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        }
    }

    // MARK: - PID file

    private static func writePIDFile(_ pid: Int) {
        let path = ProxyHelperConstants.privilegedPidFilePath
        let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        if let data = "\(pid)\n".data(using: .utf8) {
            _ = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        }
    }

    private static func readPIDFile() -> Int? {
        guard let raw = try? String(contentsOfFile: ProxyHelperConstants.privilegedPidFilePath, encoding: .utf8),
              let pid = Int(raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              pid > 1
        else { return nil }
        return pid
    }

    private static func removePIDFile() {
        unlink(ProxyHelperConstants.privilegedPidFilePath)
    }

    private static func isAlive(_ pid: Int) -> Bool {
        Darwin.kill(pid_t(pid), 0) == 0
    }

    /// Guards against a recycled PID pointing at some unrelated process: the
    /// recorded pid must still be *our* executable before we signal it.
    private static func isOurCore(pid: pid_t) -> Bool {
        var buffer = [UInt8](repeating: 0, count: Int(PATH_MAX))
        let written = buffer.withUnsafeMutableBytes { raw in
            proc_pidpath(pid, raw.baseAddress, UInt32(raw.count))
        }
        guard written > 0 else { return false }
        // `proc_pidpath` returns the byte length of the path; decode exactly that
        // many bytes rather than relying on the deprecated NUL-scanning
        // `String(cString:)`.
        let path = String(decoding: buffer.prefix(Int(written)), as: UTF8.self)
        return path == ProxyHelperConstants.privilegedCoreBinaryPath
    }

    private static func waitForExit(of pid: pid_t, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if Darwin.kill(pid, 0) != 0 { return true }
            usleep(50000)
        }
        return Darwin.kill(pid, 0) != 0
    }
}
