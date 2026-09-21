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

    private let lock = NSLock()
    private var process: Process?
    private var logHandle: FileHandle?
    private var lastExitCode = ProxyHelperConstants.unknownExitCode
    private var intentionalStop = false

    private init() {}

    // MARK: - Public surface

    func start(
        configFileName: String,
        controllerHost: String,
        controllerPort: Int,
        clientUID: uid_t) throws -> Int
    {
        if let running = self.currentRunningPID() {
            throw PrivilegedCoreError.alreadyRunning(pid: running)
        }

        let name = try Self.validatedConfigFileName(configFileName)
        let host = try Self.validatedControllerHost(controllerHost)
        let port = try Self.validatedControllerPort(controllerPort)
        let sourceConfigURL = try Self.resolveUserConfigURL(clientUID: clientUID, fileName: name)

        try Self.ensurePrivilegedLayout()
        try Self.validatePrivilegedBinary()
        let configData = try Self.readConfig(at: sourceConfigURL)
        try Self.stageRuntimeConfig(configData)

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
        }
        Self.writePIDFile(pid)
        Self.appendHelperNote("[helper] started privileged core pid=\(pid) controller=\(host):\(port) config=\(name)")
        return pid
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

    func status() -> (running: Bool, pid: Int, lastExitCode: Int) {
        let snapshot: (Process?, Int) = self.lock.withLock { (self.process, self.lastExitCode) }

        if let proc = snapshot.0, proc.isRunning {
            return (true, Int(proc.processIdentifier), snapshot.1)
        }
        if let orphan = Self.readPIDFile(), Self.isAlive(orphan), Self.isOurCore(pid: pid_t(orphan)) {
            return (true, orphan, snapshot.1)
        }
        return (false, 0, snapshot.1)
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
        }
        Self.removePIDFile()
    }

    private func currentRunningPID() -> Int? {
        let status = self.status()
        return status.running ? status.pid : nil
    }

    // MARK: - Input validation

    private static func validatedConfigFileName(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 128 else { throw PrivilegedCoreError.invalidConfigFileName }
        guard trimmed == (trimmed as NSString).lastPathComponent else {
            throw PrivilegedCoreError.invalidConfigFileName
        }
        guard !trimmed.hasPrefix("."), trimmed != "..", !trimmed.contains("/"), !trimmed.contains("\0") else {
            throw PrivilegedCoreError.invalidConfigFileName
        }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        guard trimmed.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw PrivilegedCoreError.invalidConfigFileName
        }
        let ext = (trimmed as NSString).pathExtension.lowercased()
        guard ext == "yaml" || ext == "yml" else { throw PrivilegedCoreError.invalidConfigFileName }
        return trimmed
    }

    private static func validatedControllerHost(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        switch trimmed {
        case "127.0.0.1":
            return "127.0.0.1"
        case "::1", "[::1]":
            return "[::1]"
        default:
            throw PrivilegedCoreError.invalidControllerHost
        }
    }

    private static func validatedControllerPort(_ raw: Int) throws -> Int {
        guard (1...65535).contains(raw) else { throw PrivilegedCoreError.invalidControllerPort }
        return raw
    }

    private static func resolveUserConfigURL(clientUID: uid_t, fileName: String) throws -> URL {
        guard clientUID != 0, clientUID >= 500 else {
            throw PrivilegedCoreError.untrustedClientUID(clientUID)
        }
        guard let entry = getpwuid(clientUID) else {
            throw PrivilegedCoreError.untrustedClientUID(clientUID)
        }
        let home = String(cString: entry.pointee.pw_dir)
        guard !home.isEmpty, home != "/" else {
            throw PrivilegedCoreError.untrustedClientUID(clientUID)
        }
        return URL(fileURLWithPath: home, isDirectory: true)
            .appendingPathComponent(ProxyHelperConstants.userConfigDirectoryRelativePath, isDirectory: true)
            .appendingPathComponent(fileName, isDirectory: false)
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
            (ProxyHelperConstants.privilegedLogDirectoryPath, mode_t(0o755)),
        ] {
            if lstatPath(path) == nil {
                guard mkdir(path, mode) == 0 else {
                    throw PrivilegedCoreError.directoryNotTrusted(
                        path: path,
                        reason: "mkdir failed (errno \(errno))")
                }
                _ = chown(path, 0, 0)
                _ = chmod(path, mode)
            }
            try self.validateDirectory(path)
        }
    }

    // MARK: - Config staging

    private static func readConfig(at url: URL) throws -> Data {
        let path = url.path
        let fd = open(path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else {
            throw PrivilegedCoreError.configUnreadable(path: path, reason: "open failed (errno \(errno))")
        }
        defer { close(fd) }

        var st = stat()
        guard fstat(fd, &st) == 0 else {
            throw PrivilegedCoreError.configUnreadable(path: path, reason: "fstat failed (errno \(errno))")
        }
        guard (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw PrivilegedCoreError.configUnreadable(path: path, reason: "not a regular file")
        }
        guard st.st_size > 0 else {
            throw PrivilegedCoreError.configUnreadable(path: path, reason: "empty file")
        }
        guard st.st_size <= off_t(ProxyHelperConstants.maximumConfigBytes) else {
            throw PrivilegedCoreError.configTooLarge(limit: ProxyHelperConstants.maximumConfigBytes)
        }

        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        guard let data = try handle.readToEnd(), !data.isEmpty else {
            throw PrivilegedCoreError.configUnreadable(path: path, reason: "read returned no bytes")
        }
        return data
    }

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
        let fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0o644)
        guard fd >= 0 else {
            throw PrivilegedCoreError.stagingFailed(reason: "open core log failed (errno \(errno))")
        }
        var st = stat()
        if fstat(fd, &st) == 0, st.st_size > off_t(ProxyHelperConstants.maximumCoreLogBytes) {
            _ = ftruncate(fd, 0)
        }
        _ = fchown(fd, 0, 0)
        _ = fchmod(fd, 0o644)
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    private static func appendHelperNote(_ line: String) {
        let path = ProxyHelperConstants.privilegedCoreLogPath
        let fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0o644)
        guard fd >= 0 else { return }
        defer { close(fd) }
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
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let written = proc_pidpath(pid, &buffer, UInt32(PATH_MAX))
        guard written > 0 else { return false }
        return String(cString: buffer) == ProxyHelperConstants.privilegedCoreBinaryPath
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
