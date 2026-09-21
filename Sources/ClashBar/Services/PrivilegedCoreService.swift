import Foundation
import ProxyHelperShared
import Security

enum PrivilegedCoreServiceError: LocalizedError {
    case connectionFailed(String)
    case operationFailed(String)
    case invalidController(String)
    case timedOut

    var errorDescription: String? {
        switch self {
        case let .connectionFailed(message):
            "Could not reach the ClashBar helper: \(message)"
        case let .operationFailed(message):
            message
        case let .invalidController(value):
            "Controller endpoint is not usable for a privileged core: \(value)"
        case .timedOut:
            "The ClashBar helper did not respond in time."
        }
    }
}

// `PrivilegedControllerEndpoint` now lives in ProxyHelperShared so the helper
// and the app validate the endpoint with the same code, and so it can be unit
// tested without a signed helper.

/// Thin XPC client for the helper's privileged core lifecycle methods.
final class PrivilegedCoreService: @unchecked Sendable {
    private let timeout: TimeInterval

    init(timeout: TimeInterval = 20) {
        self.timeout = timeout
    }

    struct Snapshot: Sendable {
        let running: Bool
        let pid: Int
        let lastExitCode: Int
        /// Token of the running core, so it can be recovered after an app
        /// restart instead of leaving us unable to authenticate against a live
        /// root core.
        let secret: String?
    }

    struct Started: Sendable {
        let pid: Int
        /// The controller token the helper injected. Without it every API call
        /// to the root core returns 401, so this must reach the API client.
        let secret: String?
    }

    func startCore(configFileName: String, endpoint: PrivilegedControllerEndpoint) async throws -> Started {
        try await self.invoke { helper, done in
            helper.startCore(
                configFileName: configFileName,
                controllerHost: endpoint.host,
                controllerPort: endpoint.port) { ok, pid, secret, message in
                    if ok {
                        done(.success(Started(pid: pid, secret: secret)))
                    } else {
                        done(.failure(PrivilegedCoreServiceError.operationFailed(
                            message ?? "startCore failed without a message.")))
                    }
                }
        }
    }

    func stopCore() async throws {
        try await self.invoke { helper, done in
            helper.stopCore { ok, message in
                if ok {
                    done(.success(()))
                } else {
                    done(.failure(PrivilegedCoreServiceError.operationFailed(
                        message ?? "stopCore failed without a message.")))
                }
            }
        }
    }

    /// Blocking variant for `applicationWillTerminate`-style paths.
    func stopCoreBlocking(timeout: TimeInterval = 4.0) {
        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let connection = self.makeConnection()
            guard let helper = connection.remoteObjectProxyWithErrorHandler({ _ in
                semaphore.signal()
            }) as? ProxyHelperProtocol else {
                connection.invalidate()
                semaphore.signal()
                return
            }
            helper.stopCore { _, _ in
                connection.invalidate()
                semaphore.signal()
            }
        }
        _ = semaphore.wait(timeout: .now() + timeout)
    }

    func coreStatus() async throws -> Snapshot {
        try await self.invoke { helper, done in
            helper.coreStatus { ok, running, pid, lastExitCode, secret, message in
                if ok {
                    done(.success(Snapshot(
                        running: running,
                        pid: pid,
                        lastExitCode: lastExitCode,
                        secret: secret)))
                } else {
                    done(.failure(PrivilegedCoreServiceError.operationFailed(
                        message ?? "coreStatus failed without a message.")))
                }
            }
        }
    }

    /// Prompts for administrator authorization, then has the helper install the
    /// user's managed core as the root-owned privileged core.
    ///
    /// - Returns: the SHA-256 of the installed bytes, so the caller can show the
    ///   user exactly what was authorised.
    func installPrivilegedCore() async throws -> String {
        // The dialog blocks its thread; keep it off the main actor.
        let blob = try await Task.detached(priority: .userInitiated) {
            try PrivilegedCoreInstallAuthorization.requestExternalForm()
        }.value

        return try await self.invoke { helper, done in
            helper.installPrivilegedCore(authorization: blob) { ok, digest, message in
                if ok, let digest {
                    done(.success(digest))
                } else {
                    done(.failure(PrivilegedCoreServiceError.operationFailed(
                        message ?? "installPrivilegedCore failed without a message.")))
                }
            }
        }
    }

    func privilegedCoreDigest() async throws -> String? {
        try await self.invoke { helper, done in
            helper.privilegedCoreInfo { ok, installed, digest, message in
                if ok {
                    done(.success(installed ? digest : nil))
                } else {
                    done(.failure(PrivilegedCoreServiceError.operationFailed(
                        message ?? "privilegedCoreInfo failed without a message.")))
                }
            }
        }
    }

    // MARK: - Plumbing

    private func invoke<Value: Sendable>(
        _ body: @escaping (ProxyHelperProtocol, @escaping (Result<Value, Error>) -> Void) -> Void)
        async throws -> Value
    {
        try await withCheckedThrowingContinuation { continuation in
            let connection = self.makeConnection()
            let box = ContinuationBox<Value>(continuation)

            let timeoutItem = DispatchWorkItem {
                connection.invalidate()
                box.resume(with: .failure(PrivilegedCoreServiceError.timedOut))
            }
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + self.timeout, execute: timeoutItem)

            guard let helper = connection.remoteObjectProxyWithErrorHandler({ error in
                timeoutItem.cancel()
                connection.invalidate()
                box.resume(
                    with: .failure(PrivilegedCoreServiceError.connectionFailed(error.localizedDescription)))
            }) as? ProxyHelperProtocol else {
                timeoutItem.cancel()
                connection.invalidate()
                box.resume(
                    with: .failure(PrivilegedCoreServiceError.connectionFailed("Unable to create XPC proxy.")))
                return
            }

            body(helper) { result in
                timeoutItem.cancel()
                connection.invalidate()
                box.resume(with: result)
            }
        }
    }

    private func makeConnection() -> NSXPCConnection {
        let connection = NSXPCConnection(
            machServiceName: ProxyHelperConstants.machServiceName,
            options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: ProxyHelperProtocol.self)
        // Pin the daemon from this side too, so the app will not hand a config
        // filename to something that merely grabbed the Mach name. Upstream never
        // did this, which is why it is gated: an ad-hoc signature has no
        // certificate chain, and requiring one on a development build makes every
        // call fail with "Couldn't communicate with a helper application" even
        // though the helper is running fine. Mirror the posture
        // `SystemProxyService.validateHelperSigningRequirements` already takes --
        // unsigned on both ends means no check -- rather than installing a
        // degraded requirement that cannot be satisfied.
        if let requirement = Self.helperCodeSigningRequirement() {
            connection.setCodeSigningRequirement(requirement)
        }
        connection.activate()
        return connection
    }

    /// The requirement to pin the daemon with, or nil when this build is not
    /// properly signed and therefore cannot satisfy one.
    ///
    /// Returning nil is a real reduction in defence, and it is why a Developer ID
    /// is load-bearing for this design: on an ad-hoc build anything that can
    /// claim the Mach name can answer. It is not a reason to ship an
    /// unsatisfiable requirement instead -- that just breaks the feature while
    /// providing no protection either.
    static func helperCodeSigningRequirement() -> String? {
        guard let team = self.selfTeamIdentifier(), !team.isEmpty else { return nil }
        return "\(ProxyHelperConstants.allowedHelperRequirement) " +
            "and certificate leaf[subject.OU] = \"\(team)\""
    }

    private static func selfTeamIdentifier() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else {
            return nil
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info) == errSecSuccess,
            let dict = info as? [String: Any]
        else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }
}

/// Tails the root-owned core log so the app can still surface startup failures
/// (bad config, port already bound, TUN init failure) that never reach the
/// `/logs` websocket because the core dies before the API is up.
///
/// The log file is `0644 root:wheel` in a `0755 root:wheel` directory, so the
/// unprivileged app can read it without any helper round trip.
final class PrivilegedCoreLogTail: @unchecked Sendable {
    private let path: String
    private let queue = DispatchQueue(label: "com.clashbar.privileged-core.logtail")
    private var timer: DispatchSourceTimer?
    private var offset: UInt64 = 0
    private var carry = Data()
    private let maxLinesPerTick = 200

    var onLine: ((String) -> Void)?

    init(path: String = ProxyHelperConstants.privilegedCoreLogPath) {
        self.path = path
    }

    /// Starts tailing. `fromEnd` skips whatever the previous run left behind.
    func start(fromEnd: Bool = true) {
        self.queue.async {
            self.timer?.cancel()
            self.carry = Data()
            self.offset = fromEnd ? (self.currentSize() ?? 0) : 0

            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + 0.2, repeating: 0.5)
            timer.setEventHandler { [weak self] in self?.drain() }
            self.timer = timer
            timer.resume()
        }
    }

    func stop() {
        self.queue.async {
            self.timer?.cancel()
            self.timer = nil
            self.carry = Data()
        }
    }

    private func currentSize() -> UInt64? {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: self.path),
              let size = attrs[.size] as? NSNumber
        else { return nil }
        return size.uint64Value
    }

    private func drain() {
        guard let size = self.currentSize() else { return }
        if size < self.offset {
            // Helper rotated (truncated) the log.
            self.offset = 0
            self.carry = Data()
        }
        guard size > self.offset else { return }
        guard let handle = FileHandle(forReadingAtPath: self.path) else { return }
        defer { try? handle.close() }

        do {
            try handle.seek(toOffset: self.offset)
            guard let data = try handle.readToEnd(), !data.isEmpty else { return }
            self.offset += UInt64(data.count)
            self.carry.append(data)

            var emitted = 0
            while let newline = self.carry.firstIndex(of: 0x0A) {
                let lineData = self.carry.subdata(in: self.carry.startIndex..<newline)
                self.carry.removeSubrange(self.carry.startIndex...newline)
                guard emitted < self.maxLinesPerTick else { continue }
                if let raw = String(data: lineData, encoding: .utf8) {
                    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmed.isEmpty {
                        emitted += 1
                        self.onLine?(trimmed)
                    }
                }
            }
            // Never let a single unterminated line grow without bound.
            if self.carry.count > 64 * 1024 {
                self.carry = Data()
            }
        } catch {
            return
        }
    }
}
