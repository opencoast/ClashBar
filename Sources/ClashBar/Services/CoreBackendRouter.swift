import Foundation
import ProxyHelperShared

/// The log/termination hooks `AppViewModel` wires up. Previously the view model
/// downcast to `MihomoProcessManager`; with two possible backends it needs an
/// abstraction instead.
protocol MihomoLogObserving: AnyObject {
    var onLog: ((String) -> Void)? { get set }
    var onTermination: ((Int32) -> Void)? { get set }
}

extension MihomoProcessManager: MihomoLogObserving {}

/// Drives the core through the privileged helper instead of spawning it here.
///
/// The app process stays unprivileged: it sends a config *filename* and a
/// loopback port, and reads the root-owned log file. It cannot influence the
/// executable, the data directory, or any other argument.
final class PrivilegedCoreController: MihomoControlling, MihomoLogObserving, @unchecked Sendable {
    private let service: PrivilegedCoreService
    private let logTail: PrivilegedCoreLogTail
    private let validator: any MihomoControlling
    private let lock = NSLock()

    private var storedStatus: CoreLifecycleStatus = .stopped
    private var intentionalStop = false
    private var pollTask: Task<Void, Never>?

    var onLog: ((String) -> Void)?
    var onTermination: ((Int32) -> Void)?

    /// Set after a successful privileged start. The helper strips the user's own
    /// `secret` and injects its own, so the app must pick this up or every API
    /// call to the root core will fail authentication.
    fileprivate(set) var injectedControllerSecret: String?

    /// - Parameter validator: used for `mihomo -t`, which needs no privilege and
    ///   is best run as the user against the user's own copy of the config.
    init(
        service: PrivilegedCoreService = PrivilegedCoreService(),
        logTail: PrivilegedCoreLogTail = PrivilegedCoreLogTail(),
        validator: any MihomoControlling)
    {
        self.service = service
        self.logTail = logTail
        self.validator = validator
        self.logTail.onLine = { [weak self] line in
            self?.onLog?(line)
        }
    }

    var status: CoreLifecycleStatus {
        self.lock.withLock { self.storedStatus }
    }

    var isRunning: Bool {
        if case .running = self.status { return true }
        return false
    }

    var detectedBinaryPath: String? {
        self.validator.detectedBinaryPath
    }

    func validateConfigAsync(configPath: String) async throws {
        try await self.validator.validateConfigAsync(configPath: configPath)
    }

    @discardableResult
    func startAsync(configPath: String, controller: String) async throws -> CoreLifecycleStatus {
        let fileName = URL(fileURLWithPath: configPath).lastPathComponent
        let endpoint = try PrivilegedControllerEndpoint.parse(controller)

        self.lock.withLock {
            self.intentionalStop = false
            self.storedStatus = .starting
        }
        self.logTail.start(fromEnd: true)

        do {
            let started = try await self.service.startCore(configFileName: fileName, endpoint: endpoint)
            let pid = started.pid
            self.lock.withLock {
                self.storedStatus = .running(pid: Int32(pid))
                self.injectedControllerSecret = started.secret
            }
            self.onLog?(
                "[mihomo started] privileged pid=\(pid) controller=\(endpoint.displayValue) " +
                    "binary=\(ProxyHelperConstants.privilegedCoreBinaryPath) " +
                    "workdir=\(ProxyHelperConstants.privilegedRunDirectoryPath)")
            self.startPolling()
            return self.status
        } catch {
            let reason = error.localizedDescription
            self.lock.withLock { self.storedStatus = .failed(reason: reason) }
            self.logTail.stop()
            self.onLog?("[mihomo error] \(reason)")
            throw error
        }
    }

    func stop() {
        self.lock.withLock { self.intentionalStop = true }
        self.cancelPolling()
        self.service.stopCoreBlocking()
        self.finishStop()
    }

    func stopAsync() async {
        self.lock.withLock { self.intentionalStop = true }
        self.cancelPolling()
        try? await self.service.stopCore()
        self.finishStop()
    }

    @discardableResult
    func restartAsync(configPath: String, controller: String) async throws -> CoreLifecycleStatus {
        await self.stopAsync()
        return try await self.startAsync(configPath: configPath, controller: controller)
    }

    /// Reconciles with the helper at launch: a core spawned by a previous app
    /// session (or before the app was relaunched) is still running, and the UI
    /// should show that rather than offering to start a second one.
    func adoptRunningCoreIfAny() async {
        guard let snapshot = try? await self.service.coreStatus(), snapshot.running else { return }
        self.lock.withLock {
            self.intentionalStop = false
            self.storedStatus = .running(pid: Int32(snapshot.pid))
            // Without this the app cannot authenticate against a core it did not
            // start in this session: every request comes back 401.
            self.injectedControllerSecret = snapshot.secret
        }
        self.logTail.start(fromEnd: true)
        self.startPolling()
        self.onLog?("[mihomo adopted] privileged core already running pid=\(snapshot.pid)")
    }

    private func finishStop() {
        self.logTail.stop()
        self.lock.withLock {
            self.storedStatus = .stopped
            self.intentionalStop = false
        }
    }

    private func startPolling() {
        self.cancelPolling()
        let task = Task<Void, Never> { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard !Task.isCancelled, let self else { return }
                guard let snapshot = try? await self.service.coreStatus() else { continue }
                if snapshot.running { continue }

                let shouldReport: Bool = self.lock.withLock {
                    guard case .running = self.storedStatus else { return false }
                    let wasIntentional = self.intentionalStop
                    self.intentionalStop = false
                    self.storedStatus = .stopped
                    return !wasIntentional
                }
                if shouldReport {
                    self.logTail.stop()
                    let code = snapshot.lastExitCode == ProxyHelperConstants.unknownExitCode
                        ? -1
                        : snapshot.lastExitCode
                    self.onLog?("[mihomo terminated] privileged core exit=\(code)")
                    self.onTermination?(Int32(code))
                }
                return
            }
        }
        self.lock.withLock { self.pollTask = task }
    }

    private func cancelPolling() {
        let task: Task<Void, Never>? = self.lock.withLock {
            let existing = self.pollTask
            self.pollTask = nil
            return existing
        }
        task?.cancel()
    }
}

/// Chooses between the in-process child (`MihomoProcessManager`) and the
/// helper-spawned privileged core.
///
/// TUN is the only reason to need privilege, so system-proxy-only users keep the
/// old unprivileged behaviour and no root process ever runs on their machine.
final class CoreBackendRouter: MihomoControlling, MihomoLogObserving, @unchecked Sendable {
    enum Backend {
        case unprivileged
        case privileged
    }

    let unprivileged: MihomoProcessManager
    let privileged: PrivilegedCoreController

    private let lock = NSLock()
    private var desiredBackend: Backend = .unprivileged
    private var activeBackend: Backend?

    private var storedOnLog: ((String) -> Void)?
    private var storedOnTermination: ((Int32) -> Void)?

    var onLog: ((String) -> Void)? {
        get { self.lock.withLock { self.storedOnLog } }
        set { self.lock.withLock { self.storedOnLog = newValue } }
    }

    var onTermination: ((Int32) -> Void)? {
        get { self.lock.withLock { self.storedOnTermination } }
        set { self.lock.withLock { self.storedOnTermination = newValue } }
    }

    init(unprivileged: MihomoProcessManager, privileged: PrivilegedCoreController) {
        self.unprivileged = unprivileged
        self.privileged = privileged

        // Both backends funnel into whatever the view model installed on us.
        self.unprivileged.onLog = { [weak self] line in self?.onLog?(line) }
        self.unprivileged.onTermination = { [weak self] code in self?.onTermination?(code) }
        self.privileged.onLog = { [weak self] line in self?.onLog?(line) }
        self.privileged.onTermination = { [weak self] code in self?.onTermination?(code) }
    }

    /// Set by `AppViewModel` from the TUN toggle *before* starting or restarting.
    /// Changing it while the core runs has no effect until the next start.
    var requiresPrivilegedBackend: Bool {
        get { self.lock.withLock { self.desiredBackend == .privileged } }
        set { self.lock.withLock { self.desiredBackend = newValue ? .privileged : .unprivileged } }
    }

    private var current: any MihomoControlling {
        let backend = self.lock.withLock { self.activeBackend ?? self.desiredBackend }
        return backend == .privileged ? self.privileged : self.unprivileged
    }

    var status: CoreLifecycleStatus { self.current.status }
    var isRunning: Bool { self.current.isRunning }
    var detectedBinaryPath: String? { self.unprivileged.detectedBinaryPath }

    /// Non-nil only while a privileged core is running.
    var injectedControllerSecret: String? {
        let backend = self.lock.withLock { self.activeBackend }
        return backend == .privileged ? self.privileged.injectedControllerSecret : nil
    }

    func validateConfigAsync(configPath: String) async throws {
        try await self.unprivileged.validateConfigAsync(configPath: configPath)
    }

    @discardableResult
    func startAsync(configPath: String, controller: String) async throws -> CoreLifecycleStatus {
        let target = self.lock.withLock { self.desiredBackend }

        // Never leave the other backend holding a core: two mihomo processes
        // would fight over the same ports.
        if target == .privileged {
            self.unprivileged.stop()
        } else {
            await self.privileged.stopAsync()
        }

        self.lock.withLock { self.activeBackend = target }
        let backend: any MihomoControlling = target == .privileged ? self.privileged : self.unprivileged
        do {
            return try await backend.startAsync(configPath: configPath, controller: controller)
        } catch {
            self.lock.withLock { self.activeBackend = nil }
            throw error
        }
    }

    func stop() {
        self.current.stop()
        self.lock.withLock { self.activeBackend = nil }
    }

    func stopAsync() async {
        await self.current.stopAsync()
        self.lock.withLock { self.activeBackend = nil }
    }

    @discardableResult
    func restartAsync(configPath: String, controller: String) async throws -> CoreLifecycleStatus {
        await self.stopAsync()
        return try await self.startAsync(configPath: configPath, controller: controller)
    }

    /// Called once at launch so a privileged core left running by a previous
    /// session shows up in the UI.
    func reconcileWithHelperAtLaunch() async {
        await self.privileged.adoptRunningCoreIfAny()
        if self.privileged.isRunning {
            self.lock.withLock {
                self.activeBackend = .privileged
                self.desiredBackend = .privileged
            }
        }
    }
}
