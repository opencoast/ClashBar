import Foundation

enum TunModeError: LocalizedError {
    case runtimeStateMismatch(expected: Bool)

    var errorDescription: String? {
        switch self {
        case let .runtimeStateMismatch(expected):
            "TUN runtime state mismatch. expected=\(expected)"
        }
    }
}

@MainActor
extension AppViewModel {
    func toggleTunMode(_ enabled: Bool) async {
        guard !isTunSyncing else { return }
        guard enabled != isTunEnabled else { return }

        isTunSyncing = true
        defer { isTunSyncing = false }

        do {
            if enabled, !self.isRemoteTarget {
                try await self.ensureTunPermissions(requestIfMissing: true)
            }

            // Behaviour change from the setuid design: TUN is no longer a pure
            // runtime PATCH. Creating a utun device needs a root core, and the
            // root core is a different process than the unprivileged one, so
            // crossing that line requires a restart.
            if !self.isRemoteTarget, self.privilegedBackendRequired != enabled {
                self.syncPrivilegedBackendSelection(tunEnabled: enabled)
                if self.isRuntimeRunning {
                    appendLog(level: "info", message: tr("log.tun.backend_switch_restart"))
                    await self.restartCore(trigger: .restart, privilegedBackend: enabled)
                    guard self.isRuntimeRunning else {
                        isTunEnabled = false
                        persistEditableSettingsSnapshot()
                        appendLog(level: "error", message: tr("log.tun.backend_switch_failed"))
                        return
                    }
                }
            }

            guard self.isRemoteTarget || self.isRuntimeRunning else { return }
            try await self.patchTunConfig(enable: enabled)

            let config = try await fetchRuntimeConfigSnapshot()
            let actualState = config.tunEnabled ?? false
            isTunEnabled = actualState
            persistEditableSettingsSnapshot()

            if actualState == enabled {
                appendLog(
                    level: "info",
                    message: tr("log.tun.toggled", enabled ? tr("log.tun.enabled") : tr("log.tun.disabled")))
            } else {
                appendLog(
                    level: "error",
                    message: tr("log.tun.toggle_failed", tr("app.tun.error.runtime_state_mismatch")))
            }
        } catch {
            appendLog(level: "error", message: tr("log.tun.toggle_failed", self.tunErrorMessage(error)))
            await self.refreshTunStatusFromRuntimeConfig()
        }
    }

    func prepareTunOverlayForCoreStartup(_ overlay: EditableSettingsSnapshot) async throws -> EditableSettingsSnapshot {
        guard overlay.tunEnabled else { return overlay }

        do {
            try await self.ensureTunPermissions(requestIfMissing: true)
            self.syncPrivilegedBackendSelection(tunEnabled: true)
            return overlay
        } catch {
            isTunEnabled = false
            persistEditableSettingsSnapshot()
            self.syncPrivilegedBackendSelection(tunEnabled: false)
            appendLog(level: "warning", message: tr("log.tun.startup_disabled"))
            return overlay.withTunEnabled(false)
        }
    }

    func validateTunPermissionsOnStartup() async {
        guard isTunEnabled else { return }
        do {
            try await self.ensureTunPermissions(requestIfMissing: false)
        } catch {
            if isRuntimeRunning {
                try? await self.patchTunConfig(enable: false)
            }
            isTunEnabled = false
            persistEditableSettingsSnapshot()
            appendLog(level: "warning", message: tr("log.tun.startup_disabled"))
        }
    }

    func tunErrorMessage(_ error: Error) -> String {
        if let permissionError = error as? TunPermissionServiceError {
            switch permissionError {
            case .coreBinaryNotFound, .coreBinaryNotExecutable:
                return tr("app.tun.error.binary_not_found", workingDirectoryManager.coreDirectoryURL.path)
            case let .permissionMissing(command):
                return tr("app.tun.error.permission_missing", command)
            case let .privilegedCoreStale(command):
                return tr("app.tun.error.privileged_core_stale", command)
            case let .privilegedCoreNotTrusted(reason):
                return tr("app.tun.error.privileged_core_untrusted", reason)
            case let .hashingFailed(message):
                return tr("app.tun.error.hashing_failed", message)
            }
        }

        if let tunModeError = error as? TunModeError {
            switch tunModeError {
            case .runtimeStateMismatch:
                return tr("app.tun.error.runtime_state_mismatch")
            }
        }

        if let apiError = error as? APIError,
           case .statusCode = apiError
        {
            return tr("app.tun.error.patch_failed", apiError.localizedDescription)
        }

        return error.localizedDescription
    }

    func resolvedMihomoBinaryPath() -> String? {
        if let detected = coreRepository.detectedBinaryPath,
           !detected.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        {
            return detected
        }

        let current = mihomoBinaryPath.trimmingCharacters(in: .whitespacesAndNewlines)
        if current.isEmpty || current == "-" {
            return nil
        }
        return current
    }

    func ensureTunPermissions(requestIfMissing: Bool) async throws {
        guard let binaryPath = resolvedMihomoBinaryPath() else {
            throw TunPermissionServiceError.coreBinaryNotFound
        }

        do {
            try self.tunPermissionRepository.validateCurrentPermissions(binaryPath: binaryPath)
        } catch let error as TunPermissionServiceError {
            // The app performs no root file operations, so there is nothing to
            // "request" -- both `permissionMissing` and `privilegedCoreStale`
            // are resolved by a command the user runs. Log it once so it is
            // copyable from the log pane, then propagate.
            switch error {
            case .permissionMissing, .privilegedCoreStale:
                guard requestIfMissing else { throw error }
                appendLog(level: "info", message: tr("log.tun.permission_requesting"))
                do {
                    let digest = try await self.tunPermissionRepository
                        .installPrivilegedCore(binaryPath: binaryPath)
                    appendLog(
                        level: "info",
                        message: tr("log.tun.privileged_core_installed", String(digest.prefix(16))))
                } catch let authError as PrivilegedInstallAuthorizationError {
                    // Cancelling is a normal outcome, not a failure to report as
                    // a defect.
                    throw authError
                } catch {
                    // The helper may be unreachable (unregistered, not approved).
                    // Fall back to telling the user what to run by hand so the
                    // feature is not a dead end.
                    appendLog(
                        level: "warning",
                        message: tr(
                            "log.tun.manual_install_required",
                            self.tunPermissionRepository.installCommand(binaryPath: binaryPath)))
                    throw error
                }
            default:
                throw error
            }
        }
    }

    /// Adopts a privileged core left running by a previous session, together
    /// with its controller secret, and records that the privileged backend is
    /// the active one so the UI does not offer to start a second core.
    func reconcileWithPrivilegedHelperAtLaunch() async {
        guard let router = self.processManager as? CoreBackendRouter else { return }
        await router.reconcileWithHelperAtLaunch()
        guard router.isRunning, router.requiresPrivilegedBackend else { return }
        appendLog(level: "info", message: tr("log.tun.adopted_privileged_core"))
        self.adoptPrivilegedControllerSecretIfNeeded()
        if !self.isTunEnabled {
            self.isTunEnabled = true
            persistEditableSettingsSnapshot()
        }
    }

    /// The secret the helper generated for the currently running privileged
    /// core, or nil when no privileged core is running.
    var injectedPrivilegedSecret: String? {
        (self.processManager as? CoreBackendRouter)?.injectedControllerSecret
    }

    /// The helper strips the user's `secret` from the staged config and injects
    /// its own, so after a privileged start the API client has to be rebuilt with
    /// that token. Called from both `startCore` and `restartCore`.
    func adoptPrivilegedControllerSecretIfNeeded() {
        let injected = self.injectedPrivilegedSecret
        let normalized = injected?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let normalized, !normalized.isEmpty else {
            // Back on the unprivileged backend: let the config-derived secret
            // take over again on the next sync.
            return
        }
        guard self.controllerSecret != normalized else { return }
        self.controllerSecret = normalized
        self.refreshControllerUIURL()
        self.ensureAPIClient()
        appendLog(level: "info", message: tr("log.tun.controller_secret_injected"))
    }

    /// True when the next core launch will go through the privileged helper.
    var privilegedBackendRequired: Bool {
        (self.processManager as? CoreBackendRouter)?.requiresPrivilegedBackend ?? false
    }

    /// Chooses the backend for the *next* start/restart. Does nothing to a core
    /// that is already running -- crossing the privilege boundary always needs a
    /// restart, which the callers above perform explicitly.
    func syncPrivilegedBackendSelection(tunEnabled: Bool) {
        guard let router = self.processManager as? CoreBackendRouter else { return }
        router.requiresPrivilegedBackend = tunEnabled && !self.isRemoteTarget
    }

    /// Surfaces a setuid-root core left behind by ClashBar <= 0.x. Enabling TUN
    /// once clears it, but a user who never turns TUN on again would otherwise
    /// keep a root-executable binary in a directory they can write to.
    func warnAboutLegacySetuidCoreIfNeeded() {
        guard let binaryPath = resolvedMihomoBinaryPath() else { return }
        guard self.tunPermissionRepository.legacySetuidPresent(binaryPath: binaryPath) else { return }
        appendLog(
            level: "warning",
            message: tr(
                "log.tun.legacy_setuid_detected",
                binaryPath,
                self.tunPermissionRepository.legacyCleanupCommand(binaryPath: binaryPath)))
    }

    func verifyTunAfterOverlayIfNeeded(overlay: EditableSettingsSnapshot) async {
        guard overlay.tunEnabled, isRuntimeRunning else { return }
        guard pendingCoreFeatureRecoveryState == nil else { return }

        do {
            let config = try await fetchRuntimeConfigSnapshot()
            if config.tunEnabled == true {
                isTunEnabled = true
                persistEditableSettingsSnapshot()
                return
            }

            try await self.patchTunConfig(enable: true)
            try await self.verifyTunRuntimeState(expectedEnabled: true)
            isTunEnabled = true
            persistEditableSettingsSnapshot()
            appendLog(level: "info", message: tr("log.tun.toggled", tr("log.tun.enabled")))
        } catch {
            appendLog(level: "error", message: tr("log.tun.toggle_failed", self.tunErrorMessage(error)))
        }
    }

    func applyTunRuntimeChange(enabled: Bool) async throws {
        guard self.isRemoteTarget || self.isRuntimeRunning else { return }
        try await self.patchTunConfig(enable: enabled)
        try await self.verifyTunRuntimeState(expectedEnabled: enabled)
    }

    func verifyTunRuntimeState(expectedEnabled: Bool) async throws {
        let config = try await fetchRuntimeConfigSnapshot()
        let actual = config.tunEnabled ?? false
        if actual != expectedEnabled {
            throw TunModeError.runtimeStateMismatch(expected: expectedEnabled)
        }
    }

    func patchTunConfig(enable: Bool) async throws {
        let client = try clientOrThrow()
        var tunBody: [String: JSONValue] = ["enable": .bool(enable)]

        if enable, await !self.selectedConfigDeclaresTunStack() {
            tunBody["stack"] = .string("mixed")
        }

        var body: [String: JSONValue] = ["tun": .object(tunBody)]
        if enable {
            body["dns"] = .object(["enable": .bool(true)])
        }
        try await client.requestNoResponse(.patchConfigs(body: body))
    }

    func ensureTunMixedStackOnStartupIfNeeded() async {
        guard self.isRuntimeRunning else { return }

        do {
            let config = try await fetchRuntimeConfigSnapshot()
            guard config.tunEnabled == true else { return }
            let hasConfiguredStack = await self.selectedConfigDeclaresTunStack()

            let client = try clientOrThrow()
            var body: [String: JSONValue] = [
                "dns": .object(["enable": .bool(true)]),
            ]
            if !hasConfiguredStack {
                body["tun"] = .object(["stack": .string("mixed")])
            }
            try await client.requestNoResponse(.patchConfigs(body: body))
            if !hasConfiguredStack {
                _ = try await fetchRuntimeConfigSnapshot()
            }
        } catch {
            appendLog(level: "error", message: tr("log.tun.startup_check_failed", self.tunErrorMessage(error)))
        }
    }

    func selectedConfigDeclaresTunStack() async -> Bool {
        guard
            let configPath = await resolveSelectedConfigPath(),
            let raw = try? String(contentsOfFile: configPath, encoding: .utf8)
        else {
            return false
        }

        let lines = raw.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
        guard let tunRange = self.topLevelBlockRange(for: "tun", lines: lines) else { return false }
        return self.childLineExists(for: "stack", lines: lines, range: tunRange)
    }

    private func childLineExists(for key: String, lines: [String], range: Range<Int>) -> Bool {
        for index in (range.lowerBound + 1)..<range.upperBound {
            let line = lines[index]
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }

            let leadingSpaces = line.prefix { $0 == " " || $0 == "\t" }.count
            guard leadingSpaces > 0 else { continue }

            let content = String(line.dropFirst(leadingSpaces)).trimmingCharacters(in: .whitespaces)
            if content == "\(key):" || content.hasPrefix("\(key): ") {
                return true
            }
        }
        return false
    }

    private func topLevelBlockRange(for key: String, lines: [String]) -> Range<Int>? {
        guard let start = lines.firstIndex(where: { self.isTopLevelKeyLine($0, key: key) }) else {
            return nil
        }

        var end = lines.count
        if start + 1 < lines.count {
            for index in (start + 1)..<lines.count where self.isTopLevelMappingLine(lines[index]) {
                end = index
                break
            }
        }
        return start..<end
    }

    private func isTopLevelKeyLine(_ line: String, key: String) -> Bool {
        guard line.prefix(while: { $0 == " " || $0 == "\t" }).isEmpty else { return false }
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return false }
        return trimmed == "\(key):" || trimmed.hasPrefix("\(key): ")
    }

    private func isTopLevelMappingLine(_ line: String) -> Bool {
        guard line.prefix(while: { $0 == " " || $0 == "\t" }).isEmpty else { return false }
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return false }
        return trimmed.contains(":")
    }

    func refreshTunStatusFromRuntimeConfig() async {
        do {
            let config = try await fetchRuntimeConfigSnapshot()
            if let tunEnabled = config.tunEnabled, isTunEnabled != tunEnabled {
                isTunEnabled = tunEnabled
                persistEditableSettingsSnapshot()
            }
        } catch {}
    }
}
