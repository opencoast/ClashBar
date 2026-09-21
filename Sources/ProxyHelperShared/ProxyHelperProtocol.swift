import Foundation

public enum ProxyHelperConstants {
    public static let machServiceName = "com.clashbar.helper"
    public static let daemonPlistName = "com.clashbar.helper.plist"
    public static let helperBundleProgram = "Contents/Library/HelperTools/com.clashbar.helper"
    public static let allowedClientBundleIdentifier = "com.clashbar"
    public static let allowedClientRequirement = "identifier \"\(allowedClientBundleIdentifier)\""

    /// Code-signing identifier of the helper itself. `codesign` derives this from
    /// the binary's filename when `-i` is not passed, which is what
    /// `Scripts/package_app.sh` does.
    public static let helperBundleIdentifier = "com.clashbar.helper"
    public static let allowedHelperRequirement = "identifier \"\(helperBundleIdentifier)\""

    // MARK: - Privileged core layout
    //
    // Everything below deliberately lives outside the user's home directory.
    // The helper runs as root, and a root process must never execute a binary --
    // or read a configuration -- out of a directory the logged-in user can
    // write to. `/Library/Application Support` is root-owned, so a local
    // attacker running as the console user cannot swap the core out from under
    // the helper, nor hand it a configuration of their choosing.

    public static let privilegedRootPath = "/Library/Application Support/ClashBar"
    public static let privilegedCoreDirectoryPath = privilegedRootPath + "/core"
    public static let privilegedCoreBinaryPath = privilegedCoreDirectoryPath + "/mihomo"
    public static let privilegedRunDirectoryPath = privilegedRootPath + "/run"
    public static let privilegedRuntimeConfigPath = privilegedRunDirectoryPath + "/config.yaml"
    public static let privilegedPidFilePath = privilegedRunDirectoryPath + "/core.pid"
    public static let privilegedLogDirectoryPath = privilegedRootPath + "/logs"
    public static let privilegedCoreLogPath = privilegedLogDirectoryPath + "/core.log"

    /// Resolved by the helper against the home directory of the *audited* euid of
    /// the XPC connection -- never against a path supplied by the client.
    public static let userConfigDirectoryRelativePath = "Library/Application Support/clashbar/config"

    /// Sidecar recording the digest of the core the user authorised. Root-only,
    /// so the app cannot forge it; `startCore` re-checks the binary against it
    /// before spawning, which is what makes the hash load-bearing rather than
    /// decorative.
    public static let privilegedCoreDigestPath = privilegedCoreDirectoryPath + "/mihomo.sha256"

    /// Authorization Services right gating the install. Registered by the helper
    /// with `timeout: 0` so the credential is never cached: every install of new
    /// bytes re-prompts, because that prompt *is* the user's statement that these
    /// particular bytes may run as root.
    public static let installCoreRightName = "com.clashbar.helper.install-core"

    public static let maximumCoreLogBytes = 4 * 1024 * 1024
    public static let maximumConfigBytes = 5 * 1024 * 1024

    /// Sentinel for "this core has not exited during the helper's lifetime".
    public static let unknownExitCode = -1
}

@objc(ProxyHelperProtocol)
public protocol ProxyHelperProtocol {
    func ping(completion: @escaping (Bool, String?) -> Void)
    func setSystemProxy(
        host: String,
        httpPort: Int,
        httpsPort: Int,
        socksPort: Int,
        completion: @escaping (Bool, String?) -> Void)
    func clearSystemProxy(completion: @escaping (Bool, String?) -> Void)
    func getSystemProxyState(completion: @escaping (Bool, Bool, String?) -> Void)
    func getSystemProxyActiveTarget(completion: @escaping (Bool, String?, Int, String?) -> Void)
    func isSystemProxyConfigured(
        host: String,
        httpPort: Int,
        httpsPort: Int,
        socksPort: Int,
        completion: @escaping (Bool, Bool, String?) -> Void)
    func getSystemProxyExceptions(completion: @escaping (Bool, String?, String?) -> Void)
    func setSystemProxyExceptions(serializedExceptions: String, completion: @escaping (Bool, String?) -> Void)

    // MARK: - Privileged core lifecycle
    //
    // Deliberately *not* a general-purpose process launcher. The caller cannot
    // choose the executable, the working directory, the data directory, or any
    // argument other than a bare config filename and a loopback controller
    // endpoint. Everything else is fixed in the helper.

    /// Starts the privileged core.
    ///
    /// - Parameters:
    ///   - configFileName: A bare filename (no path separators) ending in
    ///     `.yaml`/`.yml`, resolved inside the calling user's own config
    ///     directory. Anything else is rejected.
    ///   - controllerHost: Must be a loopback literal (`127.0.0.1` or `::1`).
    ///   - controllerPort: 1...65535.
    ///   - completion: `(ok, pid, secret, message)`. `pid` is 0 on failure.
    ///     `secret` is the controller token the helper generated and injected
    ///     into the staged config; the caller must use it as the bearer token.
    ///     The user's own `secret` is stripped, so this is the only way in.
    func startCore(
        configFileName: String,
        controllerHost: String,
        controllerPort: Int,
        completion: @escaping (Bool, Int, String?, String?) -> Void)

    /// Stops the privileged core. Succeeds when nothing is running.
    func stopCore(completion: @escaping (Bool, String?) -> Void)

    /// `(ok, running, pid, lastExitCode, secret, message)`. `pid` is 0 when not
    /// running; `lastExitCode` is `ProxyHelperConstants.unknownExitCode` when the
    /// core has not exited yet.
    ///
    /// `secret` is the token of the *currently running* core. It has to be
    /// recoverable: the app keeps it only in memory, so after an app restart (or
    /// a helper reconnect) it would otherwise be talking to a live root core it
    /// can no longer authenticate against, and every call returns 401.
    func coreStatus(completion: @escaping (Bool, Bool, Int, Int, String?, String?) -> Void)

    /// Reports whether a usable privileged core is installed, and the SHA-256 of
    /// its bytes so the app can tell a stale copy from a current one.
    /// `(ok, installed, sha256Hex, message)`.
    func privilegedCoreInfo(completion: @escaping (Bool, Bool, String?, String?) -> Void)

    /// Installs the user's managed core as the root-owned privileged core.
    ///
    /// - Parameter authorization: an `AuthorizationExternalForm` blob for
    ///   `installCoreRightName`. The helper re-verifies the right itself; the
    ///   app-side check only exists to raise the password dialog, and a
    ///   malicious client could simply skip it.
    /// - Parameter completion: `(ok, installedSHA256, message)`.
    ///
    /// The source is **not** a parameter: it is resolved from the connection's
    /// audited euid, through an `openat` chain, exactly like the config. A path
    /// from the client would let a caller nominate any readable file to be
    /// installed and executed as root.
    func installPrivilegedCore(
        authorization: Data,
        completion: @escaping (Bool, String?, String?) -> Void)
}
