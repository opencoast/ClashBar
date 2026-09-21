import XCTest
@testable import ProxyHelperShared

/// These tests carry more weight than usual: without an Apple Developer ID the
/// privileged helper cannot be loaded, so the root-side path is never exercised
/// end-to-end. Everything that decides *what* the root core will run is pure and
/// is pinned here instead.
final class ConfigFileNameValidationTests: XCTestCase {
    private func accepts(_ input: String) {
        XCTAssertNoThrow(
            try CoreLaunchValidation.validatedConfigFileName(input),
            "should accept \(input.debugDescription)")
    }

    private func rejects(_ input: String, _ why: String) {
        XCTAssertThrowsError(
            try CoreLaunchValidation.validatedConfigFileName(input),
            "should reject \(input.debugDescription) — \(why)")
    }

    func testAcceptsPlainNames() {
        self.accepts("config.yaml")
        self.accepts("config.yml")
        self.accepts("my-config.yaml")
        self.accepts("my_config.yaml")
        self.accepts("a.b.c.yaml")
        self.accepts("CONFIG.YAML")
        self.accepts("  config.yaml  ") // trimmed
    }

    func testRejectsTraversal() {
        self.rejects("../../../etc/passwd", "parent traversal")
        self.rejects("../config.yaml", "parent traversal with valid extension")
        self.rejects("..", "bare parent")
        self.rejects(".", "bare current")
        self.rejects("sub/config.yaml", "forward slash")
        self.rejects("sub\\config.yaml", "backslash")
        self.rejects("/etc/config.yaml", "absolute path")
        self.rejects("config.yaml/", "trailing slash")
    }

    func testRejectsDotfilesAndEmptyStems() {
        self.rejects(".yaml", "extension only")
        self.rejects(".hidden.yaml", "leading dot")
        self.rejects("", "empty")
        self.rejects("   ", "whitespace only")
    }

    func testRejectsWrongExtension() {
        self.rejects("config", "no extension")
        self.rejects("config.txt", "wrong extension")
        self.rejects("config.yaml.sh", "extension is sh")
        self.rejects("mihomo", "looks like a binary")
    }

    func testRejectsHostileCharacters() {
        self.rejects("config\u{0000}.yaml", "embedded NUL")
        self.rejects("config\u{202E}.yaml", "right-to-left override")
        self.rejects("конфиг.yaml", "non-ASCII")
        self.rejects("config .yaml", "interior space")
        self.rejects("con;fig.yaml", "shell metacharacter")
        self.rejects("$(whoami).yaml", "command substitution")
        self.rejects("config\n.yaml", "newline")
    }

    func testRejectsOverlyLongNames() {
        self.rejects(String(repeating: "a", count: 130) + ".yaml", "over 128 chars")
    }
}

final class ControllerValidationTests: XCTestCase {
    func testHostAcceptsOnlyLoopback() throws {
        XCTAssertEqual(try CoreLaunchValidation.validatedControllerHost("127.0.0.1"), "127.0.0.1")
        XCTAssertEqual(try CoreLaunchValidation.validatedControllerHost("::1"), "[::1]")
        XCTAssertEqual(try CoreLaunchValidation.validatedControllerHost("[::1]"), "[::1]")

        for hostile in ["0.0.0.0", "::", "192.168.1.5", "10.0.0.1", "localhost", "example.com", ""] {
            XCTAssertThrowsError(
                try CoreLaunchValidation.validatedControllerHost(hostile),
                "a root core must never bind \(hostile)")
        }
    }

    func testPortRange() throws {
        XCTAssertEqual(try CoreLaunchValidation.validatedControllerPort(1), 1)
        XCTAssertEqual(try CoreLaunchValidation.validatedControllerPort(65535), 65535)
        XCTAssertThrowsError(try CoreLaunchValidation.validatedControllerPort(0))
        XCTAssertThrowsError(try CoreLaunchValidation.validatedControllerPort(-1))
        XCTAssertThrowsError(try CoreLaunchValidation.validatedControllerPort(65536))
    }

    func testClientUID() throws {
        XCTAssertEqual(try CoreLaunchValidation.validatedClientUID(501), 501)
        XCTAssertThrowsError(try CoreLaunchValidation.validatedClientUID(0), "root is not a client")
        XCTAssertThrowsError(try CoreLaunchValidation.validatedClientUID(1), "system users are not clients")
        XCTAssertThrowsError(try CoreLaunchValidation.validatedClientUID(499))
    }
}

final class PrivilegedControllerEndpointTests: XCTestCase {
    func testLoopbackPassesThrough() throws {
        XCTAssertEqual(
            try PrivilegedControllerEndpoint.parse("127.0.0.1:9090"),
            PrivilegedControllerEndpoint(host: "127.0.0.1", port: 9090))
        XCTAssertEqual(
            try PrivilegedControllerEndpoint.parse("[::1]:9090"),
            PrivilegedControllerEndpoint(host: "::1", port: 9090))
    }

    /// The whole point: a config that would expose the controller is narrowed,
    /// not honoured.
    func testNonLoopbackIsRewrittenToLoopback() throws {
        for wide in ["0.0.0.0:9090", "192.168.1.5:9090", "example.com:9090"] {
            XCTAssertEqual(
                try PrivilegedControllerEndpoint.parse(wide).host,
                "127.0.0.1",
                "\(wide) must be narrowed")
            XCTAssertEqual(try PrivilegedControllerEndpoint.parse(wide).port, 9090)
        }
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("[::]:9090").host, "::1")
    }

    func testMissingPortFallsBackInsteadOfThrowing() throws {
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("127.0.0.1").port, 9090)
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("::1").host, "::1")
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("::1").port, 9090)
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("127.0.0.1", defaultPort: 19090).port, 19090)
    }

    /// Regression: `::1` was being split on its *last* colon, yielding host ":"
    /// (rewritten to 127.0.0.1) and port 1. A bare IPv6 literal has no port,
    /// because attaching one requires brackets.
    func testBareIPv6LiteralIsNotSplitOnItsOwnColons() throws {
        let loopback = try PrivilegedControllerEndpoint.parse("::1")
        XCTAssertEqual(loopback.host, "::1")
        XCTAssertEqual(loopback.port, 9090)

        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("::").host, "::1")
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("::").port, 9090)

        // A non-loopback IPv6 literal is still narrowed to loopback.
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("fe80::1").host, "127.0.0.1")
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("fe80::1").port, 9090)

        // Unbracketed IPv6-with-port is malformed; treat the whole thing as a
        // host and narrow it rather than guessing a port out of it.
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("::1:9090").host, "127.0.0.1")

        // IPv4 still splits normally.
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse("127.0.0.1:9090").port, 9090)
        XCTAssertEqual(try PrivilegedControllerEndpoint.parse(":9090").port, 9090)
    }

    func testRejectsGarbage() {
        XCTAssertThrowsError(try PrivilegedControllerEndpoint.parse(""))
        XCTAssertThrowsError(try PrivilegedControllerEndpoint.parse("127.0.0.1:99999"))
        XCTAssertThrowsError(try PrivilegedControllerEndpoint.parse("[::1]:abc"))
    }

    func testDisplayValueBracketsIPv6() {
        XCTAssertEqual(PrivilegedControllerEndpoint(host: "::1", port: 9090).displayValue, "[::1]:9090")
        XCTAssertEqual(PrivilegedControllerEndpoint(host: "127.0.0.1", port: 9090).displayValue, "127.0.0.1:9090")
    }
}

final class ConfigSanitizerTests: XCTestCase {
    private func sanitize(_ yaml: String, secret: String? = nil) -> ConfigSanitizer.Result {
        ConfigSanitizer.sanitize(yaml: yaml, injectedSecret: secret)
    }

    /// Regression guard: if someone trims this set, the reason each key is on it
    /// is recorded in `ConfigSanitizer`'s doc comment.
    func testDangerousKeySetIsComplete() {
        for key in [
            "external-controller", "external-controller-tls", "external-controller-unix",
            "external-doh-server", "secret", "external-ui", "external-ui-url", "external-ui-name",
            "tls", "allow-lan", "bind-address", "authentication", "skip-auth-prefixes",
            "listeners", "tunnels",
        ] {
            XCTAssertTrue(
                ConfigSanitizer.strippedTopLevelKeys.contains(key),
                "\(key) must be stripped before a root core reads the config")
        }
    }

    func testStripsControlPlaneScalars() {
        let result = self.sanitize("""
        mixed-port: 7890
        external-controller: 0.0.0.0:9090
        secret: hunter2
        external-ui: /tmp/ui
        allow-lan: true
        bind-address: '*'
        mode: rule
        """)
        XCTAssertFalse(result.yaml.contains("external-controller"))
        XCTAssertFalse(result.yaml.contains("hunter2"))
        XCTAssertFalse(result.yaml.contains("allow-lan"))
        XCTAssertFalse(result.yaml.contains("bind-address"))
        // Untouched keys survive.
        XCTAssertTrue(result.yaml.contains("mixed-port: 7890"))
        XCTAssertTrue(result.yaml.contains("mode: rule"))
        XCTAssertEqual(
            Set(result.removedKeys),
            ["external-controller", "secret", "external-ui", "allow-lan", "bind-address"])
    }

    func testStripsWholeNestedBlock() {
        let result = self.sanitize("""
        listeners:
          - name: open-relay
            type: socks
            port: 1080
            listen: 0.0.0.0
        proxies:
          - name: keep-me
            type: socks5
        """)
        XCTAssertFalse(result.yaml.contains("open-relay"))
        XCTAssertFalse(result.yaml.contains("1080"))
        XCTAssertFalse(result.yaml.contains("listen: 0.0.0.0"))
        XCTAssertTrue(result.yaml.contains("proxies:"))
        XCTAssertTrue(result.yaml.contains("keep-me"))
    }

    /// The killer combination from the review: `allow-lan` binds every interface
    /// and `skip-auth-prefixes` disables the only compensating control.
    func testStripsOpenRelayCombination() {
        let result = self.sanitize("""
        allow-lan: true
        authentication:
          - "user:pass"
        skip-auth-prefixes:
          - 0.0.0.0/0
        proxies: []
        """)
        XCTAssertFalse(result.yaml.contains("allow-lan"))
        XCTAssertFalse(result.yaml.contains("skip-auth-prefixes"))
        XCTAssertFalse(result.yaml.contains("0.0.0.0/0"))
        XCTAssertFalse(result.yaml.contains("user:pass"))
        XCTAssertTrue(result.yaml.contains("proxies: []"))
    }

    /// A nested key that merely shares a name must survive — a proxy's own
    /// `secret` field is not the controller secret.
    func testDoesNotStripNestedKeysOfTheSameName() {
        let result = self.sanitize("""
        proxies:
          - name: a
            type: snell
            psk: abc
            secret: not-the-controller-secret
            allow-lan: irrelevant
        """)
        XCTAssertTrue(result.yaml.contains("not-the-controller-secret"))
        XCTAssertTrue(result.yaml.contains("allow-lan: irrelevant"))
        XCTAssertTrue(result.removedKeys.isEmpty)
    }

    func testHandlesCRLFAndQuotedAndCasedKeys() {
        let crlf = self.sanitize("mixed-port: 7890\r\nsecret: leak\r\nmode: rule\r\n")
        XCTAssertFalse(crlf.yaml.contains("leak"))
        XCTAssertTrue(crlf.yaml.contains("mode: rule"))

        XCTAssertFalse(self.sanitize("\"secret\": leak\nmode: rule").yaml.contains("leak"))
        XCTAssertFalse(self.sanitize("'secret': leak\nmode: rule").yaml.contains("leak"))
        XCTAssertFalse(self.sanitize("Secret: leak\nmode: rule").yaml.contains("leak"))
        XCTAssertFalse(self.sanitize("secret : leak\nmode: rule").yaml.contains("leak"))
    }

    func testPreservesCommentsListsAndDocumentMarkers() {
        let result = self.sanitize("""
        # top comment
        ---
        mode: rule
        ...
        """)
        XCTAssertTrue(result.yaml.contains("# top comment"))
        XCTAssertTrue(result.yaml.contains("---"))
        XCTAssertTrue(result.yaml.contains("mode: rule"))
    }

    func testInjectsSecretExactlyOnce() {
        let result = self.sanitize("secret: old\nmode: rule", secret: "abc123")
        XCTAssertFalse(result.yaml.contains("old"))
        XCTAssertTrue(result.yaml.contains("secret: \"abc123\""))
        // No duplicate top-level key, which mihomo's parser would reject or
        // resolve unpredictably.
        let occurrences = result.yaml.components(separatedBy: "secret:").count - 1
        XCTAssertEqual(occurrences, 1, "exactly one top-level secret key")
    }

    func testNoSecretInjectedWhenNoneSupplied() {
        let result = self.sanitize("mode: rule")
        XCTAssertFalse(result.yaml.contains("secret"))
    }

    func testTopLevelKeyDetection() {
        XCTAssertEqual(ConfigSanitizer.topLevelKey(of: "secret: x"), "secret")
        XCTAssertEqual(ConfigSanitizer.topLevelKey(of: "secret:"), "secret")
        XCTAssertNil(ConfigSanitizer.topLevelKey(of: "  secret: x"), "indented is nested")
        XCTAssertNil(ConfigSanitizer.topLevelKey(of: "\tsecret: x"), "tab-indented is nested")
        XCTAssertNil(ConfigSanitizer.topLevelKey(of: "# secret: x"), "comment")
        XCTAssertNil(ConfigSanitizer.topLevelKey(of: "- secret: x"), "list item")
        XCTAssertNil(ConfigSanitizer.topLevelKey(of: ""), "blank")
        XCTAssertNil(ConfigSanitizer.topLevelKey(of: "no colon here"), "not a mapping")
    }
}
