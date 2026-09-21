import Foundation

/// Every decision the privileged helper makes about *what* it will launch, as
/// pure functions with no filesystem or XPC involvement.
///
/// This lives in the shared library rather than in the helper executable for one
/// reason: it is the security boundary, and an executable target is awkward to
/// `@testable import`. Everything here is exercised by
/// `Tests/ProxyHelperSharedTests` — which matters more than usual, because the
/// privileged path cannot be run end-to-end without a Developer ID.
public enum CoreLaunchValidation {
    public enum Failure: Error, Equatable {
        case invalidConfigFileName(String)
        case invalidControllerHost(String)
        case invalidControllerPort(Int)
        case untrustedUID(UInt32)
    }

    static let allowedFileNameScalars = Set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-".unicodeScalars)

    /// A bare `*.yaml`/`*.yml` filename. Rejects anything that could walk out of
    /// the caller's own config directory, plus anything a naive `lastPathComponent`
    /// round-trip would quietly normalise.
    public static func validatedConfigFileName(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmed.isEmpty, trimmed.count <= 128 else {
            throw Failure.invalidConfigFileName(raw)
        }
        // No separators, no NUL, no traversal, no dotfiles.
        guard !trimmed.contains("/"), !trimmed.contains("\\"), !trimmed.contains("\0") else {
            throw Failure.invalidConfigFileName(raw)
        }
        guard !trimmed.hasPrefix("."), trimmed != "..", trimmed != "." else {
            throw Failure.invalidConfigFileName(raw)
        }
        // Whitelist, so no clever Unicode (RTL overrides, NFD variants of the
        // separator, homoglyphs) can widen the set.
        guard trimmed.unicodeScalars.allSatisfy({ Self.allowedFileNameScalars.contains($0) }) else {
            throw Failure.invalidConfigFileName(raw)
        }
        // Belt and braces: the name must be its own last path component.
        guard trimmed == (trimmed as NSString).lastPathComponent else {
            throw Failure.invalidConfigFileName(raw)
        }
        let ext = (trimmed as NSString).pathExtension.lowercased()
        guard ext == "yaml" || ext == "yml" else {
            throw Failure.invalidConfigFileName(raw)
        }
        // "….yaml" with nothing before the dot is a dotfile, already rejected,
        // but guard the stem explicitly so ".yaml" can never slip through.
        guard !(trimmed as NSString).deletingPathExtension.isEmpty else {
            throw Failure.invalidConfigFileName(raw)
        }
        return trimmed
    }

    /// The controller of a *root* process is never allowed off the loopback
    /// interface, whatever the user's config says.
    public static func validatedControllerHost(_ raw: String) throws -> String {
        switch raw.trimmingCharacters(in: .whitespacesAndNewlines) {
        case "127.0.0.1":
            return "127.0.0.1"
        case "::1", "[::1]":
            return "[::1]"
        default:
            throw Failure.invalidControllerHost(raw)
        }
    }

    public static func validatedControllerPort(_ raw: Int) throws -> Int {
        guard (1...65535).contains(raw) else { throw Failure.invalidControllerPort(raw) }
        return raw
    }

    /// Refuses root and the system-user range; the XPC peer is expected to be a
    /// console user.
    public static func validatedClientUID(_ uid: UInt32) throws -> UInt32 {
        guard uid != 0, uid >= 500 else { throw Failure.untrustedUID(uid) }
        return uid
    }
}

/// Endpoint the privileged core exposes its controller on.
public struct PrivilegedControllerEndpoint: Equatable, Sendable {
    public let host: String
    public let port: Int

    public init(host: String, port: Int) {
        self.host = host
        self.port = port
    }

    public var displayValue: String {
        self.host == "::1" ? "[::1]:\(self.port)" : "\(self.host):\(self.port)"
    }

    /// Parses an `external-controller` value. A non-loopback bind address is
    /// **rewritten** to `127.0.0.1` rather than rejected: the helper would refuse
    /// it anyway, and silently widening a root process's controller to the LAN is
    /// precisely what we are trying to prevent. A missing port falls back to
    /// `defaultPort` instead of throwing, so `external-controller: 127.0.0.1`
    /// still starts.
    public static func parse(
        _ raw: String,
        defaultPort: Int = 9090) throws -> PrivilegedControllerEndpoint
    {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw CoreLaunchValidation.Failure.invalidControllerHost(raw)
        }

        var hostPart: String
        var portPart: String?

        if trimmed.hasPrefix("[") {
            guard let close = trimmed.firstIndex(of: "]") else {
                throw CoreLaunchValidation.Failure.invalidControllerHost(raw)
            }
            hostPart = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
            let rest = trimmed[trimmed.index(after: close)...]
            portPart = rest.hasPrefix(":") ? String(rest.dropFirst()) : nil
        } else if let separator = trimmed.lastIndex(of: ":") {
            // `::1` (bare IPv6 loopback, no port) has no host part before the
            // last colon; treat that as host-only.
            let head = String(trimmed[trimmed.startIndex..<separator])
            let tail = String(trimmed[trimmed.index(after: separator)...])
            if head.isEmpty || Int(tail) == nil {
                hostPart = trimmed
                portPart = nil
            } else {
                hostPart = head
                portPart = tail
            }
        } else {
            hostPart = trimmed
            portPart = nil
        }

        let port: Int
        if let portPart, !portPart.isEmpty {
            guard let parsed = Int(portPart), (1...65535).contains(parsed) else {
                throw CoreLaunchValidation.Failure.invalidControllerPort(Int(portPart) ?? -1)
            }
            port = parsed
        } else {
            port = defaultPort
        }

        let host: String
        switch hostPart {
        case "::1", "[::1]", "::":
            host = "::1"
        default:
            host = "127.0.0.1"
        }
        return PrivilegedControllerEndpoint(host: host, port: port)
    }
}

/// Rewrites a user-authored mihomo config before a **root** core is allowed to
/// read it.
///
/// A remote subscription can set any of these keys, and the user's config is not
/// a trusted input to a privileged process. Two classes are removed:
///
///   * **control plane** — `external-controller*`, `secret`, `external-ui*`,
///     `external-doh-server`, `tls`. Without this, a subscription can move the
///     root core's REST API onto the LAN, or strip the secret we inject, and
///     `POST /upgrade` then lets anyone overwrite a root-owned binary.
///   * **inbound exposure** — `allow-lan`, `bind-address`, `authentication`,
///     `skip-auth-prefixes`, `lan-allowed-ips`, `lan-disallowed-ips`,
///     `listeners`, `tunnels`. These decide *where* the core listens and whether
///     it authenticates; `allow-lan: true` plus
///     `skip-auth-prefixes: ["0.0.0.0/0"]` is an open relay run as root.
///
/// Proxy port keys are intentionally left alone: the app already owns them and
/// they are not a privilege boundary.
public enum ConfigSanitizer {
    public static let strippedTopLevelKeys: Set<String> = [
        // control plane
        "external-controller",
        "external-controller-tls",
        "external-controller-unix",
        "external-controller-pipe",
        "external-controller-cors",
        "external-doh-server",
        "secret",
        "external-ui",
        "external-ui-url",
        "external-ui-name",
        "tls",
        // inbound exposure
        "allow-lan",
        "bind-address",
        "authentication",
        "skip-auth-prefixes",
        "lan-allowed-ips",
        "lan-disallowed-ips",
        "listeners",
        "tunnels",
    ]

    public struct Result: Equatable {
        public let yaml: String
        public let removedKeys: [String]

        public init(yaml: String, removedKeys: [String]) {
            self.yaml = yaml
            self.removedKeys = removedKeys
        }
    }

    /// - Parameter injectedSecret: appended as a top-level `secret:`. Any
    ///   pre-existing `secret` has already been stripped, so no duplicate key is
    ///   produced.
    public static func sanitize(yaml raw: String, injectedSecret: String?) -> Result {
        // Normalise line endings so a CRLF config does not defeat the top-level
        // key detection (a trailing \r would make "secret:\r" not match).
        let normalized = raw.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")

        var output: [String] = []
        var removed: [String] = []
        var skippingBlockFor: String?

        for line in normalized.components(separatedBy: "\n") {
            let isDocumentMarker = line == "---" || line == "..."
            if isDocumentMarker {
                skippingBlockFor = nil
                output.append(line)
                continue
            }

            if let key = self.topLevelKey(of: line) {
                // A new top-level key ends any block we were dropping.
                skippingBlockFor = nil
                if self.strippedTopLevelKeys.contains(key) {
                    removed.append(key)
                    skippingBlockFor = key
                    continue
                }
                output.append(line)
                continue
            }

            // Continuation line (indented, blank, or a comment): drop it only if
            // it belongs to a block we are removing.
            if skippingBlockFor != nil {
                // A blank line does not terminate a YAML block, but a
                // non-indented non-empty line would have matched above.
                continue
            }
            output.append(line)
        }

        var result = output.joined(separator: "\n")
        if let injectedSecret, !injectedSecret.isEmpty {
            if !result.hasSuffix("\n") { result += "\n" }
            result += """
            # --- appended by the ClashBar privileged helper; do not edit ---
            secret: "\(injectedSecret)"

            """
        }
        return Result(yaml: result, removedKeys: removed)
    }

    /// Returns the top-level key name for a line, or nil if the line is not a
    /// top-level mapping key (indented, blank, a comment, a list item, …).
    static func topLevelKey(of line: String) -> String? {
        guard let first = line.unicodeScalars.first else { return nil }
        // Any leading whitespace means it is nested, not top-level.
        guard first != " ", first != "\t" else { return nil }
        guard first != "#", first != "-" else { return nil }

        guard let colon = line.firstIndex(of: ":") else { return nil }
        var key = String(line[line.startIndex..<colon])

        // Quoted keys: "secret": x / 'secret': x
        if key.count >= 2 {
            let f = key.first!
            let l = key.last!
            if (f == "\"" && l == "\"") || (f == "'" && l == "'") {
                key = String(key.dropFirst().dropLast())
            }
        }
        key = key.trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty else { return nil }
        return key.lowercased()
    }
}
