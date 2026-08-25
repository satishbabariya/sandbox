import Foundation

public enum PolicyError: Error, Equatable, CustomStringConvertible {
    case emptyPattern
    case malformedPattern(String, reason: String)

    public var description: String {
        switch self {
        case .emptyPattern:
            return "host pattern must not be empty"
        case .malformedPattern(let raw, let reason):
            return "invalid host pattern '\(raw)': \(reason)"
        }
    }
}

/// A single entry in a network allow- or deny-list.
///
/// Three shapes are accepted, matching the grammar Docker's kit spec validates:
/// an exact host (`api.anthropic.com`), an exact host with a port
/// (`registry.example.com:5000`), or a leading-label wildcard
/// (`*.githubusercontent.com`).
///
/// A pattern with no port matches every port. A wildcard covers the apex
/// domain as well as any depth of subdomain, and only ever matches on a label
/// boundary — `*.example.com` never matches `evilexample.com`.
public struct HostPattern: Sendable, Hashable {
    /// The host portion, lowercased. For a wildcard this is the suffix with
    /// the leading `*.` removed, so `*.example.com` stores `example.com`.
    public let host: String
    public let port: UInt16?
    public let isWildcard: Bool

    /// The original text, preserved for diagnostics and round-tripping.
    public let raw: String

    public init(_ raw: String) throws {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { throw PolicyError.emptyPattern }

        func bad(_ reason: String) -> PolicyError {
            .malformedPattern(raw, reason: reason)
        }

        guard !trimmed.contains("/") else {
            throw bad("expected a bare host, not a URL or path")
        }

        // Split a trailing :port, being careful not to mistake an IPv6 literal's
        // colons for a port separator.
        var hostPart = trimmed
        var portPart: UInt16?
        if let colon = trimmed.lastIndex(of: ":"), !trimmed.hasPrefix("[") {
            let after = trimmed[trimmed.index(after: colon)...]
            let before = String(trimmed[trimmed.startIndex..<colon])
            // Only treat it as a port if there is exactly one colon; more than
            // one means an IPv6 literal, which we require to be bracketed.
            if trimmed.filter({ $0 == ":" }).count > 1 {
                throw bad("bracket IPv6 literals as [::1]")
            }
            guard let parsed = UInt16(after), parsed > 0 else {
                throw bad("port must be an integer in 1...65535")
            }
            guard !before.isEmpty else { throw bad("missing host before port") }
            hostPart = before
            portPart = parsed
        }

        var wildcard = false
        if hostPart.hasPrefix("*") {
            guard hostPart.hasPrefix("*.") else {
                throw bad("a wildcard must be a whole label, as in *.example.com")
            }
            hostPart = String(hostPart.dropFirst(2))
            wildcard = true
            guard !hostPart.isEmpty else {
                throw bad("a wildcard needs a suffix, as in *.example.com")
            }
        }

        guard !hostPart.contains("*") else {
            throw bad("a wildcard is only allowed in the leading label")
        }
        guard !hostPart.isEmpty else { throw bad("missing host") }

        self.raw = trimmed
        self.host = Self.normalize(hostPart)
        self.port = portPart
        self.isWildcard = wildcard
    }

    /// Lowercase and strip a trailing root label so `EXAMPLE.com.` and
    /// `example.com` compare equal.
    static func normalize(_ host: String) -> String {
        var h = host.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }

    public func matches(host queried: String, port queriedPort: UInt16?) -> Bool {
        if let port, port != queriedPort { return false }

        let candidate = Self.normalize(queried)
        guard !candidate.isEmpty else { return false }

        if isWildcard {
            // Apex, or a label-boundary suffix. The "." guard is what stops
            // "*.example.com" from matching "evilexample.com".
            return candidate == host || candidate.hasSuffix("." + host)
        }
        return candidate == host
    }
}

extension HostPattern: CustomStringConvertible {
    public var description: String { raw }
}
