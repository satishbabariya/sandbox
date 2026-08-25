import Foundation

/// The outcome of evaluating a connection attempt against a policy.
public enum PolicyDecision: Sendable, Equatable {
    /// Permitted; carries the allow pattern that matched.
    case allowed(by: String)
    /// Refused. Carries the deny pattern that matched, or nil when the
    /// connection simply matched no allow rule.
    case denied(by: String?)

    public var isAllowed: Bool {
        if case .allowed = self { return true }
        return false
    }
}

/// A default-deny egress policy.
///
/// Evaluation order is deliberate and mirrors Docker's kit semantics: deny is
/// checked first and always wins, then allow. Anything matching neither list is
/// denied. Overlap between the lists is legal — it is how a broad allow gets a
/// narrow hole punched in it (`allow *.github.com`, `deny gist.github.com`).
public struct NetworkPolicy: Sendable {
    public let allow: [HostPattern]
    public let deny: [HostPattern]

    public init(allow: [HostPattern], deny: [HostPattern]) {
        self.allow = allow
        self.deny = deny
    }

    public init(allow: [String], deny: [String]) throws {
        self.allow = try allow.map(HostPattern.init)
        self.deny = try deny.map(HostPattern.init)
    }

    /// A policy that permits nothing. The safe starting point: a sandbox with
    /// no configured policy reaches nothing at all rather than everything.
    public static let denyAll = NetworkPolicy(
        allow: [HostPattern](), deny: [HostPattern]()
    )

    public func evaluate(host: String, port: UInt16?) -> PolicyDecision {
        for pattern in deny where pattern.matches(host: host, port: port) {
            return .denied(by: pattern.raw)
        }
        for pattern in allow where pattern.matches(host: host, port: port) {
            return .allowed(by: pattern.raw)
        }
        return .denied(by: nil)
    }

    /// Merge two policies additively. Used when composing a base agent profile
    /// with per-run `--allow` flags. Union on both lists, so a merge can only
    /// ever widen `allow` and widen `deny` — and since deny wins, a merged
    /// deny can never be weakened by someone else's allow.
    public func merging(_ other: NetworkPolicy) -> NetworkPolicy {
        func union(_ a: [HostPattern], _ b: [HostPattern]) -> [HostPattern] {
            var seen = Set<HostPattern>()
            var out: [HostPattern] = []
            for p in a + b where seen.insert(p).inserted {
                out.append(p)
            }
            return out
        }
        return NetworkPolicy(
            allow: union(allow, other.allow),
            deny: union(deny, other.deny)
        )
    }
}
