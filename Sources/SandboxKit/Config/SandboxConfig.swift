import Foundation

/// User defaults, read from `~/.sandbox/config.json`.
///
/// Everything here is a default that command-line flags override, with one
/// deliberate exception: `deny` is additive. A deny rule in config cannot be
/// removed by a flag, so an operator can pin a hard block for every sandbox on
/// the machine and know it holds.
public struct SandboxConfig: Codable, Sendable, Equatable {
    /// Agent used when `sandbox run` is given no target.
    public var defaultAgent: String?
    public var cpus: Int?
    /// Memory as a human string, e.g. "8g".
    public var memory: String?
    /// Extra egress permitted for every sandbox.
    public var allow: [String]
    /// Egress refused for every sandbox. Never weakened by a flag.
    public var deny: [String]
    /// Default to working on a private clone rather than the tree itself.
    public var clone: Bool?
    /// Secrets brokered into every sandbox.
    public var secrets: [String]

    public init(
        defaultAgent: String? = nil,
        cpus: Int? = nil,
        memory: String? = nil,
        allow: [String] = [],
        deny: [String] = [],
        clone: Bool? = nil,
        secrets: [String] = []
    ) {
        self.defaultAgent = defaultAgent
        self.cpus = cpus
        self.memory = memory
        self.allow = allow
        self.deny = deny
        self.clone = clone
        self.secrets = secrets
    }

    public static func path(_ paths: SandboxPaths = SandboxPaths()) -> URL {
        paths.root.appending(path: "config.json")
    }

    /// Load the config, or return defaults when there is none.
    ///
    /// A malformed config is an error rather than a silent fallback: quietly
    /// ignoring it could drop a `deny` rule the user believes is in force.
    public static func load(_ paths: SandboxPaths = SandboxPaths()) throws -> SandboxConfig {
        let url = path(paths)
        guard let data = try? Data(contentsOf: url) else { return SandboxConfig() }
        do {
            return try JSONDecoder().decode(SandboxConfig.self, from: data)
        } catch {
            throw ConfigError.malformed(url, underlying: "\(error)")
        }
    }

    public func save(_ paths: SandboxPaths = SandboxPaths()) throws {
        try createPrivateDirectory(at: paths.root)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: Self.path(paths), options: .atomic)
    }

    /// Validate before anything is written, so a typo cannot land in a file
    /// that every later run has to read.
    public func validate() throws {
        for pattern in allow + deny {
            _ = try HostPattern(pattern)
        }
        if let cpus, cpus < 1 {
            throw ConfigError.invalid("cpus must be at least 1")
        }
    }
}

public enum ConfigError: Error, CustomStringConvertible {
    case malformed(URL, underlying: String)
    case invalid(String)
    case unknownKey(String, known: [String])

    public var description: String {
        switch self {
        case .malformed(let url, let underlying):
            return """
                \(url.path) is not valid JSON: \(underlying)
                fix or delete it — sandbox will not ignore a config it cannot read,
                because that could silently drop a deny rule
                """
        case .invalid(let reason):
            return reason
        case .unknownKey(let key, let known):
            return "unknown setting '\(key)'; known settings: \(known.joined(separator: ", "))"
        }
    }
}
