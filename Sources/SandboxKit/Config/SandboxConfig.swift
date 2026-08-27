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

    private enum CodingKeys: String, CodingKey {
        case defaultAgent, cpus, memory, allow, deny, clone, secrets
    }

    /// Decoded field by field with defaults, so every key is optional.
    ///
    /// Two reasons. A config written by hand should only have to state what it
    /// changes rather than every key. And a config written by an older sandbox
    /// must keep loading after a field is added -- with the synthesised
    /// decoder, adding `secrets` made every config predating it fail as
    /// "not valid JSON", which is both alarming and untrue.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            defaultAgent: try c.decodeIfPresent(String.self, forKey: .defaultAgent),
            cpus: try c.decodeIfPresent(Int.self, forKey: .cpus),
            memory: try c.decodeIfPresent(String.self, forKey: .memory),
            allow: try c.decodeIfPresent([String].self, forKey: .allow) ?? [],
            deny: try c.decodeIfPresent([String].self, forKey: .deny) ?? [],
            clone: try c.decodeIfPresent(Bool.self, forKey: .clone),
            secrets: try c.decodeIfPresent([String].self, forKey: .secrets) ?? [])
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
        let config: SandboxConfig
        do {
            config = try JSONDecoder().decode(SandboxConfig.self, from: data)
        } catch {
            throw ConfigError.malformed(url, underlying: "\(error)")
        }
        // Checked here rather than left to fail when the policy is assembled.
        // Both refuse to run, but only this one can say which file is wrong --
        // and a rule in a config has been wrong since someone wrote it, not
        // since the command they just typed.
        try config.validate(from: url)
        return config
    }

    public func save(_ paths: SandboxPaths = SandboxPaths()) throws {
        try createPrivateDirectory(at: paths.root)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: Self.path(paths), options: .atomic)
    }

    /// Validate before anything is written, so a typo cannot land in a file
    /// that every later run has to read.
    public func validate(from source: URL? = nil) throws {
        for pattern in allow + deny {
            do {
                _ = try HostPattern(pattern)
            } catch {
                // Say which file, when there is one. A rule read from
                // config.json fails exactly like one typed on the command line,
                // and without the path a user goes looking at the command they
                // just ran rather than at the file that has been wrong for
                // weeks.
                guard let source else { throw error }
                throw ConfigError.invalid("\(source.path): \(error)")
            }
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
