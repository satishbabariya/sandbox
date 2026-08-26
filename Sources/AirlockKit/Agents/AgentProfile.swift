import Foundation

/// A declarative description of how to run one coding agent.
///
/// The point is that `airlock run claude` should work without the user knowing
/// which image, which egress rules, or which credential the agent needs. A
/// profile carries all three, and `--allow` on the command line adds to it
/// rather than replacing it.
/// A file written into the guest at every start.
///
/// Staged as content rather than as a host path on purpose: a kit that ships a
/// launcher script has to be able to place it without the user first
/// materialising it somewhere on their own disk.
public struct GuestFile: Codable, Sendable, Equatable {
    public var path: String
    public var content: String
    /// Octal mode, as a string so a leading zero survives YAML.
    public var mode: String?

    public init(path: String, content: String, mode: String? = nil) {
        self.path = path
        self.content = content
        self.mode = mode
    }
}

/// Guidance a kit wants the agent to read before it starts work.
///
/// Delivered only when the workspace is a clone. An agent reads this from its
/// working directory, which by default is a live share of the user's own tree
/// -- writing it there would mean a kit dropping a file into their repository.
/// `--clone` gives the agent a tree of its own, and that one is fair game.
public struct AgentInstructions: Codable, Sendable, Equatable {
    /// Conventional default; kits that target a specific agent override it.
    public static let defaultFilename = "AGENTS.md"

    public var filename: String
    public var content: String

    public init(filename: String? = nil, content: String) {
        self.filename = filename.flatMap { $0.isEmpty ? nil : $0 } ?? Self.defaultFilename
        self.content = content
    }

    private enum CodingKeys: String, CodingKey { case filename, content }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            filename: try c.decodeIfPresent(String.self, forKey: .filename),
            content: try c.decode(String.self, forKey: .content))
    }
}

/// A command run as root at every sandbox start.
///
/// Decodes either as a bare argv array or as an object with `background`, so a
/// profile written by hand can stay terse while a kit that starts a daemon can
/// say so.
public struct StartupCommand: Codable, Sendable, Equatable {
    public var argv: [String]
    /// Start it and move on, rather than waiting for it to exit. A helper
    /// daemon never returns, so waiting would hold the sandbox before the
    /// agent ever ran.
    public var background: Bool

    public init(argv: [String], background: Bool = false) {
        self.argv = argv
        self.background = background
    }

    private enum CodingKeys: String, CodingKey {
        case argv, background
    }

    public init(from decoder: any Decoder) throws {
        if let bare = try? decoder.singleValueContainer().decode([String].self) {
            self.init(argv: bare)
            return
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            argv: try c.decode([String].self, forKey: .argv),
            background: try c.decodeIfPresent(Bool.self, forKey: .background) ?? false)
    }
}

public struct AgentProfile: Codable, Sendable, Equatable {
    public var name: String
    public var displayName: String
    /// Base image the agent runs in.
    public var image: String
    /// Shell commands that install the agent. Run once, then cached.
    public var install: [String]
    /// What to execute when the sandbox starts.
    public var command: [String]
    /// Egress the agent needs to function at all.
    public var allow: [String]
    /// Credential services to broker.
    public var secrets: [String]
    /// Bindings for services airlock has no preset for, or that need more than
    /// one domain.
    ///
    /// A kit states the environment variable, domain, header and format for
    /// every credential it uses, so it can describe a service airlock has
    /// never heard of. Without this, importing such a kit silently produced an
    /// agent with no credential at all.
    public var bindings: [CredentialBinding]
    /// Host paths mounted into the guest, as "host:guest" or "host:guest:ro".
    /// Tilde is expanded.
    ///
    /// Use `:copy` for anything the agent writes to. An agent's own config is
    /// the obvious case: mounting it read-write lets a sandboxed agent rewrite
    /// the user's real configuration, which is precisely the kind of host
    /// damage a sandbox exists to prevent. A copy gives the guest a private
    /// one that is discarded with the sandbox.
    public var mounts: [String]
    public var environment: [String: String]
    /// Give this agent its own dockerd.
    public var docker: Bool
    /// Run the agent as this unprivileged user rather than root.
    ///
    /// Agents increasingly refuse to run privileged — Claude Code declines
    /// --dangerously-skip-permissions as root outright — and an agent has no
    /// business being root inside its own VM either. The user is created on
    /// first launch if the image lacks it.
    public var runAsUser: String?
    /// MCP servers to run inside the sandbox, by preset name or full spec.
    public var mcp: [MCPServer]
    /// Where this agent reads its MCP configuration, inside the guest.
    public var mcpConfigPath: String?
    /// Files written into the guest before the agent runs.
    public var files: [GuestFile]
    /// Commands run as root at every start, after the files are written and
    /// before privilege is dropped.
    ///
    /// Distinct from `install`, which runs once and is baked into the cached
    /// rootfs. Startup work is what cannot be cached: reconciling state,
    /// starting a helper daemon, reacting to what the host mounted this time.
    /// Each entry is an argv, so nothing is re-parsed by a shell it did not
    /// come from.
    public var startup: [StartupCommand]
    /// Guidance written into the agent's working directory, when that
    /// directory is a clone rather than the user's own tree.
    public var agentInstructions: AgentInstructions?

    public init(
        name: String,
        displayName: String,
        image: String,
        install: [String] = [],
        command: [String] = [],
        allow: [String] = [],
        secrets: [String] = [],
        mounts: [String] = [],
        environment: [String: String] = [:],
        docker: Bool = false,
        mcp: [MCPServer] = [],
        mcpConfigPath: String? = nil,
        runAsUser: String? = nil,
        files: [GuestFile] = [],
        startup: [StartupCommand] = [],
        agentInstructions: AgentInstructions? = nil,
        bindings: [CredentialBinding] = []
    ) {
        self.name = name
        self.displayName = displayName
        self.image = image
        self.install = install
        self.command = command
        self.allow = allow
        self.secrets = secrets
        self.mounts = mounts
        self.environment = environment
        self.docker = docker
        self.mcp = mcp
        self.mcpConfigPath = mcpConfigPath
        self.runAsUser = runAsUser
        self.files = files
        self.startup = startup
        self.agentInstructions = agentInstructions
        self.bindings = bindings
    }

    /// Decoded field by field with defaults rather than by the synthesised
    /// initialiser, for two reasons. A profile written by hand should only have
    /// to state what it wants, not every empty list. And a profile written by
    /// an older airlock must keep loading after a field is added -- the
    /// registry drops anything that fails to decode, so a strict decode would
    /// silently make a user's imported kits disappear on upgrade.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        image = try c.decode(String.self, forKey: .image)
        displayName = try c.decodeIfPresent(String.self, forKey: .displayName) ?? name
        install = try c.decodeIfPresent([String].self, forKey: .install) ?? []
        command = try c.decodeIfPresent([String].self, forKey: .command) ?? []
        allow = try c.decodeIfPresent([String].self, forKey: .allow) ?? []
        secrets = try c.decodeIfPresent([String].self, forKey: .secrets) ?? []
        mounts = try c.decodeIfPresent([String].self, forKey: .mounts) ?? []
        environment = try c.decodeIfPresent([String: String].self, forKey: .environment) ?? [:]
        docker = try c.decodeIfPresent(Bool.self, forKey: .docker) ?? false
        mcp = try c.decodeIfPresent([MCPServer].self, forKey: .mcp) ?? []
        mcpConfigPath = try c.decodeIfPresent(String.self, forKey: .mcpConfigPath)
        runAsUser = try c.decodeIfPresent(String.self, forKey: .runAsUser)
        files = try c.decodeIfPresent([GuestFile].self, forKey: .files) ?? []
        startup = try c.decodeIfPresent([StartupCommand].self, forKey: .startup) ?? []
        agentInstructions = try c.decodeIfPresent(
            AgentInstructions.self, forKey: .agentInstructions)
        bindings = try c.decodeIfPresent([CredentialBinding].self, forKey: .bindings) ?? []
    }

    /// Everything the sandbox must be able to reach: the agent's own rules plus
    /// whatever its MCP servers need. Keeping these together means a server can
    /// never require a hole the profile did not declare.
    public var allEgress: [String] {
        allow + mcp.flatMap(\.allow)
    }

    /// Install steps for the agent and its MCP servers, in that order.
    public var allInstall: [String] {
        install + mcp.flatMap(\.install)
    }
}

extension AgentProfile {
    /// Egress every agent needs regardless of vendor: fetching its own
    /// toolchain and packages. Kept separate so a profile lists only what is
    /// specific to it, and so this set is auditable in one place.
    public static let commonToolingEgress = [
        "registry.npmjs.org",
        "*.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "*.pypi.org",
    ]

    /// Egress for cloning and pushing over HTTPS.
    public static let gitEgress = [
        "github.com",
        "*.github.com",
        "*.githubusercontent.com",
    ]

    public static let builtIns: [AgentProfile] = [
        AgentProfile(
            name: "claude",
            displayName: "Claude Code",
            image: "docker.io/library/node:22-bookworm-slim",
            install: [
                "apt-get update -qq && apt-get install -y -qq --no-install-recommends "
                    + "git curl ca-certificates ripgrep less sudo python3 python3-pip",
                "npm install -g @anthropic-ai/claude-code",
            ],
            command: ["claude", "--dangerously-skip-permissions"],
            allow: ["api.anthropic.com", "statsig.anthropic.com", "sentry.io"]
                + commonToolingEgress + gitEgress,
            secrets: ["anthropic", "claude"],
            // Both are copies, not binds: Claude Code rewrites its config, and
            // a bind would let a sandboxed agent corrupt the user's real one.
            // It reads .claude.json as a file beside the directory, not inside
            // it, and refuses to start without it.
            mounts: ["~/.claude:/root/.claude:copy", "~/.claude.json:/root/.claude.json:copy"],
            mcpConfigPath: "/root/.mcp.json",
            runAsUser: "agent"
        ),
        AgentProfile(
            name: "codex",
            displayName: "OpenAI Codex CLI",
            image: "docker.io/library/node:22-bookworm-slim",
            install: [
                "apt-get update -qq && apt-get install -y -qq --no-install-recommends "
                    + "git curl ca-certificates ripgrep less sudo python3 python3-pip",
                "npm install -g @openai/codex",
            ],
            command: ["codex"],
            allow: ["api.openai.com", "chatgpt.com", "auth.openai.com"]
                + commonToolingEgress + gitEgress,
            secrets: ["openai"],
            mounts: ["~/.codex:/root/.codex:copy"],
            mcpConfigPath: "/root/.mcp.json",
            runAsUser: "agent"
        ),
        AgentProfile(
            name: "gemini",
            displayName: "Gemini CLI",
            image: "docker.io/library/node:22-bookworm-slim",
            install: [
                "apt-get update -qq && apt-get install -y -qq --no-install-recommends "
                    + "git curl ca-certificates ripgrep less sudo python3 python3-pip",
                "npm install -g @google/gemini-cli",
            ],
            command: ["gemini"],
            allow: [
                "generativelanguage.googleapis.com",
                "*.googleapis.com",
                "accounts.google.com",
            ] + commonToolingEgress + gitEgress,
            secrets: ["gemini"],
            mounts: ["~/.gemini:/root/.gemini:copy"],
            mcpConfigPath: "/root/.mcp.json",
            runAsUser: "agent"
        ),
        AgentProfile(
            name: "opencode",
            displayName: "OpenCode",
            image: "docker.io/library/node:22-bookworm-slim",
            install: [
                "apt-get update -qq && apt-get install -y -qq --no-install-recommends "
                    + "git curl ca-certificates ripgrep less sudo python3 python3-pip",
                "npm install -g opencode-ai",
            ],
            command: ["opencode"],
            allow: ["api.anthropic.com", "api.openai.com", "openrouter.ai"]
                + commonToolingEgress + gitEgress,
            secrets: ["anthropic"],
            mounts: ["~/.config/opencode:/root/.config/opencode:copy"],
            mcpConfigPath: "/root/.mcp.json",
            runAsUser: "agent"
        ),
        AgentProfile(
            name: "shell",
            displayName: "Plain shell",
            image: "docker.io/library/debian:bookworm-slim",
            install: [
                "apt-get update -qq && apt-get install -y -qq --no-install-recommends "
                    + "git curl ca-certificates ripgrep less vim sudo python3"
            ],
            command: ["/bin/bash"],
            allow: commonToolingEgress + gitEgress,
            runAsUser: "agent"
        ),
    ]
}

public enum AgentError: Error, CustomStringConvertible {
    case unknown(String, available: [String])
    case malformed(String, underlying: String)

    public var description: String {
        switch self {
        case .unknown(let name, let available):
            return """
                no agent named '\(name)'
                available: \(available.joined(separator: ", "))
                or pass an image reference instead, e.g. alpine:3.20
                """
        case .malformed(let path, let underlying):
            return "could not read agent profile at \(path): \(underlying)"
        }
    }
}

/// Resolves an agent name to a profile, letting the user override a built-in
/// or add their own by dropping JSON into the agents directory.
public struct AgentRegistry: Sendable {
    private let directory: URL

    public init(paths: AirlockPaths = AirlockPaths()) {
        self.directory = paths.root.appending(path: "agents")
    }

    public init(directory: URL) {
        self.directory = directory
    }

    public var agentsDirectory: URL { directory }

    /// User-defined profiles shadow built-ins of the same name, so a built-in
    /// can be customised without forking anything.
    public func all() -> [AgentProfile] {
        var byName: [String: AgentProfile] = [:]
        for profile in AgentProfile.builtIns {
            byName[profile.name] = profile
        }
        for profile in userProfiles() {
            byName[profile.name] = profile
        }
        return byName.values.sorted { $0.name < $1.name }
    }

    public func userProfiles() -> [AgentProfile] {
        profiles().valid
    }

    /// User profiles, alongside the files that could not be read.
    ///
    /// A profile that fails to decode used to be dropped in silence, and the
    /// only symptom was `airlock run <name>` deciding the name must be an image
    /// and reporting "invalid domain for image reference" -- which says nothing
    /// about the profile sitting right there.
    public func profiles() -> (valid: [AgentProfile], broken: [(URL, any Error)]) {
        let urls =
            (try? FileManager.default.contentsOfDirectory(
                at: directory, includingPropertiesForKeys: nil)) ?? []
        var valid: [AgentProfile] = []
        var broken: [(URL, any Error)] = []
        for url in urls where url.pathExtension == "json" {
            do {
                let data = try Data(contentsOf: url)
                valid.append(try JSONDecoder().decode(AgentProfile.self, from: data))
            } catch {
                broken.append((url, error))
            }
        }
        return (valid, broken)
    }

    public func profile(named name: String) throws -> AgentProfile {
        let profiles = all()
        guard let match = profiles.first(where: { $0.name == name }) else {
            throw AgentError.unknown(name, available: profiles.map(\.name))
        }
        return match
    }

    /// True when the argument names an agent rather than an image.
    ///
    /// Image references contain a `/`, a `:` tag, or a registry host; agent
    /// names are bare words. Checking the registry first means a user-defined
    /// agent called `node` still wins over the image of the same name.
    public func isAgentName(_ argument: String) -> Bool {
        all().contains { $0.name == argument }
    }

    public func write(_ profile: AgentProfile) throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(profile).write(
            to: directory.appending(path: "\(profile.name).json"), options: .atomic)
    }
}

/// One `host:guest[:ro|:copy]` mount.
public struct MountSpec: Sendable, Equatable {
    public var source: URL
    public var destination: String
    public var readOnly: Bool
    /// Give the guest a private copy rather than the host's own files.
    public var copy: Bool

    /// Parse a mount argument, expanding `~`.
    ///
    /// Returns nil when the host path does not exist — an agent profile may
    /// reference a config directory the user has never created, and that should
    /// not stop the sandbox from starting.
    public init(source: URL, destination: String, readOnly: Bool, copy: Bool = false) {
        self.source = source
        self.destination = destination
        self.readOnly = readOnly
        self.copy = copy
    }

    public static func parse(_ raw: String) -> MountSpec? {
        let parts = raw.split(separator: ":", maxSplits: 2).map(String.init)
        guard parts.count >= 2 else { return nil }

        var host = parts[0]
        if host.hasPrefix("~") {
            host =
                FileManager.default.homeDirectoryForCurrentUser.path
                + host.dropFirst()
        }
        let url = URL(filePath: host).standardizedFileURL
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }

        let mode = parts.count > 2 ? parts[2] : ""
        return MountSpec(
            source: url,
            destination: parts[1],
            readOnly: mode == "ro",
            copy: mode == "copy"
        )
    }
}
