import Foundation

/// An MCP server an agent can call.
///
/// airlock runs MCP servers **inside** the sandbox rather than on the host
/// behind a gateway. A server is a program that reads files and makes network
/// calls on the agent's behalf, so running it inside means it is subject to the
/// same egress policy and sees the same filesystem the agent does. A host-side
/// server would be a process outside the boundary that the sandbox can ask to
/// act for it, which is the thing the boundary exists to prevent.
///
/// The cost is that each sandbox runs its own copy. That is the right trade for
/// a tool whose whole claim is containment.
public struct MCPServer: Codable, Sendable, Equatable {
    public var name: String
    /// Executable to launch, resolved inside the sandbox.
    public var command: String
    public var args: [String]
    public var env: [String: String]
    /// Egress this server needs. Merged into the sandbox's policy, so a server
    /// cannot reach anywhere the agent could not.
    public var allow: [String]
    /// Commands that install it, run once with the agent's environment.
    public var install: [String]

    public init(
        name: String,
        command: String,
        args: [String] = [],
        env: [String: String] = [:],
        allow: [String] = [],
        install: [String] = []
    ) {
        self.name = name
        self.command = command
        self.args = args
        self.env = env
        self.allow = allow
        self.install = install
    }

    /// Servers people reach for most often, so a profile can name one.
    public static let presets: [String: MCPServer] = [
        "filesystem": MCPServer(
            name: "filesystem",
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
            install: ["npm install -g @modelcontextprotocol/server-filesystem"]
        ),
        "git": MCPServer(
            name: "git",
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-git", "--repository", "/workspace"],
            install: ["npm install -g @modelcontextprotocol/server-git"]
        ),
        "github": MCPServer(
            name: "github",
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-github"],
            env: ["GITHUB_PERSONAL_ACCESS_TOKEN": CredentialBinding.sentinel],
            allow: ["api.github.com"],
            install: ["npm install -g @modelcontextprotocol/server-github"]
        ),
        "fetch": MCPServer(
            name: "fetch",
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-fetch"],
            install: ["npm install -g @modelcontextprotocol/server-fetch"]
        ),
    ]

    public static func preset(for name: String) -> MCPServer? {
        presets[name.lowercased()]
    }
}

/// Renders the `mcpServers` object agents read.
///
/// Claude Code, Codex and others converged on the same shape, so one renderer
/// covers them; the profile only says where to put the file.
public enum MCPConfiguration {
    public static func render(_ servers: [MCPServer]) throws -> String {
        var entries: [String: [String: Any]] = [:]
        for server in servers {
            var entry: [String: Any] = [
                "command": server.command,
                "args": server.args,
            ]
            if !server.env.isEmpty {
                entry["env"] = server.env
            }
            entries[server.name] = entry
        }
        let root: [String: Any] = ["mcpServers": entries]
        // withoutEscapingSlashes keeps package names readable; agents parse
        // either form, but a human editing the file should not meet "\/".
        let data = try JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        return String(decoding: data, as: UTF8.self) + "\n"
    }
}
