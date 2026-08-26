import Containerization
import Foundation

/// The serialisable half of a sandbox definition.
///
/// `SandboxSpec` carries live stdout/stderr writers, which cannot cross a
/// process boundary. This is what `airlock run --detach` hands to the
/// supervisor it spawns.
public struct LaunchSpec: Codable, Sendable, Equatable {
    public var name: String
    public var image: String
    public var command: [String]
    public var environment: [String: String]
    public var allow: [String]
    public var deny: [String]
    public var cpus: Int
    public var memoryInBytes: UInt64
    public var workspace: String?
    public var workspaceDestination: String
    public var privileged: Bool
    /// Services whose credentials the broker should inject.
    public var secrets: [String]
    /// Give the sandbox its own dockerd.
    public var docker: Bool
    /// Extra host:guest[:ro] mounts.
    public var mounts: [String]
    /// Prepared rootfs from the agent cache, if any.
    public var preparedRootfs: String?
    /// Agent this sandbox was launched from, for display.
    public var agent: String?
    /// Published ports, as [[HOST:]HOSTPORT:]GUESTPORT.
    public var ports: [String]
    /// Give the agent a private git clone rather than the working tree.
    public var clone: Bool
    /// MCP servers to run inside the sandbox.
    public var mcp: [MCPServer]
    public var mcpConfigPath: String?
    /// Drop to this unprivileged user before running the command.
    public var runAsUser: String?

    public init(
        name: String,
        image: String,
        command: [String] = [],
        environment: [String: String] = [:],
        allow: [String] = [],
        deny: [String] = [],
        cpus: Int = 4,
        memoryInBytes: UInt64 = 4 * 1024 * 1024 * 1024,
        workspace: String? = nil,
        workspaceDestination: String = "/workspace",
        privileged: Bool = false,
        secrets: [String] = [],
        docker: Bool = false,
        mounts: [String] = [],
        preparedRootfs: String? = nil,
        agent: String? = nil,
        ports: [String] = [],
        clone: Bool = false,
        mcp: [MCPServer] = [],
        mcpConfigPath: String? = nil,
        runAsUser: String? = nil
    ) {
        self.name = name
        self.image = image
        self.command = command
        self.environment = environment
        self.allow = allow
        self.deny = deny
        self.cpus = cpus
        self.memoryInBytes = memoryInBytes
        self.workspace = workspace
        self.workspaceDestination = workspaceDestination
        self.privileged = privileged
        self.secrets = secrets
        self.docker = docker
        self.mounts = mounts
        self.preparedRootfs = preparedRootfs
        self.agent = agent
        self.ports = ports
        self.clone = clone
        self.mcp = mcp
        self.mcpConfigPath = mcpConfigPath
        self.runAsUser = runAsUser
    }

    /// Build a runnable spec. Writers are supplied by the caller because they
    /// differ between an attached run and a detached supervisor.
    public func sandboxSpec(
        stdout: (any Writer)? = nil,
        stderr: (any Writer)? = nil,
        terminal: Bool = false
    ) throws -> SandboxSpec {
        var spec = SandboxSpec(
            id: name,
            image: image,
            command: command,
            environment: environment,
            policy: try NetworkPolicy(allow: allow, deny: deny),
            cpus: cpus,
            memoryInBytes: memoryInBytes,
            workspaceDestination: workspaceDestination,
            mounts: mounts.compactMap(MountSpec.parse),
            cloneWorkspace: clone,
            mcp: mcp,
            mcpConfigPath: mcpConfigPath,
            runAsUser: runAsUser,
            preparedRootfs: preparedRootfs.map { URL(filePath: $0) },
            terminal: terminal,
            privileged: privileged,
            credentials: bindings,
            ports: try ports.map(PortForward.parse),
            docker: docker,
            stdout: stdout,
            stderr: stderr
        )
        if let workspace {
            spec.workspace = URL(filePath: workspace)
        }
        return spec
    }

    /// Resolve service names to bindings, ignoring any without a known one —
    /// storing a secret with no binding should not stop a sandbox starting.
    public var bindings: [CredentialBinding] {
        secrets.compactMap { CredentialBinding.preset(for: $0) }
    }

    public var record: SandboxRecord {
        SandboxRecord(
            name: name,
            image: image,
            allow: allow,
            deny: deny,
            workspace: workspace,
            privileged: privileged
        )
    }
}
