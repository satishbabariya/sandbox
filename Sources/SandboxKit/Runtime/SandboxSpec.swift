import Containerization
import ContainerizationEXT4
import ContainerizationOCI
import ContainerizationOS
import Darwin
import Foundation
import Logging
import SystemPackage

public struct SandboxSpec: Sendable {
    public var id: String
    public var image: String
    /// The command the sandbox runs. Empty means the image's own entrypoint.
    public var command: [String]
    public var environment: [String: String]
    public var policy: NetworkPolicy
    public var cpus: Int
    public var memoryInBytes: UInt64
    public var workspace: URL?
    public var workspaceDestination: String
    /// Extra host directories to share, beyond the workspace.
    public var mounts: [MountSpec]
    /// Give the agent a private git clone instead of your working tree.
    public var cloneWorkspace: Bool
    /// MCP servers to declare to the agent, and where to write the file.
    public var mcp: [MCPServer]
    public var mcpConfigPath: String?
    /// Drop to this unprivileged user before running the command.
    public var runAsUser: String?
    /// Run as uid 0 regardless of the user the image declares.
    ///
    /// Agent images increasingly ship a non-root default user, which is right
    /// for running an agent and wrong for building one: an install step cannot
    /// write to /usr/local/bin. Kits say so themselves -- their install steps
    /// carry `user: "0"`.
    public var runAsRoot: Bool
    /// Files written into the guest before the command runs.
    public var files: [GuestFile]
    /// Commands run as root at every start, after the files are written and
    /// before privilege is dropped.
    public var startup: [StartupCommand]
    /// Guidance written into the workspace, honoured only when the workspace
    /// is a clone.
    public var agentInstructions: AgentInstructions?
    /// Use this prepared ext4 image as the rootfs instead of unpacking the
    /// image fresh. Set by the agent cache.
    public var preparedRootfs: URL?
    public var terminal: Bool
    /// Grant the guest process every Linux capability.
    ///
    /// Needed by workloads that manage their own namespaces and networking,
    /// such as a dockerd running inside the sandbox. It deliberately does NOT
    /// weaken egress policy: the enforcement point is the host end of the
    /// guest's only network device, so CAP_NET_ADMIN buys the guest control
    /// over an interface that still has nowhere else to go.
    public var privileged: Bool
    /// Credentials to broker. The guest receives a sentinel, never the secret.
    public var credentials: [CredentialBinding]
    /// Ports published from the host into the sandbox.
    public var ports: [PortForward]
    /// Give the sandbox its own dockerd, backed by a dedicated block device.
    public var docker: Bool
    /// Size of that block device.
    public var dockerDiskBytes: UInt64
    /// The host terminal to attach when `terminal` is set. Supplying it makes
    /// the guest process interactive: it gets a PTY, and keystrokes and window
    /// size changes reach it.
    public var hostTerminal: Terminal?
    /// Where the guest's stdout goes. Defaults to the host's stdout.
    public var stdout: (any Writer)?
    /// Where the guest's stderr goes. Defaults to the host's stderr.
    public var stderr: (any Writer)?

    public init(
        id: String,
        image: String,
        command: [String] = [],
        environment: [String: String] = [:],
        policy: NetworkPolicy = .denyAll,
        cpus: Int = 4,
        memoryInBytes: UInt64 = 4 * 1024 * 1024 * 1024,
        workspace: URL? = nil,
        workspaceDestination: String = "/workspace",
        mounts: [MountSpec] = [],
        cloneWorkspace: Bool = false,
        mcp: [MCPServer] = [],
        mcpConfigPath: String? = nil,
        runAsUser: String? = nil,
        runAsRoot: Bool = false,
        files: [GuestFile] = [],
        startup: [StartupCommand] = [],
        agentInstructions: AgentInstructions? = nil,
        preparedRootfs: URL? = nil,
        terminal: Bool = false,
        hostTerminal: Terminal? = nil,
        privileged: Bool = false,
        credentials: [CredentialBinding] = [],
        ports: [PortForward] = [],
        docker: Bool = false,
        dockerDiskBytes: UInt64 = 20 * 1024 * 1024 * 1024,
        stdout: (any Writer)? = nil,
        stderr: (any Writer)? = nil
    ) {
        self.id = id
        // Normalised on the way in, so every caller -- run, supervise, a test
        // constructing a spec directly -- reaches the image store with a
        // reference it accepts.
        self.image = ImageReference.normalised(image)
        self.command = command
        self.environment = environment
        self.policy = policy
        self.cpus = cpus
        self.memoryInBytes = memoryInBytes
        self.workspace = workspace
        self.workspaceDestination = workspaceDestination
        self.mounts = mounts
        self.cloneWorkspace = cloneWorkspace
        self.mcp = mcp
        self.mcpConfigPath = mcpConfigPath
        self.runAsUser = runAsUser
        self.runAsRoot = runAsRoot
        self.files = files
        self.startup = startup
        self.agentInstructions = agentInstructions
        self.preparedRootfs = preparedRootfs
        self.terminal = terminal
        self.hostTerminal = hostTerminal
        self.privileged = privileged
        self.credentials = credentials
        self.ports = ports
        self.docker = docker
        self.dockerDiskBytes = dockerDiskBytes
        self.stdout = stdout ?? StreamWriter.standardOutput
        self.stderr = stderr ?? StreamWriter.standardError
    }
}

/// Create a directory only its owner can enter.
///
/// A sandbox's runtime directory sits in /tmp and holds the console output of
/// whatever the agent did, the policy it was given, and the paths of the files
/// holding resolved secrets. The secrets themselves are written 0600, but the
/// rest was 0644 in a world-traversable directory -- so another account on the
/// machine could read an agent's entire console log. Restricting the directory
/// covers everything inside it, whatever mode each file is written with.
