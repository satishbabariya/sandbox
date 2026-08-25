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
        privileged: Bool = false
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
            terminal: terminal,
            privileged: privileged,
            stdout: stdout,
            stderr: stderr
        )
        if let workspace {
            spec.workspace = URL(filePath: workspace)
        }
        return spec
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
