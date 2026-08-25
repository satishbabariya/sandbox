import Containerization
import Foundation
import Logging

/// Builds an agent's root filesystem once and caches it.
///
/// The first launch of an agent installs a toolchain, which takes minutes. That
/// happens here, in a throwaway sandbox, and the resulting filesystem is kept.
/// Every later launch clones it.
///
/// The install sandbox gets the agent's own egress rules and nothing more, so a
/// compromised package cannot reach further during installation than the agent
/// could once running.
public actor AgentPreparer {
    private let paths: AirlockPaths
    private let cache: RootfsCache
    private let logger: Logger?

    public init(paths: AirlockPaths = AirlockPaths(), logger: Logger? = nil) {
        self.paths = paths
        self.cache = RootfsCache(paths: paths, logger: logger)
        self.logger = logger
    }

    public enum Progress: Sendable {
        case alreadyCached
        case pulling(String)
        case installing(step: Int, of: Int, command: String)
        case caching
        case ready
    }

    /// Return a rootfs with the agent installed, building it if needed.
    public func prepare(
        _ profile: AgentProfile,
        gatewayBinary: URL,
        force: Bool = false,
        onProgress: @Sendable (Progress) -> Void = { _ in }
    ) async throws -> URL {
        let cached = cache.cachedPath(for: profile)
        if !force, cache.isCached(profile) {
            onProgress(.alreadyCached)
            return cached
        }
        if force {
            try await cache.remove(profile)
        }
        guard !profile.install.isEmpty else {
            // Nothing to install: the image is already the environment, so
            // there is nothing worth caching.
            onProgress(.ready)
            return cached
        }

        let buildID = "build-\(profile.name)-\(UInt32.random(in: 0..<0xFFFF))"
        onProgress(.pulling(profile.image))

        // Install steps need the agent's own egress, and its package
        // registries, but nothing beyond that.
        let policy = try NetworkPolicy(
            allow: profile.allow + AgentProfile.commonToolingEgress
                + ["deb.debian.org", "security.debian.org", "*.debian.org"],
            deny: []
        )

        let script = profile.install.enumerated().map { index, command in
            """
            echo "airlock: [\(index + 1)/\(profile.install.count)] \(command.prefix(60))"
            \(command) || { echo "airlock: install step failed: \(command)" >&2; exit 1; }
            """
        }.joined(separator: "\n")

        let spec = SandboxSpec(
            id: buildID,
            image: profile.image,
            command: ["/bin/sh", "-lc", script],
            policy: policy,
            cpus: 4,
            memoryInBytes: 4 * 1024 * 1024 * 1024
        )

        let sandbox = Sandbox(spec: spec, paths: paths, logger: logger)
        for (index, command) in profile.install.enumerated() {
            onProgress(.installing(step: index + 1, of: profile.install.count, command: command))
        }

        try await sandbox.start(gatewayBinary: gatewayBinary)
        let status = try await sandbox.wait()
        await sandbox.stop()

        let builtRootfs = paths.containerRoot(buildID).appending(path: "rootfs.ext4")
        defer { try? FileManager.default.removeItem(at: paths.containerRoot(buildID)) }

        guard status == 0 else {
            throw PrepareError.installFailed(profile.name, status: status)
        }
        guard FileManager.default.fileExists(atPath: builtRootfs.path) else {
            throw PrepareError.rootfsMissing(builtRootfs)
        }

        onProgress(.caching)
        try FileManager.default.createDirectory(
            at: cache.directory, withIntermediateDirectories: true)
        try? FileManager.default.removeItem(at: cached)
        try FileManager.default.moveItem(at: builtRootfs, to: cached)

        onProgress(.ready)
        return cached
    }
}

public enum PrepareError: Error, CustomStringConvertible {
    case installFailed(String, status: Int32)
    case rootfsMissing(URL)

    public var description: String {
        switch self {
        case .installFailed(let name, let status):
            return """
                installing '\(name)' failed with status \(status)
                the environment was not cached, so the next run will retry
                """
        case .rootfsMissing(let url):
            return "expected a built rootfs at \(url.path)"
        }
    }
}
