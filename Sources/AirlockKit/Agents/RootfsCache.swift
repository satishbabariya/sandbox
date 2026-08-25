import Containerization
import ContainerizationOCI
import Crypto
import Darwin
import Foundation
import Logging

/// Prepared root filesystems for agents, so install steps run once rather than
/// on every launch.
///
/// Installing an agent means an `apt-get` and an `npm install -g`, which takes
/// minutes. Doing it per run would make the tool unusable, so the first launch
/// builds a rootfs and every later launch clones it — copy-on-write where the
/// filesystem supports it, which on APFS makes the clone effectively free.
///
/// The cache key covers the image and the exact install commands, so editing a
/// profile rebuilds rather than silently reusing a stale environment.
public actor RootfsCache {
    private let paths: AirlockPaths
    private let logger: Logger?

    public init(paths: AirlockPaths = AirlockPaths(), logger: Logger? = nil) {
        self.paths = paths
        self.logger = logger
    }

    public nonisolated var directory: URL {
        paths.root.appending(path: "cache/agents")
    }

    /// Identifies a prepared environment. Changing the image or any install
    /// command changes the key.
    public nonisolated static func key(for profile: AgentProfile) -> String {
        var hasher = SHA256()
        hasher.update(data: Data(profile.image.utf8))
        for command in profile.install {
            hasher.update(data: Data(command.utf8))
        }
        let digest = hasher.finalize()
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return "\(profile.name)-\(hex.prefix(12))"
    }

    public nonisolated func cachedPath(for profile: AgentProfile) -> URL {
        directory.appending(path: "\(Self.key(for: profile)).ext4")
    }

    public nonisolated func isCached(_ profile: AgentProfile) -> Bool {
        FileManager.default.fileExists(atPath: cachedPath(for: profile).path)
    }

    /// Copy the cached rootfs for a new sandbox, preferring a CoW clone.
    public nonisolated func materialize(_ profile: AgentProfile, at destination: URL) throws {
        let source = cachedPath(for: profile)
        try FileManager.default.createDirectory(
            at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? FileManager.default.removeItem(at: destination)

        // clonefile makes this O(1) on APFS. A plain copy of a multi-GB image
        // would otherwise dominate startup.
        let cloned = clonefile(
            source.path(percentEncoded: false),
            destination.path(percentEncoded: false),
            0
        )
        if cloned != 0 {
            try FileManager.default.copyItem(at: source, to: destination)
        }
    }

    public func remove(_ profile: AgentProfile) throws {
        try? FileManager.default.removeItem(at: cachedPath(for: profile))
    }

    public func removeAll() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    public nonisolated func list() -> [(key: String, bytes: UInt64)] {
        let urls =
            (try? FileManager.default.contentsOfDirectory(
                at: directory, includingPropertiesForKeys: [.fileSizeKey])) ?? []
        return
            urls
            .filter { $0.pathExtension == "ext4" }
            .map { url in
                let size =
                    (try? url.resourceValues(forKeys: [.totalFileAllocatedSizeKey])
                        .totalFileAllocatedSize) ?? 0
                return (key: url.deletingPathExtension().lastPathComponent, bytes: UInt64(size))
            }
            .sorted { $0.key < $1.key }
    }
}
