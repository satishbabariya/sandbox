import Containerization
import ContainerizationEXT4
import ContainerizationOCI
import ContainerizationOS
import Darwin
import Foundation
import Logging
import SystemPackage

func createPrivateDirectory(at url: URL) throws {
    try FileManager.default.createDirectory(
        at: url, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
    // createDirectory only applies attributes to directories it creates, so an
    // existing one -- a reused name, or a directory from an older build --
    // keeps whatever mode it had.
    try? FileManager.default.setAttributes(
        [.posixPermissions: 0o700], ofItemAtPath: url.path)
}

/// Where sandbox keeps kernels, images, and per-sandbox runtime state.
public struct SandboxPaths: Sendable {
    public let root: URL

    public init(root: URL? = nil) {
        let home = FileManager.default.homeDirectoryForCurrentUser
        self.root = root ?? home.appending(path: ".sandbox")
        if root == nil { Self.adoptFormerStateDirectory(home: home, into: self.root) }
        // Tightened here as well as at creation, so a directory made by an
        // earlier build -- which left it world-readable -- is corrected the
        // next time sandbox runs rather than staying open forever.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: self.root.path)
    }

    /// Take over the state directory this tool used when it was called airlock.
    ///
    /// Cached agent environments are gigabytes and take minutes each to
    /// rebuild, and the stored agents, templates and configuration are not
    /// rebuildable at all. Leaving them behind under the old name would look
    /// exactly like the tool having forgotten everything.
    ///
    /// Only ever moves into a directory that does not exist yet, so a state
    /// directory already in use is never touched.
    private static func adoptFormerStateDirectory(home: URL, into destination: URL) {
        let former = home.appending(path: ".airlock")
        let manager = FileManager.default
        guard manager.fileExists(atPath: former.path),
            !manager.fileExists(atPath: destination.path)
        else { return }

        do {
            try manager.moveItem(at: former, to: destination)
            FileHandle.standardError.write(
                Data("sandbox: moved ~/.airlock to ~/.sandbox\n".utf8))
        } catch {
            FileHandle.standardError.write(
                Data(
                    ("sandbox: ~/.airlock is from when this was called airlock and could "
                        + "not be moved to ~/.sandbox: \(error)\n").utf8))
        }
    }

    public var kernel: URL { root.appending(path: "vmlinux-arm64") }
    public var images: URL { root.appending(path: "images") }
    public func runtime(_ id: String) -> URL { runtimeRoot.appending(path: id) }

    /// The directories every sandbox's state hangs off, so a sweep can find
    /// what no sandbox owns any more.
    public var runtimeRoot: URL { root.appending(path: "run") }
    public var containerRootParent: URL { images.appending(path: "containers") }

    /// Where ContainerManager unpacks a sandbox's rootfs. Removing a sandbox
    /// has to clear this too, or the name cannot be reused.
    public func containerRoot(_ id: String) -> URL {
        containerRootParent.appending(path: id)
    }

    /// Everything a single sandbox owns on disk.
    public func allDirectories(_ id: String) -> [URL] {
        [runtime(id), socketDirectory(id), containerRoot(id)]
    }

    /// `sun_path` is 104 bytes, and the gateway sockets live in the runtime
    /// directory, so keep that path short by placing sockets under /tmp.
    public func socketDirectory(_ id: String) -> URL {
        URL(filePath: "/tmp/sandbox-\(id)")
    }
}

/// One sandbox: a Linux VM with exactly one network device, whose wire is held
/// by this process.
///
/// The ordering in `start()` is load-bearing. The gateway must be listening
/// before the VM is configured, because the interface handed to Virtualization
/// wraps a socket that has to be connected at configuration time.
