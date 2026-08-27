import Darwin
import Foundation

/// Saved sandbox filesystems, reusable as the starting point for new ones.
///
/// An agent environment built by `AgentPreparer` is reproducible from a
/// profile. A template is the other thing: a sandbox someone configured by hand
/// — extra packages, a checked-out branch, a logged-in CLI — captured so the
/// next sandbox starts from it.
public struct TemplateStore: Sendable {
    private let paths: SandboxPaths

    public init(paths: SandboxPaths = SandboxPaths()) {
        self.paths = paths
    }

    public var directory: URL {
        paths.root.appending(path: "templates")
    }

    public func path(_ name: String) -> URL {
        directory.appending(path: "\(name).ext4")
    }

    public func exists(_ name: String) -> Bool {
        FileManager.default.fileExists(atPath: path(name).path)
    }

    /// Capture a sandbox's root filesystem under `name`.
    ///
    /// The caller must quiesce the filesystem first; this only copies. A clone
    /// is attempted before a copy so a multi-gigabyte image costs nothing on
    /// APFS.
    public func save(from rootfs: URL, as name: String, overwrite: Bool = false) throws {
        try SandboxStore.validate(name: name)
        guard FileManager.default.isReadableFile(atPath: rootfs.path) else {
            throw TemplateError.sourceMissing(rootfs)
        }
        if exists(name), !overwrite {
            throw TemplateError.alreadyExists(name)
        }
        try createPrivateDirectory(at: directory)

        let destination = path(name)
        try? FileManager.default.removeItem(at: destination)
        let cloned = clonefile(
            rootfs.path(percentEncoded: false),
            destination.path(percentEncoded: false), 0)
        if cloned != 0 {
            try FileManager.default.copyItem(at: rootfs, to: destination)
        }
        // clonefile preserves the source's timestamps, so stamp the copy with
        // when the template was actually taken. Creation date is not reliably
        // settable on APFS, so listing reads the modification date.
        try? FileManager.default.setAttributes(
            [.modificationDate: Date()], ofItemAtPath: destination.path)
    }

    public func remove(_ name: String) throws {
        guard exists(name) else { throw TemplateError.notFound(name) }
        try FileManager.default.removeItem(at: path(name))
    }

    public func list() -> [(name: String, bytes: UInt64, created: Date)] {
        let urls =
            (try? FileManager.default.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: [
                    .totalFileAllocatedSizeKey, .contentModificationDateKey,
                ]))
            ?? []
        return
            urls
            .filter { $0.pathExtension == "ext4" }
            .map { url in
                let values = try? url.resourceValues(forKeys: [
                    .totalFileAllocatedSizeKey, .contentModificationDateKey,
                ])
                return (
                    name: url.deletingPathExtension().lastPathComponent,
                    bytes: UInt64(values?.totalFileAllocatedSize ?? 0),
                    created: values?.contentModificationDate ?? Date.distantPast
                )
            }
            .sorted { $0.created > $1.created }
    }
}

public enum TemplateError: Error, CustomStringConvertible {
    case notFound(String)
    case alreadyExists(String)
    case sourceMissing(URL)

    public var description: String {
        switch self {
        case .notFound(let name):
            return "no template named '\(name)'"
        case .alreadyExists(let name):
            return "template '\(name)' already exists; pass --force to replace it"
        case .sourceMissing(let url):
            return "no root filesystem at \(url.path)"
        }
    }
}
