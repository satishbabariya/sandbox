import Foundation

/// What airlock remembers about a sandbox between commands.
public struct SandboxRecord: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable {
        case running
        /// The supervisor is gone but the record and rootfs remain, so the
        /// sandbox can be recreated under the same name.
        case stopped
    }

    public var name: String
    public var image: String
    public var createdAt: Date
    /// PID of the supervisor holding the VM. Nil once stopped.
    public var supervisorPID: Int32?
    public var allow: [String]
    public var deny: [String]
    public var workspace: String?
    public var privileged: Bool

    public init(
        name: String,
        image: String,
        createdAt: Date = Date(),
        supervisorPID: Int32? = nil,
        allow: [String] = [],
        deny: [String] = [],
        workspace: String? = nil,
        privileged: Bool = false
    ) {
        self.name = name
        self.image = image
        self.createdAt = createdAt
        self.supervisorPID = supervisorPID
        self.allow = allow
        self.deny = deny
        self.workspace = workspace
        self.privileged = privileged
    }

    /// A record is only "running" if its supervisor is still alive. Checking
    /// the process rather than trusting the file means a crashed supervisor
    /// shows as stopped instead of as a sandbox you cannot reach.
    public var state: State {
        guard let pid = supervisorPID, ProcessLiveness.isAlive(pid) else { return .stopped }
        return .running
    }
}

public enum ProcessLiveness {
    /// `kill(pid, 0)` tests for existence without delivering a signal.
    public static func isAlive(_ pid: Int32) -> Bool {
        guard pid > 0 else { return false }
        return kill(pid, 0) == 0 || errno == EPERM
    }
}

public enum StoreError: Error, CustomStringConvertible {
    case notFound(String)
    case alreadyExists(String)
    case invalidName(String)

    public var description: String {
        switch self {
        case .notFound(let name):
            return "no sandbox named '\(name)'"
        case .alreadyExists(let name):
            return "a sandbox named '\(name)' already exists"
        case .invalidName(let name):
            return """
                invalid sandbox name '\(name)': use lowercase letters, digits, \
                '-' and '_', 1-64 characters
                """
        }
    }
}

/// Sandbox records on disk, one JSON file per sandbox.
///
/// A directory of files rather than a single index, so two concurrent commands
/// touching different sandboxes never contend, and a corrupt record takes out
/// one sandbox instead of the whole list.
public struct SandboxStore: Sendable {
    private let directory: URL

    public init(paths: AirlockPaths = AirlockPaths()) {
        self.directory = paths.root.appending(path: "sandboxes")
    }

    public init(directory: URL) {
        self.directory = directory
    }

    /// Names go into file paths and socket paths, so they are validated rather
    /// than sanitised — a silently rewritten name is a confusing name.
    public static func validate(name: String) throws {
        guard (1...64).contains(name.count) else { throw StoreError.invalidName(name) }
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        guard name.allSatisfy({ allowed.contains($0) }) else {
            throw StoreError.invalidName(name)
        }
    }

    private func path(_ name: String) -> URL {
        directory.appending(path: "\(name).json")
    }

    public func save(_ record: SandboxRecord) throws {
        try Self.validate(name: record.name)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(record)
        try data.write(to: path(record.name), options: .atomic)
    }

    public func create(_ record: SandboxRecord) throws {
        if (try? load(record.name)) != nil {
            throw StoreError.alreadyExists(record.name)
        }
        try save(record)
    }

    public func load(_ name: String) throws -> SandboxRecord {
        let url = path(name)
        guard let data = try? Data(contentsOf: url) else {
            throw StoreError.notFound(name)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(SandboxRecord.self, from: data)
    }

    public func remove(_ name: String) throws {
        let url = path(name)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw StoreError.notFound(name)
        }
        try FileManager.default.removeItem(at: url)
    }

    public func list() -> [SandboxRecord] {
        let urls =
            (try? FileManager.default.contentsOfDirectory(
                at: directory, includingPropertiesForKeys: nil)) ?? []
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return
            urls
            .filter { $0.pathExtension == "json" }
            .compactMap { url -> SandboxRecord? in
                guard let data = try? Data(contentsOf: url) else { return nil }
                return try? decoder.decode(SandboxRecord.self, from: data)
            }
            .sorted { $0.createdAt > $1.createdAt }
    }
}
