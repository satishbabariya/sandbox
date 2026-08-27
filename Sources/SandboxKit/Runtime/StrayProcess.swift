import Foundation

/// A supervisor or gateway still running for a sandbox that no longer exists.
///
/// The pid files in a runtime directory handle the ordinary case, but they live
/// in the directory being cleaned up: a process whose directory was removed
/// before it was stopped becomes unfindable, and the only recourse was `pkill`.
/// Both processes name their runtime directory on their own command line, so
/// they can be identified without guessing.
public struct StrayProcess: Sendable, Equatable {
    public enum Kind: String, Sendable {
        case supervisor
        case gateway
    }

    public var pid: Int32
    public var kind: Kind
    public var directory: String
}

extension StrayProcess {
    /// Every stray process on this machine.
    public static func all(
        fileExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
    ) -> [StrayProcess] {
        parse(processListing()).filter {
            // A live sandbox always has its runtime directory. Its absence is
            // the whole basis for calling a process an orphan.
            $0.pid != ProcessInfo.processInfo.processIdentifier && !fileExists($0.directory)
        }
    }

    /// `ps -axo pid=,command=`, or empty if it cannot be run.
    static func processListing() -> String {
        let listing = Process()
        listing.executableURL = URL(filePath: "/bin/ps")
        listing.arguments = ["-axo", "pid=,command="]
        let pipe = Pipe()
        listing.standardOutput = pipe
        listing.standardError = FileHandle.nullDevice
        guard (try? listing.run()) != nil else { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        listing.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    public static func parse(_ listing: String) -> [StrayProcess] {
        listing.split(separator: "\n").compactMap { parse(line: String($0)) }
    }

    /// One line of the listing, or nil if it is not one of ours.
    ///
    /// Separated from the sweep because what this decides gets a SIGTERM.
    /// Matching is on the executable, never on the command line as a whole: a
    /// shell, a grep or an editor whose *arguments* mention these names is not
    /// one of our processes, and matching loosely killed the shell this was
    /// first tested from.
    public static func parse(line: String) -> StrayProcess? {
        let text = line.trimmingCharacters(in: .whitespaces)
        guard let space = text.firstIndex(of: " "),
            let pid = Int32(text[text.startIndex..<space]), pid > 0
        else { return nil }

        let command = String(text[space...]).trimmingCharacters(in: .whitespaces)
        let arguments = command.split(separator: " ", maxSplits: 1)
        guard let executable = arguments.first else { return nil }
        let program = URL(filePath: String(executable)).lastPathComponent
        let rest = arguments.count > 1 ? String(arguments[1]) : ""

        let kind: Kind
        if program == "sandbox", rest.hasPrefix("supervise") {
            kind = .supervisor
        } else if program == "gvsandbox" {
            kind = .gateway
        } else {
            return nil
        }

        // Each is given its runtime directory as an argument; without one there
        // is nothing to judge it against.
        guard
            let range = command.range(
                of: "/tmp/sandbox-[A-Za-z0-9_.-]+", options: .regularExpression)
        else { return nil }
        return StrayProcess(pid: pid, kind: kind, directory: String(command[range]))
    }
}

extension StrayProcess {
    /// Whether a pid currently belongs to one of sandbox's own processes.
    ///
    /// A pid file outlives the process it names, and pids are reused. Checking
    /// only that *something* answers to the number means a recycled pid gets a
    /// SIGTERM meant for a gateway that exited hours ago -- and the something
    /// could be anything the user is running. Asking what the process actually
    /// is costs one ps and removes the whole class of mistake.
    public static func isOurs(pid: Int32, executable: (Int32) -> String? = commandName) -> Bool {
        guard pid > 0, let name = executable(pid) else { return false }
        return name == "sandbox" || name == "gvsandbox"
    }

    /// The executable name of a running process, or nil if it is gone.
    public static func commandName(pid: Int32) -> String? {
        let listing = Process()
        listing.executableURL = URL(filePath: "/bin/ps")
        listing.arguments = ["-p", "\(pid)", "-o", "comm="]
        let pipe = Pipe()
        listing.standardOutput = pipe
        listing.standardError = FileHandle.nullDevice
        guard (try? listing.run()) != nil else { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        listing.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        return URL(filePath: text).lastPathComponent
    }
}
