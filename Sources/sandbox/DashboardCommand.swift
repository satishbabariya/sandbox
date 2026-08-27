import ArgumentParser
import ContainerizationOS
import Darwin
import Foundation
import SandboxKit

/// A live view of what the sandboxes are doing.
///
/// `ls` answers "what exists" and `policy log` answers "why was that refused",
/// but neither answers "what is happening right now" — which is the question
/// while an agent is working. This puts both on one screen and keeps them
/// current.
///
/// Deliberately drawn with plain ANSI rather than a curses dependency: the
/// whole screen is redrawn each tick, which is simple to reason about and
/// perfectly adequate at one frame a second.
struct DashboardCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "top",
        abstract: "Live view of running sandboxes and their network decisions.",
        aliases: ["dashboard"]
    )

    @Option(name: .long, help: "Seconds between refreshes.")
    var interval: Double = 1.0

    @Option(name: .long, help: "How many recent decisions to show.")
    var decisions: Int = 12

    func run() async throws {
        guard isatty(STDOUT_FILENO) == 1 else {
            throw CleanExit.message(
                "sandbox top needs a terminal; use 'sandbox ls' when piping")
        }

        let terminal = try Terminal.current
        try terminal.setraw()

        // Restore the terminal whatever happens. Leaving it in raw mode with
        // the cursor hidden makes the user's shell unusable.
        @Sendable func restore() {
            print("\u{1B}[?25h\u{1B}[?1049l", terminator: "")
            terminal.tryReset()
        }
        let trap = SignalTrap {
            restore()
            Darwin.exit(0)
        }
        trap.arm()
        defer {
            trap.disarm()
            restore()
        }

        // Alternate screen buffer, so quitting leaves the scrollback intact.
        print("\u{1B}[?1049h\u{1B}[?25l", terminator: "")

        while true {
            let size = (try? terminal.size) ?? Terminal.Size(width: 80, height: 24)
            render(width: Int(size.width), height: Int(size.height))

            // Poll stdin so a keypress is noticed without blocking the refresh.
            if let key = readKey(timeout: interval), key == "q" || key == "\u{03}" {
                return
            }
        }
    }

    private func render(width: Int, height: Int) {
        let paths = SandboxPaths()
        let records = SandboxStore(paths: paths).list()
        let running = records.filter { $0.state == .running }

        var lines: [String] = []
        lines.append(
            bold(
                "sandbox  \(running.count) running, \(records.count) total"
                    .padding(toLength: max(0, width - 10), withPad: " ", startingAt: 0)
                    + "q quit"))
        lines.append("")

        if records.isEmpty {
            lines.append(dim("  no sandboxes — start one with: sandbox run shell"))
        } else {
            lines.append(bold("  NAME              STATE     IMAGE                     EGRESS"))
            for record in records.prefix(max(1, height / 3)) {
                let state = record.state == .running ? green("running") : dim("stopped")
                lines.append(
                    "  " + pad(record.name, 18)
                        + pad(state, 9, visible: record.state == .running ? 7 : 7)
                        + pad(ListCommand.shortImage(record.image), 26)
                        + ListCommand.summariseEgress(record.allow))
            }
        }

        lines.append("")
        lines.append(bold("  RECENT DECISIONS"))
        let recent = latestDecisions(paths: paths, sandboxes: records.map(\.name))
        if recent.isEmpty {
            lines.append(dim("  none yet"))
        } else {
            for (sandbox, record) in recent.suffix(decisions) {
                let verdict = record.allowed ? green("allow") : red("deny ")
                let name = (record.names?.first).map {
                    $0.hasSuffix(".") ? String($0.dropLast()) : $0
                }
                // A DNS decision has no address; the name is the whole story.
                let target =
                    record.proto == "dns"
                    ? (name ?? "(unknown)") : "\(record.address):\(record.port)"
                let suffix = record.proto == "dns" ? "" : (name.map { "  \($0)" } ?? "")
                lines.append(
                    "  " + pad(sandbox, 18) + verdict
                        + " \(target)  \(record.reason)\(suffix)")
            }
        }

        // Clear and repaint in one write, so the screen never shows a
        // half-drawn frame.
        var frame = "\u{1B}[H\u{1B}[2J"
        for line in lines.prefix(height - 1) {
            frame += line + "\r\n"
        }
        FileHandle.standardOutput.write(Data(frame.utf8))
    }

    /// Newest decisions across every sandbox, oldest first.
    private func latestDecisions(
        paths: SandboxPaths, sandboxes: [String]
    ) -> [(String, PolicyAuditRecord)] {
        let decoder = JSONDecoder()
        var all: [(String, PolicyAuditRecord)] = []
        for name in sandboxes {
            let log = paths.socketDirectory(name).appending(path: "policy.jsonl")
            guard let data = try? Data(contentsOf: log) else { continue }
            // Only the tail is ever shown, so parsing the whole file every tick
            // would be wasteful on a long-lived sandbox.
            let tail = data.suffix(64 * 1024)
            for line in tail.split(separator: UInt8(ascii: "\n")) {
                if let record = try? decoder.decode(PolicyAuditRecord.self, from: Data(line)) {
                    all.append((name, record))
                }
            }
        }
        return all.sorted { $0.1.time < $1.1.time }
    }

    /// Read one key, or nil if none arrived within the timeout.
    private func readKey(timeout: Double) -> Character? {
        var readable = fd_set()
        withUnsafeMutableBytes(of: &readable.fds_bits) { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
            let words = raw.bindMemory(to: Int32.self)
            words[Int(STDIN_FILENO) / 32] |= Int32(1) << (Int32(STDIN_FILENO) % 32)
        }
        var tv = timeval(
            tv_sec: Int(timeout),
            tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000))

        guard select(STDIN_FILENO + 1, &readable, nil, nil, &tv) > 0 else { return nil }
        var byte: UInt8 = 0
        guard read(STDIN_FILENO, &byte, 1) == 1 else { return nil }
        return Character(UnicodeScalar(byte))
    }

    // Padding is done on visible length, because escape codes are zero-width
    // and would otherwise throw the columns out.
    private func pad(_ text: String, _ width: Int, visible: Int? = nil) -> String {
        let length = visible ?? text.count
        let padding = max(0, width - length)
        return text + String(repeating: " ", count: padding)
    }

    private func bold(_ text: String) -> String { "\u{1B}[1m\(text)\u{1B}[0m" }
    private func dim(_ text: String) -> String { "\u{1B}[2m\(text)\u{1B}[0m" }
    private func green(_ text: String) -> String { "\u{1B}[32m\(text)\u{1B}[0m" }
    private func red(_ text: String) -> String { "\u{1B}[31m\(text)\u{1B}[0m" }
}
