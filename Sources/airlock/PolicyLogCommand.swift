import AirlockKit
import ArgumentParser
import Darwin
import Foundation

/// Answers the question every user of this tool eventually has: why did that
/// not work?
///
/// A blocked connection inside a sandbox looks like a timeout, a DNS failure,
/// or a confusing TLS error. The reason is only visible here, so it needs to be
/// easy to reach rather than a flag you had to remember to pass beforehand.
struct PolicyLogCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "log",
        abstract: "Show why connections were allowed or refused.",
        discussion: """
            Every decision the gateway made, with the rule that decided it. A \
            refusal inside the sandbox surfaces as a timeout or a DNS failure; \
            the reason is here.

            Reasons:
              allow-rule          a rule permitted it
              deny-rule           a rule refused it
              no-allow-rule       nothing permitted it
              unresolved-address  an address our resolver never handed out
              sni-denied          the TLS server name is not permitted
            """
    )

    @Argument(help: "Sandbox name.")
    var name: String

    @Flag(name: .shortAndLong, help: "Keep watching for new decisions.")
    var follow: Bool = false

    @Flag(name: .shortAndLong, help: "Show only refusals.")
    var denied: Bool = false

    @Option(name: .long, help: "Show at most this many recent decisions.")
    var tail: Int = 200

    func run() async throws {
        let paths = AirlockPaths()
        // Deliberately not requiring the sandbox to still exist: the most
        // useful moment to ask why something was refused is right after it
        // exited because of it.
        let log = paths.socketDirectory(name).appending(path: "policy.jsonl")

        guard FileManager.default.fileExists(atPath: log.path) else {
            if (try? SandboxStore(paths: paths).load(name)) == nil {
                throw StoreError.notFound(name)
            }
            print("no decisions recorded for '\(name)' yet")
            return
        }

        if follow {
            // print() block-buffers when stdout is not a terminal, so piping
            // this into grep would show nothing until the buffer filled — which
            // for a slow trickle of decisions is indistinguishable from a hang.
            setvbuf(stdout, nil, _IOLBF, 0)
        }

        var offset = try render(log, from: 0, limit: tail)
        guard follow else { return }

        // Poll rather than watch: the file only grows, and a poll cannot miss
        // an append the way a coalesced filesystem event can.
        while true {
            try await Task.sleep(for: .milliseconds(400))
            offset = try render(log, from: offset, limit: nil)
        }
    }

    /// Print records from `offset`, returning the new end of file.
    private func render(_ log: URL, from offset: UInt64, limit: Int?) throws -> UInt64 {
        let handle = try FileHandle(forReadingFrom: log)
        defer { try? handle.close() }
        try handle.seek(toOffset: offset)
        let data = handle.readDataToEndOfFile()
        guard !data.isEmpty else { return offset }

        let decoder = JSONDecoder()
        var records = data.split(separator: UInt8(ascii: "\n")).compactMap {
            try? decoder.decode(PolicyAuditRecord.self, from: Data($0))
        }
        if denied {
            records = records.filter { !$0.allowed }
        }
        if let limit, records.count > limit {
            records = Array(records.suffix(limit))
        }
        for record in records {
            print(Self.format(record))
        }
        return offset + UInt64(data.count)
    }

    static func format(_ record: PolicyAuditRecord) -> String {
        let verdict = record.allowed ? "allow" : "deny "
        let time = String(record.time.prefix(19)).replacingOccurrences(of: "T", with: " ")
        let names = (record.names ?? []).map {
            $0.hasSuffix(".") ? String($0.dropLast()) : $0
        }

        // A DNS decision has no address by definition — the point is that no
        // name was resolved — so showing ":0" would read as a bug.
        let target: String
        if record.proto == "dns" {
            target = names.first ?? "(unknown)"
        } else {
            target = "\(record.address):\(record.port)"
        }

        var line = "\(time)  \(verdict) \(record.proto) \(target)  \(record.reason)"
        if let rule = record.rule, !rule.isEmpty {
            line += " '\(rule)'"
        }
        // For DNS the name is already the target; repeating it adds nothing.
        if record.proto != "dns", !names.isEmpty {
            line += "  [\(names.joined(separator: ", "))]"
        }
        return line
    }
}
