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
    private let paths: SandboxPaths
    private let cache: RootfsCache
    private let logger: Logger?

    public init(paths: SandboxPaths = SandboxPaths(), logger: Logger? = nil) {
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
        guard !profile.allInstall.isEmpty else {
            // Nothing to install: the image is already the environment, so
            // there is nothing worth caching.
            onProgress(.ready)
            return cached
        }

        let buildID = "build-\(profile.name)-\(UInt32.random(in: 0..<0xFFFF))"
        let reference = ImageReference.normalised(profile.image)
        onProgress(.pulling(reference))

        // Install steps need the agent's own egress, and its package
        // registries, but nothing beyond that.
        let policy = try NetworkPolicy(
            allow: profile.allEgress + AgentProfile.commonToolingEgress
                + ["deb.debian.org", "security.debian.org", "*.debian.org"],
            deny: []
        )

        let steps = profile.allInstall
        let script = Self.installScript(for: steps)

        let spec = SandboxSpec(
            id: buildID,
            image: reference,
            command: ["/bin/sh", "-lc", script],
            policy: policy,
            cpus: 4,
            memoryInBytes: 4 * 1024 * 1024 * 1024,
            runAsRoot: true
        )

        let sandbox = Sandbox(spec: spec, paths: paths, logger: logger)
        for (index, command) in steps.enumerated() {
            onProgress(.installing(step: index + 1, of: steps.count, command: command))
        }

        // Building an agent runs a VM for as long as its install steps take,
        // which is minutes. Until this was armed, Ctrl-C during that did
        // nothing at all -- the run ignored SIGINT, and a SIGTERM that did
        // land left the build's gateway running with no sandbox to serve.
        let buildDirectories = paths.allDirectories(buildID)
        // Stopping the sandbox makes wait() return a failed status, so without
        // knowing an interrupt caused it the build reports itself as a failed
        // install and exits 1 -- and which of the two happens first is a race,
        // so the exit code differed between runs of the same interrupt.
        let wasInterrupted = InterruptFlag()
        let interrupted = SignalTrap {
            wasInterrupted.set()
            Task {
                await sandbox.stop()
                // exit() does not unwind, so the defer below that removes the
                // half-built rootfs never runs. Left alone, every interrupted
                // build keeps a few hundred MB of a rootfs nobody will finish.
                // Removal races whatever the interrupt caught mid-write --
                // an image unpack recreates the path right after a single
                // remove, which is how an interrupted build was once found
                // still holding its half-built rootfs. Removing again after a
                // pause wins against a writer that is itself shutting down.
                for attempt in 1...3 {
                    for directory in buildDirectories {
                        try? FileManager.default.removeItem(at: directory)
                    }
                    if buildDirectories.allSatisfy({
                        !FileManager.default.fileExists(atPath: $0.path)
                    }) {
                        break
                    }
                    if attempt < 3 { try? await Task.sleep(for: .milliseconds(400)) }
                }
                Darwin.exit(130)  // 128 + SIGINT, what a shell reports for Ctrl-C.
            }
        }
        interrupted.arm()
        defer { interrupted.disarm() }

        try await sandbox.start(gatewayBinary: gatewayBinary)
        let status = try await sandbox.wait()
        await sandbox.stop()

        // Whichever path gets here first, an interrupted build exits the way an
        // interrupted command does rather than as a broken one.
        if wasInterrupted.isSet {
            for directory in buildDirectories {
                try? FileManager.default.removeItem(at: directory)
            }
            Darwin.exit(130)
        }

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

extension AgentPreparer {
    /// Assemble the install steps into one script.
    ///
    /// Each step is handed to the shell as a file rather than spliced into a
    /// larger script. Kit install steps are multi-line programs with `case`
    /// blocks, command substitutions and quoting of their own: appending
    /// `|| { ... }` to one only guards its last line, and interpolating it into
    /// an echo to report progress truncated `$(dpkg --print-architecture)` into
    /// an unterminated `$(` that failed to parse before anything ran.
    ///
    /// They are also bash programs -- `set -euo pipefail` is the near-universal
    /// opening line -- so bash runs them where the image has it.
    public static func installScript(for steps: [String]) -> String {
        var lines = [
            "set -e",
            // Kits are written against bash; dash is a fallback for images
            // that ship nothing else.
            "RUNNER=sh",
            "command -v bash >/dev/null 2>&1 && RUNNER=bash",
        ]
        for (index, command) in steps.enumerated() {
            let label = Sandbox.shellQuote("[\(index + 1)/\(steps.count)] \(summary(of: command))")
            let encoded = Sandbox.shellQuote(Data(command.utf8).base64EncodedString())
            lines.append("printf 'sandbox: %s\\n' \(label)")
            lines.append("printf %s \(encoded) | base64 -d > /tmp/sandbox-install-step")
            lines.append(
                "\"$RUNNER\" /tmp/sandbox-install-step "
                    + "|| { printf 'sandbox: install step %s failed\\n' \(label) >&2; exit 1; }")
        }
        return lines.joined(separator: "\n")
    }

    /// A one-line description of a step, for progress output.
    ///
    /// Comments and `set -e` lines are what most kit steps open with and say
    /// nothing about what the step does, so the first line that looks like work
    /// is used instead.
    public static func summary(of command: String) -> String {
        let interesting = command.split(separator: "\n").map {
            $0.trimmingCharacters(in: .whitespaces)
        }.first {
            !$0.isEmpty && !$0.hasPrefix("#") && !$0.hasPrefix("set ")
        }
        let line = interesting ?? command.trimmingCharacters(in: .whitespacesAndNewlines)
        return line.count > 60 ? String(line.prefix(59)) + "\u{2026}" : line
    }
}
