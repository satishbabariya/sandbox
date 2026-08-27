import AirlockKit
import ArgumentParser
import Darwin
import Foundation

/// Checks the things that go wrong on a fresh machine.
///
/// airlock has several preconditions that each fail in a confusing way: an
/// unsigned binary dies at VM start with an opaque error, a missing kernel
/// fails late, and a gateway built for the wrong architecture fails later
/// still. This turns all of that into one list.
struct DoctorCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "doctor",
        abstract: "Check that airlock can actually run sandboxes here."
    )

    enum Status {
        case ok(String)
        case warn(String, fix: String)
        case fail(String, fix: String)
    }

    func run() async throws {
        let paths = AirlockPaths()
        var results: [(String, Status)] = []

        results.append(("architecture", checkArchitecture()))
        results.append(("macOS version", checkMacOSVersion()))
        results.append(("entitlement", checkEntitlement()))
        results.append(("guest kernel", checkKernel(paths)))
        results.append(("gateway binary", checkGateway()))
        results.append(("state directory", checkStateDirectory(paths)))
        results.append(("disk space", checkDiskSpace(paths)))
        results.append(("stray state", checkOrphans(paths)))

        var failures = 0
        var warnings = 0
        let width = results.map(\.0.count).max() ?? 0

        for (name, status) in results {
            let label = name.padding(toLength: width, withPad: " ", startingAt: 0)
            switch status {
            case .ok(let detail):
                print("  ok    \(label)  \(detail)")
            case .warn(let detail, let fix):
                warnings += 1
                print("  warn  \(label)  \(detail)")
                print("        \(String(repeating: " ", count: width))  fix: \(fix)")
            case .fail(let detail, let fix):
                failures += 1
                print("  FAIL  \(label)  \(detail)")
                print("        \(String(repeating: " ", count: width))  fix: \(fix)")
            }
        }

        print("")
        if failures > 0 {
            print("\(failures) problem(s) will stop sandboxes from starting.")
            throw ExitCode(1)
        }
        if warnings > 0 {
            print("ready, with \(warnings) warning(s).")
            return
        }
        print("ready.")
    }

    /// Crashes and kill -9 leave runtime directories behind, and nothing else
    /// removes them.
    private func checkOrphans(_ paths: AirlockPaths) -> Status {
        let orphans = PruneCommand.orphanedRuntimeDirectories(
            store: SandboxStore(paths: paths))
        // A directory is untidy; a process is a VM still holding memory, so it
        // is worth naming separately even though one command clears both.
        let strays = StrayProcess.all()
        // The ones that actually cost the user something: a rootfs left by a
        // run that was killed is hundreds of MB, and they accumulate silently.
        let abandoned = PruneCommand.abandonedStateDirectories(
            store: SandboxStore(paths: paths), paths: paths)

        if orphans.isEmpty, strays.isEmpty, abandoned.isEmpty { return .ok("none") }

        var parts: [String] = []
        if !orphans.isEmpty {
            parts.append(
                "\(orphans.count) orphaned runtime director\(orphans.count == 1 ? "y" : "ies")")
        }
        if !strays.isEmpty {
            let vms = strays.filter { $0.kind == .supervisor }.count
            parts.append(
                vms > 0
                    ? "\(strays.count) stray process\(strays.count == 1 ? "" : "es") "
                        + "(\(vms) still holding a VM)"
                    : "\(strays.count) stray process\(strays.count == 1 ? "" : "es")")
        }
        if !abandoned.isEmpty {
            let bytes = abandoned.reduce(Int64(0)) { $0 + PruneCommand.directorySize($1) }
            parts.append(
                "\(abandoned.count) abandoned director\(abandoned.count == 1 ? "y" : "ies") "
                    + "holding \(ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file))")
        }
        return .warn(parts.joined(separator: ", "), fix: "airlock prune")
    }

    private func checkArchitecture() -> Status {
        #if arch(arm64)
        return .ok("arm64")
        #else
        return .fail(
            "not Apple silicon",
            fix: "airlock uses Virtualization.framework, which is arm64-only here")
        #endif
    }

    private func checkMacOSVersion() -> Status {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let text = "\(version.majorVersion).\(version.minorVersion)"
        if version.majorVersion >= 26 {
            return .ok(text)
        }
        return .warn(
            "\(text); airlock targets macOS 26",
            fix: "older versions may work but are untested")
    }

    /// The failure this catches is the most confusing one: an unsigned binary
    /// builds and runs right up until the VM starts.
    private func checkEntitlement() -> Status {
        let executable = URL(filePath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        let process = Process()
        process.executableURL = URL(filePath: "/usr/bin/codesign")
        process.arguments = ["-d", "--entitlements", "-", executable.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        guard (try? process.run()) != nil else {
            return .warn("could not run codesign", fix: "install the Xcode command line tools")
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self)

        if text.contains("com.apple.security.virtualization") {
            return .ok("com.apple.security.virtualization present")
        }
        return .fail(
            "binary is not signed for virtualization",
            fix: "run 'make build' — a bare 'swift build' skips signing")
    }

    private func checkKernel(_ paths: AirlockPaths) -> Status {
        guard FileManager.default.isReadableFile(atPath: paths.kernel.path) else {
            // The binary can fetch it itself; 'make install-kernel' only works
            // from a source tree, which someone who installed a build has not
            // got.
            return .fail(
                "missing at \(paths.kernel.path)", fix: "run 'airlock kernel install'")
        }
        let size =
            (try? paths.kernel.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size > 1_000_000 else {
            return .fail(
                "at \(paths.kernel.path) but only \(size) bytes",
                fix: "delete it and run 'airlock kernel install'")
        }
        return .ok("\(size / 1_048_576) MiB")
    }

    private func checkGateway() -> Status {
        let binary = InstallLayout.gatewayBinary()
        guard FileManager.default.isExecutableFile(atPath: binary.path) else {
            return .fail("not found at \(binary.path)", fix: "run 'make -C netstack'")
        }
        let process = Process()
        process.executableURL = binary
        process.arguments = ["--help"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        guard (try? process.run()) != nil else {
            return .fail("cannot execute \(binary.path)", fix: "rebuild with 'make -C netstack'")
        }
        process.waitUntilExit()
        return .ok(binary.path)
    }

    private func checkStateDirectory(_ paths: AirlockPaths) -> Status {
        do {
            try FileManager.default.createDirectory(
                at: paths.root, withIntermediateDirectories: true)
        } catch {
            return .fail("cannot create \(paths.root.path)", fix: "check permissions")
        }
        return .ok(paths.root.path)
    }

    /// Agent environments are hundreds of megabytes each, and running out of
    /// space mid-install produces a confusing failure.
    private func checkDiskSpace(_ paths: AirlockPaths) -> Status {
        guard
            let values = try? paths.root.resourceValues(forKeys: [
                .volumeAvailableCapacityForImportantUsageKey
            ]),
            let available = values.volumeAvailableCapacityForImportantUsage
        else {
            return .warn("could not determine free space", fix: "")
        }
        let gib = Double(available) / 1_073_741_824
        if gib < 5 {
            return .fail(
                String(format: "%.1f GiB free", gib),
                fix: "agent environments need a few GiB; free some space")
        }
        if gib < 20 {
            return .warn(
                String(format: "%.1f GiB free", gib),
                fix: "each cached agent environment is a few hundred MiB")
        }
        return .ok(String(format: "%.0f GiB free", gib))
    }
}
