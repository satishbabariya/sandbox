import ArgumentParser
import Foundation
import SandboxKit

struct KernelCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "kernel",
        abstract: "Manage the Linux kernel sandboxes boot.",
        subcommands: [KernelInstall.self, KernelShow.self]
    )
}

struct KernelInstall: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "install",
        abstract: "Download a guest kernel into ~/.sandbox.",
        discussion: """
            Every sandbox is a VM, so a Linux kernel is required. This fetches \
            the Kata Containers kernel, which is prebuilt for arm64 and is what \
            Apple's own containerization test suite uses.

            Pass --kernel to install one you built yourself instead.
            """
    )

    /// Pinned rather than "latest": the kernel decides what works inside every
    /// sandbox, so it should not change under a user without them asking.
    static let kataVersion = "3.17.0"
    static let kernelInArchive = "vmlinux-6.12.28-153"

    @Option(name: .long, help: "Install this local kernel image instead of downloading one.")
    var kernel: String?

    @Flag(name: .long, help: "Replace an existing kernel.")
    var force: Bool = false

    func run() async throws {
        let paths = SandboxPaths()
        try FileManager.default.createDirectory(
            at: paths.root, withIntermediateDirectories: true)

        if FileManager.default.fileExists(atPath: paths.kernel.path), !force {
            print("kernel already at \(paths.kernel.path); pass --force to replace it")
            return
        }

        if let kernel {
            let source = URL(filePath: kernel).standardizedFileURL
            guard FileManager.default.isReadableFile(atPath: source.path) else {
                throw CleanExit.message("cannot read \(source.path)")
            }
            try? FileManager.default.removeItem(at: paths.kernel)
            try FileManager.default.copyItem(at: source, to: paths.kernel)
            print("installed \(source.lastPathComponent) to \(paths.kernel.path)")
            return
        }

        let address =
            "https://github.com/kata-containers/kata-containers/releases/download/"
            + "\(Self.kataVersion)/kata-static-\(Self.kataVersion)-arm64.tar.xz"
        guard let url = URL(string: address) else {
            throw CleanExit.message("could not build the download URL: \(address)")
        }

        let scratch = paths.root.appending(path: "download")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: scratch) }

        let archive = scratch.appending(path: "kata.tar.xz")
        print("downloading kata \(Self.kataVersion) kernel (about 280 MiB)...")
        try await download(url, to: archive)

        print("extracting...")
        let member = "./opt/kata/share/kata-containers/\(Self.kernelInArchive)"
        try run("/usr/bin/tar", ["-xJf", archive.path, "-C", scratch.path, member])

        let extracted = scratch.appending(path: member)
        guard FileManager.default.isReadableFile(atPath: extracted.path) else {
            throw CleanExit.message("archive did not contain \(member)")
        }
        try? FileManager.default.removeItem(at: paths.kernel)
        try FileManager.default.moveItem(at: extracted, to: paths.kernel)

        let size =
            (try? paths.kernel.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        print("installed \(size / 1_048_576) MiB kernel to \(paths.kernel.path)")
        print("check everything with: sandbox doctor")
    }

    private func download(_ url: URL, to destination: URL) async throws {
        let (temporary, response) = try await URLSession.shared.download(from: url)
        if let http = response as? HTTPURLResponse, http.statusCode != 200 {
            throw CleanExit.message("download failed: HTTP \(http.statusCode) from \(url)")
        }
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.moveItem(at: temporary, to: destination)
    }

    private func run(_ executable: String, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(filePath: executable)
        process.arguments = arguments
        let errors = Pipe()
        process.standardError = errors
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let detail = String(
                decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            throw CleanExit.message(
                "\(executable) failed with status \(process.terminationStatus): \(detail)")
        }
    }
}

struct KernelShow: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "show",
        abstract: "Report which kernel is installed."
    )

    func run() async throws {
        let paths = SandboxPaths()
        guard FileManager.default.isReadableFile(atPath: paths.kernel.path) else {
            print("no kernel installed; run: sandbox kernel install")
            throw ExitCode(1)
        }
        let size = (try? paths.kernel.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        print("\(paths.kernel.path)  \(size / 1_048_576) MiB")
    }
}
