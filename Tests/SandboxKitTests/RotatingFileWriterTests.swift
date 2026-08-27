import Foundation
import Testing

@testable import SandboxKit

/// A detached sandbox has no terminal, so everything the guest prints lands in
/// a file on the host, and the guest decides how much that is. Measured at
/// 635 MB/s from a shell loop -- fast enough to fill a disk in minutes, and it
/// does not take a compromised agent: a program stuck printing in a retry loop
/// does it by accident.
@Suite("rotating file writer")
struct RotatingFileWriterTests {
    private func temporaryPath() -> URL {
        FileManager.default.temporaryDirectory
            .appending(path: "sandbox-rotate-\(UUID().uuidString).log")
    }

    private func size(_ url: URL) -> Int64 {
        (try? FileManager.default.attributesOfItem(atPath: url.path)[.size])
            .flatMap { $0 as? Int64 } ?? 0
    }

    @Test("output below the limit is written untouched")
    func belowLimit() throws {
        let path = temporaryPath()
        let writer = try RotatingFileWriter(path: path, limit: 1024)
        defer { try? FileManager.default.removeItem(at: path) }

        try writer.write(Data("hello".utf8))
        try writer.close()

        #expect(try String(contentsOf: path, encoding: .utf8) == "hello")
        #expect(!FileManager.default.fileExists(atPath: writer.rotatedPath.path))
    }

    /// The point of the exercise: however much a guest prints, the total stops
    /// growing.
    @Test("a flood is bounded at twice the limit")
    func floodIsBounded() throws {
        let path = temporaryPath()
        let limit: Int64 = 4096
        let writer = try RotatingFileWriter(path: path, limit: limit)
        defer {
            try? FileManager.default.removeItem(at: path)
            try? FileManager.default.removeItem(at: writer.rotatedPath)
        }

        let chunk = Data(repeating: UInt8(ascii: "x"), count: 512)
        for _ in 0..<200 {  // 100KB, far past the limit
            try writer.write(chunk)
        }
        try writer.close()

        let total = size(path) + size(writer.rotatedPath)
        #expect(total <= limit * 2, "held \(total) bytes against a limit of \(limit)")
    }

    /// Rotating rather than refusing to write: what a user wants after a flood
    /// is what happened most recently, not the first 32MB of it.
    @Test("the newest output is the output that is kept")
    func newestIsKept() throws {
        let path = temporaryPath()
        let writer = try RotatingFileWriter(path: path, limit: 64)
        defer {
            try? FileManager.default.removeItem(at: path)
            try? FileManager.default.removeItem(at: writer.rotatedPath)
        }

        try writer.write(Data(repeating: UInt8(ascii: "o"), count: 64))  // forces a rotation
        try writer.write(Data("NEWEST".utf8))
        try writer.close()

        let current = try String(contentsOf: path, encoding: .utf8)
        #expect(current.contains("NEWEST"))
        #expect(!current.contains("oooo"))
    }

    /// One generation, not a growing pile of them.
    @Test("only one generation is kept")
    func oneGeneration() throws {
        let path = temporaryPath()
        let writer = try RotatingFileWriter(path: path, limit: 32)
        defer {
            try? FileManager.default.removeItem(at: path)
            try? FileManager.default.removeItem(at: writer.rotatedPath)
        }

        for _ in 0..<10 {
            try writer.write(Data(repeating: UInt8(ascii: "x"), count: 32))
        }
        try writer.close()

        let directory = path.deletingLastPathComponent()
        let siblings = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        let mine = siblings.filter { $0.hasPrefix(path.lastPathComponent) }
        #expect(mine.count == 2, "expected the log and one generation back, got \(mine)")
    }
}
