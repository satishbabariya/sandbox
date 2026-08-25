import Foundation
import Testing

@testable import AirlockKit

@Suite("SandboxStore")
struct SandboxStoreTests {
    private func tempStore() -> (SandboxStore, URL) {
        let dir = URL(filePath: NSTemporaryDirectory())
            .appending(path: "airlock-store-\(UInt32.random(in: 0..<0xFFFF_FFFF))")
        return (SandboxStore(directory: dir), dir)
    }

    @Test("round-trips a record")
    func roundTrip() throws {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        let record = SandboxRecord(
            name: "devbox", image: "alpine:3.20",
            allow: ["*.anthropic.com"], deny: ["evil.com"],
            workspace: "/tmp/work", privileged: true)
        try store.create(record)

        let loaded = try store.load("devbox")
        #expect(loaded.image == "alpine:3.20")
        #expect(loaded.allow == ["*.anthropic.com"])
        #expect(loaded.deny == ["evil.com"])
        #expect(loaded.workspace == "/tmp/work")
        #expect(loaded.privileged)
    }

    @Test("refuses to create a duplicate")
    func duplicate() throws {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        try store.create(SandboxRecord(name: "devbox", image: "alpine"))
        #expect(throws: StoreError.self) {
            try store.create(SandboxRecord(name: "devbox", image: "alpine"))
        }
    }

    @Test("reports a missing sandbox rather than returning a blank one")
    func missing() throws {
        let (store, _) = tempStore()
        #expect(throws: StoreError.self) { try store.load("nope") }
        #expect(throws: StoreError.self) { try store.remove("nope") }
    }

    @Test("a record whose supervisor is gone reads as stopped")
    func deadSupervisorIsStopped() throws {
        // Trusting the file would leave a crashed supervisor looking like a
        // running sandbox the user cannot actually reach.
        var record = SandboxRecord(name: "devbox", image: "alpine")
        record.supervisorPID = 999_999  // not a live pid
        #expect(record.state == .stopped)

        record.supervisorPID = ProcessInfo.processInfo.processIdentifier
        #expect(record.state == .running)

        record.supervisorPID = nil
        #expect(record.state == .stopped)
    }

    @Test("lists newest first")
    func listOrder() throws {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        let old = SandboxRecord(
            name: "older", image: "alpine", createdAt: Date().addingTimeInterval(-3600))
        let new = SandboxRecord(name: "newer", image: "alpine", createdAt: Date())
        try store.create(old)
        try store.create(new)

        #expect(store.list().map(\.name) == ["newer", "older"])
    }

    @Test(
        "rejects names that would escape the state directory",
        arguments: [
            "", "../evil", "with/slash", "UPPER", "has space", "sym$link",
            String(repeating: "x", count: 65),
        ])
    func rejectsBadNames(_ name: String) {
        // Names become file paths and socket paths, so they are validated
        // rather than sanitised — a silently rewritten name is a confusing one.
        #expect(throws: StoreError.self) { try SandboxStore.validate(name: name) }
    }

    @Test("accepts ordinary names", arguments: ["devbox", "my-agent_2", "a"])
    func acceptsGoodNames(_ name: String) throws {
        try SandboxStore.validate(name: name)
    }
}

@Suite("Control protocol")
struct ControlProtocolTests {
    @Test("requests round-trip through the codec")
    func requestRoundTrip() throws {
        let request = ControlRequest.exec(
            command: ["/bin/sh", "-c", "echo hi"],
            environment: ["FOO": "bar"],
            workingDirectory: "/workspace")
        let encoded = try ControlCodec.encode(request)
        #expect(encoded.last == UInt8(ascii: "\n"), "frames must be newline-terminated")

        let decoded = try ControlCodec.decode(
            ControlRequest.self, from: encoded.dropLast())
        #expect(decoded == request)
    }

    @Test("output frames survive arbitrary bytes")
    func outputRoundTrip() throws {
        // Guest output is arbitrary binary, including newlines, which would
        // otherwise break the line framing — hence base64.
        let raw = Data([0x00, 0x0A, 0xFF, 0x0D] + Array("hello\nworld".utf8))
        let response = ControlResponse.output(
            stream: .stdout, base64: raw.base64EncodedString())
        let encoded = try ControlCodec.encode(response)

        #expect(encoded.filter { $0 == UInt8(ascii: "\n") }.count == 1)

        let decoded = try ControlCodec.decode(
            ControlResponse.self, from: encoded.dropLast())
        guard case .output(let stream, let base64) = decoded else {
            Issue.record("wrong case: \(decoded)")
            return
        }
        #expect(stream == .stdout)
        #expect(Data(base64Encoded: base64) == raw)
    }

    @Test("LineReader splits a stream into frames")
    func lineReader() throws {
        let path = "/tmp/al-lines-\(UInt32.random(in: 0..<0xFFFF)).txt"
        defer { try? FileManager.default.removeItem(atPath: path) }
        // Deliberately no trailing newline on the last line.
        try "one\ntwo\nthree".write(toFile: path, atomically: true, encoding: .utf8)

        let fd = open(path, O_RDONLY)
        defer { close(fd) }
        var reader = LineReader(fd: fd)

        var lines: [String] = []
        while let line = reader.next() {
            lines.append(String(decoding: line, as: UTF8.self))
        }
        #expect(lines == ["one", "two", "three"])
    }
}

@Suite("LaunchSpec")
struct LaunchSpecTests {
    @Test("carries policy across the process boundary")
    func policySurvives() throws {
        let launch = LaunchSpec(
            name: "devbox", image: "alpine:3.20",
            allow: ["*.anthropic.com"], deny: ["gist.github.com"])
        let data = try JSONEncoder().encode(launch)
        let decoded = try JSONDecoder().decode(LaunchSpec.self, from: data)
        #expect(decoded == launch)

        // The supervisor rebuilds the policy from this, so a spec that lost a
        // deny rule would silently widen egress.
        let spec = try decoded.sandboxSpec()
        #expect(!spec.policy.evaluate(host: "gist.github.com", port: 443).isAllowed)
        #expect(spec.policy.evaluate(host: "api.anthropic.com", port: 443).isAllowed)
    }

    @Test("an invalid pattern fails before a sandbox is started")
    func invalidPatternRejected() throws {
        let launch = LaunchSpec(name: "devbox", image: "alpine", allow: ["*bad.com"])
        #expect(throws: PolicyError.self) { try launch.sandboxSpec() }
    }
}
