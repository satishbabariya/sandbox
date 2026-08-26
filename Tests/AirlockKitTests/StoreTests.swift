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

@Suite("PortForward")
struct PortForwardTests {
    @Test("a bare port publishes on the same host port")
    func barePort() throws {
        let forward = try PortForward.parse("8080")
        #expect(forward.hostPort == 8080)
        #expect(forward.guestPort == 8080)
        #expect(forward.hostAddress == "127.0.0.1")
    }

    @Test("host:guest maps across")
    func hostToGuest() throws {
        let forward = try PortForward.parse("3000:8080")
        #expect(forward.hostPort == 3000)
        #expect(forward.guestPort == 8080)
    }

    @Test("an explicit interface is honoured")
    func explicitInterface() throws {
        let forward = try PortForward.parse("0.0.0.0:3000:8080")
        #expect(forward.hostAddress == "0.0.0.0")
        #expect(forward.hostPort == 3000)
        #expect(forward.guestPort == 8080)
    }

    @Test("defaults to loopback")
    func defaultsToLoopback() throws {
        // A published port should not become reachable from the local network
        // unless the user asks for that explicitly.
        #expect(try PortForward.parse("9000").hostAddress == "127.0.0.1")
        #expect(try PortForward.parse("9000:80").hostAddress == "127.0.0.1")
    }

    @Test(
        "rejects a privileged host port before anything boots",
        arguments: ["80", "443:8080", "0.0.0.0:22:2222"])
    func rejectsPrivileged(_ spec: String) {
        // airlock does not run as root, so the gateway could not bind these.
        // Failing here beats failing after the VM has started.
        #expect(throws: PortForwardError.self) { try PortForward.parse(spec) }
    }

    @Test("a privileged guest port is fine")
    func guestPrivilegedIsFine() throws {
        // Only the host side needs the privilege; inside the sandbox the
        // process is root and may bind 80 freely.
        let forward = try PortForward.parse("8080:80")
        #expect(forward.guestPort == 80)
    }

    @Test("rejects malformed specs", arguments: ["", "abc", "1:2:3:4", "8080:0", "8080:99999"])
    func rejectsMalformed(_ spec: String) {
        #expect(throws: (any Error).self) { try PortForward.parse(spec) }
    }
}

@Suite("AirlockConfig")
struct AirlockConfigTests {
    private func tempPaths() -> AirlockPaths {
        AirlockPaths(
            root: URL(filePath: NSTemporaryDirectory())
                .appending(path: "airlock-config-\(UInt32.random(in: 0..<0xFFFF_FFFF))"))
    }

    @Test("absent config yields defaults rather than failing")
    func absentIsFine() throws {
        let config = try AirlockConfig.load(tempPaths())
        #expect(config.defaultAgent == nil)
        #expect(config.allow.isEmpty)
        #expect(config.deny.isEmpty)
    }

    @Test("round-trips")
    func roundTrip() throws {
        let paths = tempPaths()
        defer { try? FileManager.default.removeItem(at: paths.root) }

        let config = AirlockConfig(
            defaultAgent: "claude", cpus: 8, memory: "8g",
            allow: ["*.internal.corp"], deny: ["evil.com"], clone: true,
            secrets: ["anthropic"])
        try config.save(paths)

        #expect(try AirlockConfig.load(paths) == config)
    }

    @Test("a malformed config is an error, never silently ignored")
    func malformedIsLoud() throws {
        let paths = tempPaths()
        defer { try? FileManager.default.removeItem(at: paths.root) }
        try FileManager.default.createDirectory(
            at: paths.root, withIntermediateDirectories: true)
        try "{ not json".write(
            to: AirlockConfig.path(paths), atomically: true, encoding: .utf8)

        // Falling back to defaults here could silently drop a deny rule the
        // user believes is in force.
        #expect(throws: ConfigError.self) { try AirlockConfig.load(paths) }
    }

    @Test("rejects a bad pattern before it is written")
    func validatesPatterns() throws {
        let config = AirlockConfig(allow: ["*bad.com"])
        #expect(throws: PolicyError.self) { try config.validate() }
    }

    @Test("rejects a nonsensical cpu count")
    func validatesCPUs() throws {
        #expect(throws: ConfigError.self) { try AirlockConfig(cpus: 0).validate() }
    }
}

@Suite("MCP")
struct MCPTests {
    @Test("renders the shape agents expect")
    func rendersConfig() throws {
        let servers = [
            MCPServer(name: "git", command: "npx", args: ["-y", "server-git"]),
            MCPServer(
                name: "github", command: "npx", args: ["-y", "server-github"],
                env: ["TOKEN": "sentinel"]),
        ]
        let json = try MCPConfiguration.render(servers)
        let parsed =
            try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        let entries = parsed?["mcpServers"] as? [String: Any]

        #expect(entries?.count == 2)
        let git = entries?["git"] as? [String: Any]
        #expect(git?["command"] as? String == "npx")
        #expect(git?["args"] as? [String] == ["-y", "server-git"])
        // A server with no env should not carry an empty object.
        #expect(git?["env"] == nil)

        let github = entries?["github"] as? [String: Any]
        #expect((github?["env"] as? [String: String])?["TOKEN"] == "sentinel")
    }

    @Test("slashes stay readable")
    func noEscapedSlashes() throws {
        let json = try MCPConfiguration.render([
            MCPServer(name: "fs", command: "npx", args: ["@scope/package"])
        ])
        #expect(!json.contains("\\/"), "package names should not be slash-escaped")
        #expect(json.hasSuffix("\n"), "config files end with a newline")
    }

    @Test("a server's egress becomes the sandbox's egress")
    func egressIsMerged() throws {
        // A server running inside the sandbox must not be able to reach
        // anywhere the agent could not, so its rules join the same policy.
        let profile = AgentProfile(
            name: "test", displayName: "Test", image: "alpine",
            allow: ["api.example.com"],
            mcp: [MCPServer(name: "github", command: "npx", allow: ["api.github.com"])])

        #expect(profile.allEgress.contains("api.example.com"))
        #expect(profile.allEgress.contains("api.github.com"))
    }

    @Test("MCP install steps run after the agent's own")
    func installOrder() throws {
        let profile = AgentProfile(
            name: "test", displayName: "Test", image: "alpine",
            install: ["install-agent"],
            mcp: [MCPServer(name: "s", command: "npx", install: ["install-server"])])

        // The server is installed with the agent's toolchain already present.
        #expect(profile.allInstall == ["install-agent", "install-server"])
    }

    @Test("adding a server changes the cache key")
    func cacheKeyCoversMCP() throws {
        // Otherwise adding an MCP server would silently reuse an environment
        // that does not contain it.
        let base = AgentProfile(
            name: "test", displayName: "Test", image: "alpine", install: ["a"])
        var withServer = base
        withServer.mcp = [MCPServer(name: "s", command: "npx", install: ["b"])]

        #expect(RootfsCache.key(for: base) != RootfsCache.key(for: withServer))
    }

    @Test("presets exist for the common servers", arguments: ["filesystem", "git", "github", "fetch"])
    func presetsResolve(_ name: String) throws {
        #expect(MCPServer.preset(for: name) != nil)
    }
}
