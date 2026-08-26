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

@Suite("Host keychain credentials")
struct HostKeychainTests {
    private let sample: [String: Any] = [
        "claudeAiOauth": [
            "accessToken": "tok-abc123",
            "expiresAt": 4_102_444_800_000,  // year 2100, in milliseconds
            "scopes": ["a", "b"],
        ]
    ]

    @Test("walks a nested path to the token")
    func findsNestedToken() throws {
        let value = HostKeychainSource.string(
            at: ["claudeAiOauth", "accessToken"], in: sample)
        #expect(value == "tok-abc123")
    }

    @Test("a path that does not resolve returns nil rather than guessing")
    func missingPathIsNil() throws {
        #expect(HostKeychainSource.string(at: ["nope"], in: sample) == nil)
        #expect(HostKeychainSource.string(at: ["claudeAiOauth", "nope"], in: sample) == nil)
        // A path that lands on a non-string must not be coerced.
        #expect(HostKeychainSource.string(at: ["claudeAiOauth", "scopes"], in: sample) == nil)
    }

    @Test("reads a numeric expiry")
    func readsExpiry() throws {
        let value = HostKeychainSource.number(at: ["claudeAiOauth", "expiresAt"], in: sample)
        #expect(value == 4_102_444_800_000)
    }

    @Test("milliseconds and seconds are both understood")
    func expiryUnits() throws {
        // Apps differ, and reading milliseconds as seconds would place the
        // expiry ~50,000 years out and never flag a dead token.
        let millis = 4_102_444_800_000.0
        let seconds = 4_102_444_800.0
        let fromMillis = Date(
            timeIntervalSince1970: millis > 32_503_680_000 ? millis / 1000 : millis)
        let fromSeconds = Date(
            timeIntervalSince1970: seconds > 32_503_680_000 ? seconds / 1000 : seconds)
        #expect(abs(fromMillis.timeIntervalSince(fromSeconds)) < 1)
    }

    @Test("claude has an OAuth preset bound to one domain")
    func claudePreset() throws {
        let preset = CredentialBinding.oauthPreset(for: "claude")
        #expect(preset != nil)
        #expect(preset?.0.domain == "api.anthropic.com")
        #expect(preset?.0.format == "Bearer {}")
        // A token must not be sendable anywhere else.
        #expect(preset?.1.service == "Claude Code-credentials")
    }

    @Test("an unknown service has no OAuth preset")
    func unknownHasNoPreset() throws {
        #expect(CredentialBinding.oauthPreset(for: "nonsense") == nil)
    }
}

@Suite("Docker kit import")
struct KitTests {
    private func spec(_ yaml: String) throws -> KitSpec {
        let path = URL(filePath: NSTemporaryDirectory())
            .appending(path: "kit-\(UInt32.random(in: 0..<0xFFFF_FFFF)).yaml")
        defer { try? FileManager.default.removeItem(at: path) }
        try yaml.write(to: path, atomically: true, encoding: .utf8)
        return try KitSpec.load(from: path)
    }

    @Test("translates the shape a real kit uses")
    func translatesRealShape() throws {
        let parsed = try spec(
            """
            schemaVersion: "2"
            kind: sandbox
            name: demo
            displayName: Demo Agent
            sandbox:
              image: docker/sandbox-templates:shell
              entrypoint:
                - /usr/bin/demo
              command:
                default: ["--flag"]
            permissions:
              network:
                allow:
                  - api.example.com
                  - "*.example.org"
            environment:
              variables:
                DEMO_MODE: "on"
            setup:
              install:
                - command: install-demo
                  user: "1000"
            """)
        let result = try KitTranslator.translate(parsed)

        #expect(result.profile.name == "demo")
        #expect(result.profile.displayName == "Demo Agent")
        #expect(result.profile.image == "docker/sandbox-templates:shell")
        // entrypoint and the default command concatenate.
        #expect(result.profile.command == ["/usr/bin/demo", "--flag"])
        #expect(result.profile.allow == ["api.example.com", "*.example.org"])
        #expect(result.profile.environment["DEMO_MODE"] == "on")
        #expect(result.profile.install == ["install-demo"])
    }

    @Test("a deny rule is reported, never silently dropped")
    func denyIsReported() throws {
        // A profile carries no deny list. Dropping one quietly would produce a
        // sandbox weaker than the kit author described.
        let parsed = try spec(
            """
            name: demo
            kind: sandbox
            sandbox:
              image: alpine
            permissions:
              network:
                allow: ["a.example.com"]
                deny: ["blocked.example.com"]
            """)
        let result = try KitTranslator.translate(parsed)
        #expect(result.notes.contains { $0.contains("blocked.example.com") })
    }

    @Test("startup commands are reported as unsupported")
    func startupIsReported() throws {
        let parsed = try spec(
            """
            name: demo
            kind: sandbox
            sandbox:
              image: alpine
            setup:
              startup:
                - command: ["do", "a thing"]
                  background: true
            """)
        let result = try KitTranslator.translate(parsed)
        #expect(result.unsupported.contains { $0.contains("setup.startup") })
    }

    @Test("argv install steps survive quoting")
    func argvQuoting() throws {
        let parsed = try spec(
            """
            name: demo
            kind: sandbox
            sandbox:
              image: alpine
            setup:
              install:
                - command: ["sh", "-c", "echo hello world"]
            """)
        let result = try KitTranslator.translate(parsed)
        // Losing the quoting would turn one argument into three.
        #expect(result.profile.install == ["sh -c 'echo hello world'"])
    }

    @Test("a mixin is refused rather than half-imported")
    func mixinRefused() throws {
        let parsed = try spec(
            """
            name: some-mixin
            kind: mixin
            """)
        #expect(throws: KitError.self) { try KitTranslator.translate(parsed) }
    }

    @Test("a kit with no image is refused")
    func missingImageRefused() throws {
        let parsed = try spec(
            """
            name: demo
            kind: sandbox
            """)
        #expect(throws: KitError.self) { try KitTranslator.translate(parsed) }
    }

    @Test("an OAuth credential is reported with its endpoint")
    func oauthReported() throws {
        // Real kits write tokenEndpoint as a mapping, not a string.
        let parsed = try spec(
            """
            name: demo
            kind: sandbox
            sandbox:
              image: alpine
            credentials:
              - service: something
                oauth:
                  tokenEndpoint:
                    host: api.example.com
                    path: /token
            """)
        let result = try KitTranslator.translate(parsed)
        #expect(result.unsupported.contains { $0.contains("api.example.com/token") })
    }
}

@Suite("Credential coverage")
struct CredentialCoverageTests {
    @Test("bindings for the same domain are alternatives, not requirements")
    func sameDomainAlternatives() throws {
        // The claude profile carries both an API key and an OAuth binding for
        // api.anthropic.com. Warning about the unset one when the other
        // resolved reads as a problem when nothing is wrong.
        let bindings = [
            CredentialBinding(
                service: "anthropic", domain: "api.anthropic.com", header: "x-api-key"),
            CredentialBinding(
                service: "claude", domain: "api.anthropic.com",
                header: "authorization", format: "Bearer {}"),
        ]
        let covered = Set(["api.anthropic.com"])
        let stillMissing = ["anthropic"].filter { service in
            guard let domain = bindings.first(where: { $0.service == service })?.domain
            else { return true }
            return !covered.contains(domain)
        }
        #expect(stillMissing.isEmpty)
    }

    @Test("an uncovered domain is still reported")
    func uncoveredStillReported() throws {
        let bindings = [
            CredentialBinding(
                service: "github", domain: "api.github.com",
                header: "authorization", format: "Bearer {}")
        ]
        let covered = Set(["api.anthropic.com"])
        let stillMissing = ["github"].filter { service in
            guard let domain = bindings.first(where: { $0.service == service })?.domain
            else { return true }
            return !covered.contains(domain)
        }
        #expect(stillMissing == ["github"])
    }
}
