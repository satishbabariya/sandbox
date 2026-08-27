import Foundation
import Testing

@testable import SandboxKit

/// Conformance against the vectors the Go enforcement engine also reads.
///
/// The Swift matcher here is advisory — it renders `sandbox policy check`. The
/// Go matcher in netstack/ is authoritative — it actually refuses the
/// connection. If the two disagree, the CLI tells users something different
/// from what the sandbox will do, which is the worst failure mode a security
/// tool has. Both suites read `testdata/host-patterns.json`, and
/// `make -C netstack check-vectors` proves the two copies are byte-identical.
struct Vectors: Decodable {
    struct Match: Decodable {
        let pattern: String
        let host: String
        let port: UInt16
        let expect: Bool
    }
    struct PolicyCase: Decodable {
        let host: String
        let port: UInt16
        let allowed: Bool
    }
    struct PolicySpec: Decodable {
        let name: String
        let allow: [String]
        let deny: [String]
        let cases: [PolicyCase]
    }
    let invalid: [String]
    let matches: [Match]
    let policies: [PolicySpec]
}

private func loadVectors() throws -> Vectors {
    // Tests/SandboxKitTests/ConformanceTests.swift -> package root
    let root = URL(filePath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let url = root.appending(path: "testdata/host-patterns.json")
    let data = try Data(contentsOf: url)
    return try JSONDecoder().decode(Vectors.self, from: data)
}

@Suite("Shared conformance vectors")
struct ConformanceTests {
    @Test("every invalid pattern is rejected")
    func invalidRejected() throws {
        for raw in try loadVectors().invalid {
            #expect(throws: PolicyError.self, "pattern \(raw.debugDescription) should be rejected") {
                try HostPattern(raw)
            }
        }
    }

    @Test("every match vector agrees with the enforcement engine")
    func matchesAgree() throws {
        for c in try loadVectors().matches {
            let p = try HostPattern(c.pattern)
            let got = p.matches(host: c.host, port: c.port)
            #expect(
                got == c.expect,
                "\(c.pattern) vs \(c.host):\(c.port) — got \(got), vectors say \(c.expect)"
            )
        }
    }

    @Test("every policy vector agrees with the enforcement engine")
    func policiesAgree() throws {
        for spec in try loadVectors().policies {
            let policy = try NetworkPolicy(allow: spec.allow, deny: spec.deny)
            for c in spec.cases {
                let got = policy.evaluate(host: c.host, port: c.port).isAllowed
                #expect(
                    got == c.allowed,
                    "\(spec.name): \(c.host):\(c.port) — got \(got), vectors say \(c.allowed)"
                )
            }
        }
    }
}

@Suite("NetworkPolicy merging")
struct MergeTests {
    @Test("merging unions both lists")
    func union() throws {
        let base = try NetworkPolicy(allow: ["*.anthropic.com"], deny: [])
        let extra = try NetworkPolicy(allow: ["pypi.org"], deny: ["evil.com"])
        let merged = base.merging(extra)

        #expect(merged.evaluate(host: "api.anthropic.com", port: 443).isAllowed)
        #expect(merged.evaluate(host: "pypi.org", port: 443).isAllowed)
        #expect(!merged.evaluate(host: "evil.com", port: 443).isAllowed)
    }

    @Test("a merge cannot weaken an existing deny")
    func mergeCannotWeakenDeny() throws {
        // Composing a profile with per-run flags must never let a broad allow
        // punch through a deny the base profile established.
        let base = try NetworkPolicy(allow: ["*.github.com"], deny: ["gist.github.com"])
        let permissive = try NetworkPolicy(allow: ["*.github.com", "gist.github.com"], deny: [])

        let merged = base.merging(permissive)
        #expect(!merged.evaluate(host: "gist.github.com", port: 443).isAllowed)
    }

    @Test("merging is duplicate-free")
    func dedupes() throws {
        let a = try NetworkPolicy(allow: ["*.anthropic.com"], deny: [])
        let merged = a.merging(a)
        #expect(merged.allow.count == 1)
    }
}
