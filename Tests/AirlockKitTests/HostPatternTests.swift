import Testing

@testable import AirlockKit

@Suite("HostPattern parsing")
struct HostPatternParsingTests {
    @Test("exact host")
    func exactHost() throws {
        let p = try HostPattern("api.anthropic.com")
        #expect(p.host == "api.anthropic.com")
        #expect(p.port == nil)
        #expect(p.isWildcard == false)
    }

    @Test("host with port")
    func hostWithPort() throws {
        let p = try HostPattern("registry.example.com:5000")
        #expect(p.host == "registry.example.com")
        #expect(p.port == 5000)
    }

    @Test("leading-label wildcard")
    func wildcard() throws {
        let p = try HostPattern("*.githubusercontent.com")
        #expect(p.isWildcard)
        #expect(p.host == "githubusercontent.com")
    }

    @Test("patterns are case-insensitive")
    func caseInsensitive() throws {
        let p = try HostPattern("API.Anthropic.COM")
        #expect(p.host == "api.anthropic.com")
    }

    @Test("rejects malformed patterns", arguments: [
        "",
        "*",
        "*.",
        "*example.com",       // wildcard must be its own label
        "a.*.example.com",    // wildcard only in leading position
        "example.com:0",
        "example.com:65536",
        "example.com:notaport",
        "http://example.com", // scheme is not part of a host pattern
        "example.com/path",
    ])
    func rejectsMalformed(_ raw: String) {
        #expect(throws: PolicyError.self) { try HostPattern(raw) }
    }
}

@Suite("HostPattern matching")
struct HostPatternMatchingTests {
    @Test("exact host matches only itself")
    func exactMatch() throws {
        let p = try HostPattern("api.anthropic.com")
        #expect(p.matches(host: "api.anthropic.com", port: 443))
        #expect(!p.matches(host: "evil.com", port: 443))
    }

    @Test("exact host with no port matches any port")
    func anyPort() throws {
        let p = try HostPattern("api.anthropic.com")
        #expect(p.matches(host: "api.anthropic.com", port: 443))
        #expect(p.matches(host: "api.anthropic.com", port: 8080))
    }

    @Test("port-qualified pattern matches only that port")
    func portQualified() throws {
        let p = try HostPattern("registry.example.com:5000")
        #expect(p.matches(host: "registry.example.com", port: 5000))
        #expect(!p.matches(host: "registry.example.com", port: 443))
    }

    @Test("matching is case-insensitive on the queried host")
    func matchCaseInsensitive() throws {
        let p = try HostPattern("api.anthropic.com")
        #expect(p.matches(host: "API.ANTHROPIC.COM", port: 443))
    }

    @Test("wildcard matches subdomains")
    func wildcardSubdomain() throws {
        let p = try HostPattern("*.githubusercontent.com")
        #expect(p.matches(host: "raw.githubusercontent.com", port: 443))
        #expect(p.matches(host: "objects.githubusercontent.com", port: 443))
    }

    @Test("wildcard matches the apex domain too")
    func wildcardApex() throws {
        // Docker's kit spec treats *.example.com as covering example.com.
        let p = try HostPattern("*.githubusercontent.com")
        #expect(p.matches(host: "githubusercontent.com", port: 443))
    }

    @Test("wildcard spans multiple labels")
    func wildcardMultiLabel() throws {
        let p = try HostPattern("*.example.com")
        #expect(p.matches(host: "a.b.c.example.com", port: 443))
    }

    @Test("wildcard does not match a suffix that is not a label boundary")
    func wildcardNoSuffixConfusion() throws {
        // The classic bug: "*.example.com" must NOT match "notexample.com"
        // or "evil-example.com".
        let p = try HostPattern("*.example.com")
        #expect(!p.matches(host: "notexample.com", port: 443))
        #expect(!p.matches(host: "evilexample.com", port: 443))
        #expect(!p.matches(host: "example.com.evil.net", port: 443))
    }

    @Test("trailing dot on the queried host is normalized")
    func trailingDot() throws {
        // A DNS name may arrive fully qualified with a root label.
        let p = try HostPattern("api.anthropic.com")
        #expect(p.matches(host: "api.anthropic.com.", port: 443))
    }
}
