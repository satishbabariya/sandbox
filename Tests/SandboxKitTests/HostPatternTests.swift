import Testing

@testable import SandboxKit

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

    @Test(
        "rejects malformed patterns",
        arguments: [
            "",
            "*",
            "*.",
            "*example.com",  // wildcard must be its own label
            "a.*.example.com",  // wildcard only in leading position
            "example.com:0",
            "example.com:65536",
            "example.com:notaport",
            "http://example.com",  // scheme is not part of a host pattern
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

/// A pattern that parses and then matches nothing is the worst outcome for a
/// tool whose job is deciding what is reachable: the sandbox reaches neither
/// what you asked for nor anything else, and says nothing about why.
@Suite("HostPattern rejects the unmatchable")
struct HostPatternUnmatchableTests {
    /// The mistake a user actually makes. Before this was rejected,
    /// `--allow "example.com, github.com"` reached neither host in silence.
    @Test("a comma-separated list is refused, not accepted as one host")
    func commaSeparatedList() {
        #expect(throws: PolicyError.self) { try HostPattern("example.com, github.com") }
    }

    @Test("characters that cannot appear in a hostname are refused")
    func invalidCharacters() throws {
        for raw in ["exa mple.com", "exam,ple.com", "under_score.com", "ex!ample.com"] {
            #expect(throws: PolicyError.self, "should reject \(raw)") {
                try HostPattern(raw)
            }
        }
        // The message has to name the character, or the user is left guessing
        // which one of a long pattern is at fault.
        do {
            _ = try HostPattern("exam,ple.com")
        } catch {
            #expect(String(describing: error).contains(","))
        }
    }

    @Test("an empty label is refused")
    func emptyLabels() {
        for raw in ["example..com", ".example.com"] {
            #expect(throws: PolicyError.self, "should reject \(raw)") {
                try HostPattern(raw)
            }
        }
    }

    @Test("a label cannot begin or end with a hyphen")
    func hyphenBoundaries() {
        for raw in ["-example.com", "example-.com", "sub.-example.com"] {
            #expect(throws: PolicyError.self, "should reject \(raw)") {
                try HostPattern(raw)
            }
        }
    }

    /// The half that matters more: tightening validation must not refuse
    /// anything that legitimately worked.
    @Test("everything a user might legitimately write still parses")
    func legitimatePatternsSurvive() throws {
        for raw in [
            "example.com",
            "*.example.com",
            "api.anthropic.com",
            "registry-1.docker.io",  // hyphens inside a label
            "sub.domain.example.co.uk",
            "example.com:443",
            "*.example.com:8080",
            "localhost",
            "127.0.0.1",
            "example.com.",  // trailing root label
            "xn--80ak6aa92e.com",  // punycode
            "3com.com",  // a label may start with a digit
        ] {
            _ = try HostPattern(raw)
        }
    }

    /// An IPv6 literal is an address, not a hostname, and has its own alphabet.
    /// Checking hostname characters against one rejected it -- including with a
    /// port, where the closing bracket has already been split away.
    @Test("bracketed IPv6 literals are addresses, not hostnames")
    func ipv6Literals() throws {
        for raw in ["[::1]", "[2001:db8::1]", "[::1]:8080"] {
            _ = try HostPattern(raw)
        }
    }
}
