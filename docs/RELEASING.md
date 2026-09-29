# Releasing

The release is cut by pushing a tag. Everything else is automated, and the
workflow refuses to publish an archive that would not work.

## Before tagging

```console
$ make package VERSION=v0.1.0
```

This is the same target CI runs. It builds release, signs it, and then checks
the **archive** rather than the build tree: that the entitlement survived being
copied and tarred, that the gateway is inside it, and that the binary runs.
codesign travels in an extended attribute, and an archive that lost it would
install cleanly and fail at VM start with an error about entitlements rather
than about the download.

Run the acceptance suite too. It boots real VMs, so CI cannot:

```console
$ make acceptance                       # ~10 minutes
$ SANDBOX_ALL_AGENTS=1 make acceptance  # also builds every built-in agent
$ SANDBOX_AGENT_E2E=1 make acceptance   # also drives a real Claude Code session
```

Update `CHANGELOG.md`: move `[Unreleased]` items under the new version and date
it.

## Tagging

```console
$ git tag -a v0.1.0 -m "v0.1.0"
$ git push origin v0.1.0
```

The workflow then:

1. stamps `Sources/SandboxKit/Version.swift` so `sandbox --version` matches the
   tag rather than lying about what someone is running,
2. runs the unit tests and the Go suites,
3. builds and verifies the archive with `make package`,
4. stamps `packaging/sandbox.rb` with the tag's source tarball and its sha256 —
   the source tarball, because a poured bottle would arrive without the
   codesigned entitlement, so Homebrew has to build from source,
5. publishes the archive, its checksum, and the formula.

## The tap

The formula is published as a release asset with its url and sha256 already
stamped. Copy that file into the tap rather than editing one by hand, so the
checksum is the one that was actually built:

```console
$ gh release download v0.1.0 --pattern sandbox.rb --dir /path/to/homebrew-tap/Formula
$ cd /path/to/homebrew-tap && git commit -am "sandbox 0.1.0" && git push
```

Then `brew install satishbabariya/tap/sandbox` works.

## After

Check the published archive the way a user would, rather than trusting the
workflow said so. Download both files and verify the checksum first — that is
what a careful user does, and it is the step most likely to be quietly broken:

```console
$ gh release download v0.1.0
$ shasum -a 256 -c sandbox-v0.1.0-darwin-arm64.tar.gz.sha256
```

Then run it:

```console
$ tar -xzf sandbox-v0.1.0-darwin-arm64.tar.gz
$ ./sandbox-v0.1.0-darwin-arm64/bin/sandbox --version
$ ./sandbox-v0.1.0-darwin-arm64/bin/sandbox doctor
```

macOS quarantines anything downloaded through a browser. `sandbox doctor` will
report the entitlement as missing when that has happened; clear it with:

```console
$ xattr -d com.apple.quarantine /usr/local/bin/sandbox
```

## Version numbers

`Sources/SandboxKit/Version.swift` holds `0.0.1-dev` in the repository and is
stamped at release time. It is deliberately not the tag: a checkout is not a
release, and a binary built from one should not claim to be.

## If the Go gateway becomes swift-netstack

RED-4 asks what this release chain loses and gains if `netstack/`'s Go gateway
is replaced by swift-netstack. What follows traces every Go-toolchain,
upstream-fetch, and patch step in the current workflows against `main`, and
says what a `--netstack=swift` backend does or does not replace it with. It
does not change a workflow — see `ci.yml` and `release.yml` for that, unchanged.

### Where Go enters the chain today

| Step | Where | What it does |
|---|---|---|
| Go toolchain | `ci.yml:24-33` (`swift` job), `ci.yml:109-118` (`gateway` job), `ci.yml:131-140` (`vectors` job), `release.yml:36-43` | `actions/setup-go@v7` pinned to `>=1.25.6`, four separate times, because the pinned gvisor-tap-vsock revision's `go.mod` declares that version |
| Upstream fetch | `netstack/Makefile:17-25`, reading the commit from `netstack/UPSTREAM:1` | `git fetch --depth 1` of `containers/gvisor-tap-vsock` at `fca6da3418e8e6bd3b0f4f1a8c8bc1a2e84e2208`, triggered by every `make -C netstack` call: `ci.yml:43`, `ci.yml:124`, `ci.yml:142`, `release.yml:59`, `release.yml:64` |
| Patch application | `netstack/Makefile:30-35`, applying `netstack/patches/0001`–`0012` (3,481 lines across 38 files in the fetched tree) | Same call sites as the fetch — the two are inseparable in the Makefile |
| Go build | `netstack/Makefile:47-51` (`go build ./cmd/gvproxy` → `gvsandbox`) | Called from `ci.yml:43` and `release.yml:59` |
| Go test | `netstack/Makefile:53-55` (`go test` over `pkg/policy`, `pkg/broker`, `pkg/sni`, `pkg/services/dns`, `pkg/services/forwarder`) | `ci.yml:124`, `release.yml:64` |
| Conformance check | `netstack/Makefile:40-45`, diffing `testdata/host-patterns.json` against the patched tree's copy | Its own `ci.yml:142` job, and a prerequisite of the build and test targets above |
| Packaged as a second binary | `Makefile:98-99` (copied into the archive), `Makefile:118` (`test -x .../gvsandbox` inside `verify-package`) | The archive ships `sandbox` and `gvsandbox` side by side; the CLI resolves the gateway next to itself |
| Go at install time | `packaging/sandbox.rb:30` (`depends_on "go" => :build`) | Homebrew builds from source rather than pouring a bottle — the entitlement can't survive one — so a `brew install` machine needs Go too |

### What a swift-netstack backend changes

| Current step | On `--netstack=swift` |
|---|---|
| `setup-go@v7` (four call sites) | Removed. A SwiftPM build needs no Go toolchain. |
| Upstream fetch of gvisor-tap-vsock @ `fca6da3` | Replaced by a `.package(url: ".../swift-netstack.git", from: "0.2.x")` entry in `Package.swift`, resolved and pinned in `Package.resolved` the same way the six dependencies at `Package.swift:13-18` already are |
| Patch series (12 patches, 3,481 lines) | **Not replaced — removed with nothing standing in for it yet.** swift-netstack's parity claim is against plain gvproxy v0.8.9, and it has no policy hook. Every one of these patches *is* the enforcement path (default-deny egress, credential broker, SNI inspection, audit log, ICMP gating, dropping the port-forward API) sandbox added on top of upstream gvproxy — none of it is something upstream gvproxy did, so there is nothing in swift-netstack for it to already match. This document doesn't invent a mapping for the 12 patches; that's the policy-hook design and upstream-diff classification work RED-4 scopes as separate issues. Until that lands, treat this row as "gap," not "swap." |
| `go build ./cmd/gvproxy` → `gvsandbox` | Removed as a separate build. If swift-netstack links into `SandboxKit` as an ordinary SwiftPM target, there is no second binary to produce. |
| `go test` over policy/broker/sni/dns/forwarder | Removed as a Go suite. What replaces it is a Swift test, but only once the policy hook above exists — there is nothing on the swift-netstack side yet to test policy against. |
| Conformance check (`check-vectors`) | Removed in its current form. It exists to catch drift between the Swift matcher and *this Go implementation* of the matcher; with no Go matcher, there's nothing for the Swift side to drift from. A future policy hook would need its own pair of implementations to compare — not a revival of this check. |
| Second binary in the archive (`Makefile:98-99`), its existence check (`Makefile:118`) | Removed. One binary, one entitlement to verify. |
| `depends_on "go" => :build` (`packaging/sandbox.rb:30`) | Removed, once the Go path is fully retired rather than merely optional. |

### Supply chain

**Disappears:**
- The Go toolchain as a build dependency, at every call site above.
- `netstack/UPSTREAM`'s pinned commit and the shallow `git fetch` that resolves it. The comment at `netstack/Makefile:1-7` calls this "reviewable in one directory" — which is accurate, but it's review, not verification: nothing checks a signature on that commit or tag today.
- The 3,481-line patch series as *sandbox's own* Go artifact. If a policy hook eventually gets built for swift-netstack, that enforcement logic moves to wherever it lives on the Swift side — it doesn't disappear as a security property, only as a Go one, and only once it's rebuilt.
- A second binary, and the signing and existence checks that exist only because of it.

**Appears:**
- An entry in `Package.resolved` for swift-netstack, carrying a resolved revision the same way the six current dependencies do. That's a stronger provenance anchor than today's: `swift package resolve` records exactly what was fetched, and a checkout that drifts from `Package.resolved` fails closed. `netstack/Makefile:17-25` fetches whatever `FETCH_HEAD` resolves to at `UPSTREAM_SHA` with no equivalent check.
- Visibility. A repo-wide search for `sbom`, `provenance`, `slsa`, `cosign`, or `attest` turns up nothing — there is no SBOM today for either backend. But `Package.resolved` is already the closest thing this repo has to a dependency manifest, and gvisor-tap-vsock does not appear in it: that dependency is invisible to anything that reads the manifest, and discoverable only by reading `netstack/UPSTREAM` and its Makefile by hand. A SwiftPM-native swift-netstack dependency would show up there for the first time.

**Unchanged:** neither backend has a signed provenance attestation or a generated SBOM today, and this delta does not add one — that would be separate work from swapping the gateway.

### Transition period (`--netstack=swift` behind a flag)

Nothing in the "removed" rows above is true on day one. Shipping both backends
means:

- The Go toolchain provisioning, upstream fetch, patch series, and Go
  build/test steps all stay exactly as they are — the default path is still
  Go.
- The swift-netstack dependency is purely additive: a seventh entry alongside
  the six at `Package.swift:13-18`.
- The archive gains rather than trades surface area: `gvsandbox` still gets
  built and shipped for the default path, and whatever swift-netstack needs
  ships alongside it.
- `verify-package` (`Makefile:111-123`) would need a check for whichever
  backend a given build was configured with — adding that check is a workflow
  change, and out of scope here.
- The "removed" rows above describe the end state once Go is retired, not the
  state behind the flag.
