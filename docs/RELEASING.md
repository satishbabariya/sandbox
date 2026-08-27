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
