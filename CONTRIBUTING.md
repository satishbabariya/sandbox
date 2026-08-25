# Contributing to airlock

## Ground rules for a security tool

airlock's entire value is one claim: **a compromised agent cannot get out**.
That means two things for contributions.

**Claims need evidence, not argument.** If a change touches the enforcement
path, it needs a test that fails without it. `scripts/acceptance.sh` boots real
VMs precisely because unit tests cannot establish that claim.

**The README's "What this does NOT protect against" section is load-bearing.**
If your change narrows or widens what airlock defends against, update it in the
same PR. Overclaiming is worse than not shipping.

## Getting set up

Requires Apple silicon, macOS 26, Xcode 26, and Go 1.21+.

```console
$ make build            # CLI + gateway, signed with the entitlement
$ make install-kernel   # guest kernel into ~/.airlock
$ make test             # Swift + Go unit tests
$ make acceptance       # boots real VMs; the one that matters
```

`make build` always codesigns. A bare `swift build` produces a binary that
fails at VM start with an opaque entitlement error — if you see that, you
skipped the Makefile.

## Where things live

| Path | What |
|---|---|
| `Sources/AirlockKit/Policy` | Pattern matching, deny-wins evaluation |
| `Sources/AirlockKit/Network` | `GuestLink`, `AirlockInterface`, gateway supervisor |
| `Sources/AirlockKit/Runtime` | Sandbox lifecycle, store, control protocol |
| `Sources/AirlockKit/Agents` | Agent profiles, rootfs cache |
| `Sources/AirlockKit/Credentials` | Keychain, bindings, sentinel |
| `netstack/` | Pinned upstream SHA + our patches |

## Changing the gateway

`netstack/` is **not** a vendored copy. It is a pinned upstream commit plus a
patch series, so the whole security-relevant difference stays reviewable in one
directory. To change it:

```console
$ make -C netstack            # fetches and patches into netstack/.work
$ cd netstack/.work
$ git checkout -b my-change
# edit, then:
$ git commit -am "..."
$ git format-patch -o ../patches <UPSTREAM_SHA>..HEAD
```

Keep the diff against upstream files small. Prefer adding a package and calling
into it over editing upstream logic in place — it keeps the patch applying
cleanly when the pin moves.

## The policy matcher exists twice

Swift powers `airlock policy check`; Go actually refuses the connection. They
must agree exactly, or the CLI lies about what the sandbox will do. Both read
`testdata/host-patterns.json`, and `make -C netstack check-vectors` fails the
build on drift.

**Add a case to that file first**, then make both sides pass it.

## Style

- `swift format --in-place --recursive Sources Tests` before pushing; CI lints it.
- Comments explain *why*, not *what*. The code says what.
- Commit messages: a short subject, then prose explaining the reasoning. No
  AI-assistant attribution trailers.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).
