# `policy-vectors.json` format

Conformance vectors for sandbox's egress-policy `Engine` — the stateful
object built on top of the pattern matcher that `host-patterns.json` pins.
Where `host-patterns.json` fixes "does this pattern match this host:port",
this file fixes "given this sequence of DNS resolutions, dials and TLS
ClientHellos, what does the engine decide, and why".

The Go engine (`pkg/policy` in the vendored `gvisor-tap-vsock` fork, built by
`netstack/Makefile`) is authoritative. Any later implementation of this
engine — including a Swift one — must reproduce every verdict and reason in
this file exactly, without reading the Go source. This document is the
contract; the Go side's reading of it is `pkg/policy/policy_vectors_test.go`
(added by `netstack/patches/0014-*.patch`), which is the reference
implementation of "what running a case means."

## Top level

```json
{ "_comment": [...], "cases": [ ... ] }
```

`_comment` is documentation only. `cases` is the list of named scenarios.

## A case

```json
{
  "name": "a resolved allowed address is dialable",
  "allow": ["*.anthropic.com"],
  "deny": [],
  "expectConstructError": false,
  "steps": [ ... ]
}
```

- `name` — unique, human-readable. Used as the test name on every
  implementation; keep it stable once merged, since CI output and issue
  references will quote it.
- `allow`, `deny` — the pattern lists passed to the engine's constructor, in
  the same syntax as `host-patterns.json` (`host`, `host:port`, `*.host`).
- `expectConstructError` (optional, default `false`) — when `true`,
  constructing the engine from `allow`/`deny` must fail (a malformed
  pattern), and `steps` must be empty. No further evaluation happens.
- `steps` — an ordered list of inputs fed to one freshly constructed engine.
  Each case gets its own engine; state never carries over between cases.

## A step

Every step is an object with exactly one of the keys below, naming the
engine operation it drives, and an optional `expect`. A step without
`expect` is a pure side effect (seeding the ledger or advancing time); a
step with `expect` is also an assertion.

| Step key     | Engine call                          | Fields                                      |
|--------------|---------------------------------------|----------------------------------------------|
| `resolve`    | `NoteResolution(host, ips, ttl)`      | `host`, `ips` (array), `ttlSeconds`           |
| `query`      | `AllowName(host)`                     | `host`                                        |
| `dial`       | `AllowDial(proto, ip, port)`          | `proto` (`"tcp"`, `"udp"`, or `"icmp"`), `ip`, `port` |
| `hello`      | `AllowSNI(host, port)`                | `host`, `port`                                |
| `advance`    | moves the engine's clock forward      | `seconds`                                     |
| `fillLedger` | calls `NoteResolution` `count` times with distinct synthetic addresses | `count`, `ttlSeconds` |

`fillLedger` exists to exercise the ledger's capacity bound
(`maxLedgerEntries`, currently 8192) without writing eight thousand literal
addresses into this file. Implementations must generate `count` distinct
addresses that do not collide with any address a literal `resolve` step in
the same case uses.

All cases run against a fake clock that starts at a fixed instant and only
moves forward in response to `advance` steps — never the real wall clock —
so a case's outcome does not depend on when or how fast it runs.

### `expect`

```json
{ "allowed": true, "reason": "allow-rule" }
```

- `allowed` — required, the `Verdict.Allowed` the step's call must return.
- `reason` — optional. When present, must equal `Verdict.Reason` exactly.
  One of: `allow-rule`, `deny-rule`, `no-allow-rule`, `unresolved-address`,
  `sni-denied`, `sni-unreadable`.

`Verdict.Rule` and `Verdict.Names` are not checked: `Rule` is redundant with
`reason` plus the case's own pattern lists, and `Names` order is not
guaranteed by the Go engine (it is collected from a map).

## Adding a case

Add it here first, with a name that states the behavior, then make the Go
side (`make -C netstack test`, or `check-vectors` for the file-identity
check) pass it before implementing the same behavior anywhere else.
