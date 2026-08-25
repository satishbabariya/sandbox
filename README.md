# airlock

Run coding agents on Apple silicon in sandboxes whose network egress they
cannot bypass — even as root inside the sandbox.

> Status: early. The enforcement boundary works and is tested against live VMs.
> Persistence, credential brokering, and in-sandbox Docker are not built yet.
> See [Status](#status).

```console
$ airlock run alpine:3.20 --allow '*.anthropic.com' -- /bin/sh
```

## Why

Agents work best unattended — installing packages, running builds, executing
code. Granting that on your own machine is the risk. On macOS the existing
options each give something up:

- **Docker Sandboxes** solves it well, but is proprietary, and gets its
  guarantees by shipping its own VMM on `Hypervisor.framework`.
- **`containerization`'s `sandboxy`** is Apache-2.0 and elegant, but filters
  egress with `HTTP_PROXY`. Its own README notes the sandbox "can currently
  reach services listening on `0.0.0.0` on the host." Any process that ignores
  the proxy variables walks straight out.

airlock is an open-source enforcement boundary built on
**Virtualization.framework**, where you do not own the VMM.

## How it works

You do not need to own the VMM. You need to own the wire.

Containerization exposes a public `VZInterface` protocol. Its `NATInterface`
returns a `VZNATNetworkDeviceAttachment`, which gives the guest a real route to
the internet. airlock supplies a different conformer that returns
**`VZFileHandleNetworkDeviceAttachment`** — a virtio-net device whose wire is a
datagram socket held by the airlock process.

The sandbox is then built with **exactly one network device and nothing else**.

```
airlock  ──spawns──>  gvairlock (userspace TCP/IP + policy)
   │                       ▲
   │                       │ unixgram: one datagram = one ethernet frame
   └──configures──>  VZVirtualMachine
                       └── virtio-net ── the only way out
```

Root inside the guest may flush its firewall, replace its default route, and
unset every proxy variable. The frames still arrive at our gateway, because
there is nowhere else to send them.

### Two gates

1. **DNS.** The gateway is the sandbox's only resolver. A name outside policy is
   never resolved, so the guest never learns its address. Every address we *do*
   hand out is recorded.
2. **Dial.** The forwarder refuses any address our resolver did not vouch for
   under an allowed name. Hardcoding an IP to skip DNS therefore fails closed
   rather than bypassing the check.

Deny is evaluated before allow everywhere, including across every name sharing a
CDN address, so a denied name cannot be laundered through a second name on the
same IP.

## What is verified

Against live VMs on `alpine:3.20`:

| Scenario | Result |
|---|---|
| No `--allow` | DNS refused |
| `--allow '*.anthropic.com'` | `api.anthropic.com` resolves |
| `--allow example.com` | HTTP succeeds, logged with the vouching name |
| Raw IP, different allow | `deny tcp … unresolved-address` |
| uid 0, proxy vars cleared | still refused |
| **`--privileged`** (`CapEff: 000001ffffffffff`), route replaced | still refused |

That last row is the one that matters: with **every Linux capability**, root
replaced the default route and still could not get out. It could not create a
second interface, and pointing the route elsewhere only broke its own
networking.

## What this does NOT protect against

Being wrong about this is worse than not shipping it.

- **A hypervisor escape.** The VM boundary is the floor.
- **Exfiltration through an allowed host.** `--allow '*.github.com'` lets an
  agent push your private repo to an attacker's GitHub account. This is a
  network control, not a data-loss control.
- **Anything written into the mounted workspace.** That is what the mount is for.
- **Side channels** — timing, or data encoded in DNS names within an allowed zone.
- **Filesystem access beyond directory granularity.** Virtualization.framework
  offers no per-file-operation hook, so airlock cannot express "allow
  `~/.ssh/config`, deny `~/.ssh/id_rsa`".

## Install

Requires Apple silicon, macOS 26, Xcode 26, and Go 1.21+ to build the gateway.

```console
$ make build          # builds the CLI and gateway, signs with the entitlement
$ make install-kernel # fetches a guest kernel into ~/.airlock
```

The CLI **must** be codesigned with `com.apple.security.virtualization` or
Virtualization refuses to start the VM. `make build` always signs; a bare
`swift build` produces a binary that fails at VM start with an opaque error.

## Usage

```console
# Nothing gets out unless you say so
$ airlock run alpine:3.20 -- /bin/sh -c 'wget example.com'
airlock: no --allow rules; this sandbox reaches nothing

# Permit specific hosts
$ airlock run alpine:3.20 --allow '*.anthropic.com' --allow registry.npmjs.org -- /bin/sh

# Deny beats allow
$ airlock run alpine:3.20 --allow '*.github.com' --deny gist.github.com -- /bin/sh

# See every decision the gateway made
$ airlock run alpine:3.20 --allow example.com --show-policy-log -- \
    /bin/sh -c 'wget -q -O/dev/null http://example.com'
allow tcp 104.20.23.154:80 allow-rule example.com

# Check a rule without booting anything
$ airlock policy check evilexample.com --allow '*.example.com'
deny   evilexample.com  (no allow rule matched)
```

## Policy grammar

An exact host (`api.anthropic.com`), a host with a port
(`registry.example.com:5000`), or a leading-label wildcard
(`*.githubusercontent.com`). A wildcard covers the apex and any depth of
subdomain, and only ever matches on a label boundary — `*.example.com` never
matches `evilexample.com`.

The matcher is implemented twice: in Swift for `airlock policy check`, and in Go
where enforcement actually happens. Both read
[`testdata/host-patterns.json`](testdata/host-patterns.json), and
`make -C netstack check-vectors` fails the build if they drift. A CLI that
disagreed with the enforcement point would be worse than no CLI.

## Layout

| Path | What |
|---|---|
| `Sources/AirlockKit/Policy` | Pattern matching, deny-wins evaluation |
| `Sources/AirlockKit/Network` | `GuestLink`, `AirlockInterface`, gateway supervisor |
| `Sources/AirlockKit/Runtime` | Sandbox lifecycle |
| `netstack/` | Pinned upstream SHA + our patches. Upstream is not vendored, so the entire security-relevant diff is reviewable in one directory |

## Status

Working: enforced egress (DNS gate + dial gate), policy audit log, sandbox
boot/run/stop, workspace mounts, `--privileged`.

Not yet: named persistent sandboxes and `exec`, credential brokering, dockerd
inside the sandbox, SNI inspection, dynamic filesystem approval.

## License

Apache-2.0. `netstack/` patches apply to
[gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock), also
Apache-2.0.
