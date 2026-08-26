# airlock

Run coding agents on Apple silicon in sandboxes whose network egress they
cannot bypass — even as root inside the sandbox.

> Status: early but complete for its first scope. Everything below is verified
> against live VMs, not asserted. See [Status](#status).

```console
$ airlock run claude          # Claude Code, sandboxed, in the current directory
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
3. **SNI.** On port 443 the ClientHello is peeked and policy applied to the
   name it actually asks for. The ledger can only say which names an address
   was handed out for; on a shared CDN address that is not precise enough. The
   ClientHello is sent in the clear, so this needs no interception, no
   certificate, and no key — the bytes are replayed verbatim.

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
| `exec` into a running sandbox | same policy applies |
| **container started by dockerd inside the sandbox** | same policy applies |
| `--secret anthropic` | guest sees `airlock-managed`; real value absent from the guest |
| `--clone`, agent deletes `.git` and overwrites files | host tree and history intact |
| **Vouched CDN address, different SNI** | `deny tcp … sni-denied evil.example.org` |

The `--privileged` row is the one that matters. With **every Linux capability**,
root replaced the default route and still could not get out: it could not create
a second interface, and pointing the route elsewhere only broke its own
networking. The guarantee rests on there being one device that terminates in the
airlock process, not on dropping capabilities.

The dockerd row matters for a different reason — a container started *inside* the
sandbox inherits the policy with nothing extra wired up, because it is behind the
same single interface.

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

Requires Apple silicon and macOS 26. Building needs Xcode 26 and Go 1.21+.

```console
$ brew install satishbabariya/tap/airlock   # or: make build
$ airlock kernel install                    # guest kernel, ~280 MiB download
$ airlock doctor                            # check everything at once
```

The CLI **must** be codesigned with `com.apple.security.virtualization` or
Virtualization refuses to start the VM. `make build` always signs; a bare
`swift build` produces a binary that fails at VM start with an opaque error —
`airlock doctor` catches exactly that.

## Agents

`airlock run claude` works without you knowing which image, egress rules, or
credential it needs — the agent profile carries all three, and mounts the
current directory as the workspace.

```console
$ airlock agents ls
NAME      AGENT             IMAGE                                    READY  SOURCE
claude    Claude Code       docker.io/library/node:22-bookworm-slim  yes    built-in
codex     OpenAI Codex CLI  docker.io/library/node:22-bookworm-slim  no     built-in
gemini    Gemini CLI        docker.io/library/node:22-bookworm-slim  no     built-in
opencode  OpenCode          docker.io/library/node:22-bookworm-slim  no     built-in
shell     Plain shell       docker.io/library/debian:bookworm-slim   yes    built-in
```

Installing a toolchain takes minutes, so it happens once. The first launch
builds the environment in a throwaway sandbox constrained to that agent's own
egress; later launches clone it copy-on-write. On APFS that is effectively
free — **40s to build, 0.5s to start thereafter**.

`--allow` on the command line *adds* to a profile's rules. A profile is a
floor, never a ceiling.

Override a built-in or add your own:

```console
$ airlock agents edit claude   # writes ~/.airlock/agents/claude.json
$ airlock agents cache         # what is built, and how much disk it uses
```

## MCP servers

```console
$ airlock run claude --mcp github --mcp filesystem
```

airlock runs MCP servers **inside** the sandbox, not on the host behind a
gateway. A server reads files and makes network calls on the agent's behalf, so
running it inside means it is bound by the same egress policy and sees the same
filesystem the agent does. A host-side server would be a process outside the
boundary that the sandbox can ask to act for it — which is the thing the
boundary exists to prevent.

Whatever a server needs to reach joins that sandbox's policy, so it can never
reach somewhere the agent could not. Servers are installed into the agent's
cached environment, and adding one changes the cache key so the environment is
rebuilt rather than silently reused without it.

The cost is a copy per sandbox. That is the right trade for a tool whose whole
claim is containment.

Presets: `filesystem`, `git`, `github`, `fetch`. Declare others in an agent
profile.

## Credentials the sandbox never holds

```console
$ airlock secret set anthropic          # stored in the macOS Keychain
$ airlock run claude-image --secret anthropic -- claude
```

Inside the sandbox, `ANTHROPIC_API_KEY` reads `airlock-managed`. The real value
is substituted on the host, per request, and only for `api.anthropic.com` — so a
sentinel copied out of the sandbox is worthless.

Interception is deliberately narrow: only after policy has allowed the dial,
only on 443, and only for a hostname a credential is bound to. Everything else
stays end-to-end encrypted between guest and server. Upstream certificates are
still verified.

Trust is installed by sharing a directory containing **only** the CA
certificate, read-only — never the runtime directory, which holds the resolved
secrets. The CA is appended to the system bundle rather than replacing it, and
`NODE_EXTRA_CA_CERTS` is set separately because node ignores the bundle.

## Docker inside the sandbox

```console
$ airlock run docker:28-dind --docker --allow '*.docker.io' -- /bin/sh
```

dockerd gets its own ext4 disk at `/var/lib/docker`. Containers it starts are
behind the same single interface, so **they inherit the same egress policy** with
nothing extra wired up.

Implies `--privileged`. The guest kernel does not expose the nf_tables netlink
API, so airlock points iptables at the legacy backend when the nft shim is
broken — otherwise dockerd cannot create its NAT chain.

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

## Long-lived sandboxes

```console
$ airlock run claude --name feature-x -d      # detach, print the name
$ airlock exec feature-x -- git status        # same VM, same policy
$ airlock cp ./patch.diff feature-x:/workspace/
$ airlock ls / logs / stop / rm / prune
```

Each detached sandbox is held by its own supervisor process with its own
gateway — no daemon to manage, and no shared component between sandboxes.

## Templates

```console
$ airlock run shell --name box -d
$ airlock exec box -- <configure it by hand>
$ airlock snapshot box my-setup
$ airlock run shell --template my-setup
```

An agent environment is reproducible from its profile. A template is the other
thing: a sandbox you configured by hand — extra packages, a checked-out branch,
a logged-in CLI — captured so the next one starts from it. The filesystem is
frozen for the copy, so a template is consistent rather than a snapshot of a
half-written state.

## Defaults

```console
$ airlock config set defaultAgent claude   # then just: airlock run
$ airlock config set cpus 8
$ airlock config set deny internal.example.com
$ airlock config show
```

Flags override config, with one deliberate exception: **`deny` is additive and
cannot be weakened by a flag.** An operator can pin a block for every sandbox
on the machine and rely on it. A config file that will not parse is an error,
never a silent fallback — quietly ignoring it could drop a deny rule the user
believes is in force.

## Protecting your working tree

```console
$ airlock run claude --clone
```

The agent gets a real git clone it can commit to, made from a read-only share
of your repository. It can `rm -rf` the lot and your tree is untouched — pull
the work back with `git fetch` when you are happy with it.

## Reaching a server the agent started

```console
$ airlock run claude -p 3000:3000 --name web -d
$ curl http://127.0.0.1:3000
```

Binds loopback unless you ask otherwise. Publishing opens a way *in*; it does
not widen egress.

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
| `Sources/AirlockKit/Credentials` | Keychain store, bindings, sentinel |
| `netstack/` | Pinned upstream SHA + our patches. Upstream is not vendored, so the entire security-relevant diff is reviewable in one directory |

## Status

**Working:** agent profiles with cached environments, enforced egress (DNS gate
+ dial gate + SNI inspection), policy audit log, named persistent sandboxes (`run --detach`,
`exec`, `ls`, `stop`, `rm`, `logs`, `prune`), `cp`, published ports, credential
brokering via the Keychain, a private dockerd per sandbox, workspace and
arbitrary mounts, `--clone`, `--privileged`, in-sandbox MCP servers, a config
file, templates and snapshots, interactive terminals, `doctor`,
`kernel install`.

**Not yet:** SNI inspection (hostname precision on shared CDN addresses without
interception), dynamic filesystem approval (`VZHotplugProvider`),
kit-format compatibility, host-side MCP gateway parity with sbx (a deliberate
divergence — see above), OAuth credential flows, a TUI, x86 emulation.

**Known limitation, unverified:** whether revoking a shared directory closes
file descriptors the guest already holds open. Until that is settled, revocation
is not offered as a security control.

## License

Apache-2.0. `netstack/` patches apply to
[gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock), also
Apache-2.0.
