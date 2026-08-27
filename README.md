# sandbox

Run coding agents on Apple silicon in sandboxes whose network egress they
cannot bypass — even as root inside the sandbox.

> Status: early but complete for its first scope. Everything below is verified
> against live VMs, not asserted. See [Status](#status).

```console
$ sandbox run claude          # Claude Code, sandboxed, in the current directory
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

`sandbox` is an open-source enforcement boundary built on
**Virtualization.framework**, where you do not own the VMM.

## How it works

You do not need to own the VMM. You need to own the wire.

Containerization exposes a public `VZInterface` protocol. Its `NATInterface`
returns a `VZNATNetworkDeviceAttachment`, which gives the guest a real route to
the internet. `sandbox` supplies a different conformer that returns
**`VZFileHandleNetworkDeviceAttachment`** — a virtio-net device whose wire is a
datagram socket held by the sandbox process.

The sandbox is then built with **exactly one network device and nothing else**.

```
sandbox  ──spawns──>  gvsandbox (userspace TCP/IP + policy)
   │                       ▲
   │                       │ unixgram: one datagram = one ethernet frame
   └──configures──>  VZVirtualMachine
                       └── virtio-net ── the only way out
```

Root inside the guest may flush its firewall, replace its default route, and
unset every proxy variable. The frames still arrive at our gateway, because
there is nowhere else to send them.

### Four gates

1. **DNS.** The gateway is the sandbox's only resolver. A name outside policy is
   never resolved, so the guest never learns its address. Every address we *do*
   hand out is recorded.
2. **Dial.** The forwarder refuses any address our resolver did not vouch for
   under an allowed name. Hardcoding an IP to skip DNS therefore fails closed
   rather than bypassing the check.
3. **ICMP.** An echo request is gated on the same rule as a dial. It carries a
   payload and elicits a reply, so forwarding one to any address the guest
   named would be both a reachability oracle and a channel out. There is no
   port, so a bare rule permits ping to a host it allows while a rule written
   with a port does not.
4. **SNI.** On port 443 the ClientHello is peeked and policy applied to the
   name it actually asks for. The ledger can only say which names an address
   was handed out for; on a shared CDN address that is not precise enough. The
   ClientHello is sent in the clear, so this needs no interception, no
   certificate, and no key — the bytes are replayed verbatim.

Deny is evaluated before allow everywhere, including across every name sharing a
CDN address, so a denied name cannot be laundered through a second name on the
same IP.

The gateway's own control API is not served into the sandbox. Upstream exposes
it at `gatewayIP:80` so a VM can request port forwards; here the guest is the
untrusted party, so it is removed. Ports are published from the host with `-p`,
on loopback, and the guest gets no say.

## What is verified

Against live VMs, by `scripts/acceptance.sh` — 146 cases, nearly all of which
boot a real sandbox (a few check what sandbox refuses before it boots one).
Each security claim carries a control, so a case cannot pass because the thing
it was testing never ran.

Four more run under `SANDBOX_AGENT_E2E=1`: they drive Claude Code through a
real task and cost API tokens, so they are opt-in rather than skipped by
default for being awkward.

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
| `--secret anthropic` | guest sees `sandbox-managed`; real value absent from the guest |
| `--secret claude` (host OAuth) | `HTTP 200` from the real API; token appears 0 times in the guest |
| `--clone`, agent deletes `.git` and overwrites files | host tree and history intact |
| **Vouched CDN address, different SNI** | `deny tcp … sni-denied evil.example.org` |
| **`ping 1.1.1.1` with no `--allow`** | `deny icmp 1.1.1.1:0 unresolved-address`; an allowed host stays pingable |
| A resolver the guest picked itself (`nslookup … 8.8.8.8`) | unreachable |
| IPv6 | no global address and no route; nothing to police |
| **Guest POSTs to the gateway's forwarder API** | refused; no host port appears, while `-p` still publishes on loopback |
| DNS over TCP for a denied name | `REFUSED`, while an allowed name resolves |
| Runtime and state directories | `drwx------`; another account cannot read an agent's console log |
| **TLS interception scope** | a bound domain verifies against sandbox's CA; an unbound one does not, and the CA key never leaves the host |
| Guest forging `Host:` on a brokered request | the request is addressed to the name whose certificate was verified, not the one the guest wrote |
| Guest reading outside the share (`..`, absolute path, symlink) | all refused; the share is the only thing visible |
| One sandbox reaching another at the same address | unreachable; control proves the server was up |
| Agent rewriting its own config through a `copy` mount | guest's copy changes; host file byte-identical |
| **Claude Code running a real task** | completes, with the OAuth token absent from the guest |
| **Agent fixes a bug and proves it** | edits code, installs pytest itself, `1 passed`, host tree untouched |
| Agent process identity | `uid=1000`, with sudo available inside its own VM |
| **`docker compose up` inside a sandbox** | nginx served to the host through a published port |
| `-p 18231:8231`, two servers running | published port reachable from the host; the other refused, while still serving inside the guest |
| Agent with MCP servers and an unprivileged user | the config reaches the agent's own home |
| Kit-declared file containing `$HOME` and a backtick | written verbatim at the declared mode |
| Kit-declared `background: true` command | daemon still serving when the agent runs |
| Five sandboxes started at once | all completed; no leftover gateway or supervisor |
| Ctrl-C during an agent build | stops, exits 130, leaves no gateway and no half-built rootfs |
| A run killed mid-flight | its rootfs is reclaimable: `prune` reports what it freed, `doctor` warns first |
| A guest printing at 635 MB/s | console log bounded at two generations of 32 MiB; newest output kept, and the loss is reported |
| `prune` while an unnamed run is working | it keeps its network and its rootfs; only what nothing is using is removed |
| A recorded pid that now belongs to something else | not signalled; its directory still reclaimed |
| A kit imported and run | multi-line install step, declared file, startup command, and a credential for a service sandbox ships no preset for |
| Kit `agentInstructions`, no `--clone` | withheld, and said so; your tree gains no file |
| The same kit with `--clone` | delivered into the agent's own tree |

The `--privileged` row is the one that matters. With **every Linux capability**,
root replaced the default route and still could not get out: it could not create
a second interface, and pointing the route elsewhere only broke its own
networking. The guarantee rests on there being one device that terminates in the
sandbox process, not on dropping capabilities.

The dockerd row matters for a different reason — a container started *inside* the
sandbox inherits the policy with nothing extra wired up, because it is behind the
same single interface.

## Concurrency and isolation

Sandboxes run side by side. Each gets its own gateway, its own policy, its own
resolution ledger, and its own audit log — nothing is shared between them.

They all use the same private subnet, which sounds like a collision and is not:
each gateway is a separate userspace network reachable only over that sandbox's
own socket. The practical consequence is that **one sandbox has no address by
which to name another**. Verified with a server running in one sandbox and a
second sandbox failing to reach it at the identical address, with a control
proving the server was actually up.

## What this does NOT protect against

Being wrong about this is worse than not shipping it.

- **A hypervisor escape.** The VM boundary is the floor.
- **Exfiltration through an allowed host.** `--allow '*.github.com'` lets an
  agent push your private repo to an attacker's GitHub account. This is a
  network control, not a data-loss control.
- **Anything written into the mounted workspace.** That is what the mount is for.
  Including a **symlink pointing outside it**. The agent cannot follow one — the
  guest resolves it against its own root, where the target does not exist, which
  is verified — but a tool *you* run afterwards over your tree will: an editor,
  `grep -r`, `tar`, a build step. Sharing a writable directory with an untrusted
  process has this property whatever the runtime; `--clone` avoids it by giving
  the agent a tree that is not yours.
- **Side channels** — timing, or data encoded in DNS names within an allowed zone.
- **Host sockets**, one per connection the guest holds open — measured 1:1, which
  is what any forwarding proxy does. Bounded by the process descriptor limit and
  by what the allowed host will accept; exhausting it costs that sandbox its own
  networking rather than the host's.
- **Filling your disk from inside the sandbox** is bounded, not prevented. What
  the guest drives is capped: its console output, which a shell loop wrote at
  635 MB/s before it was, and the audit log of its refusals. Each holds 32 MiB
  with one generation kept, and `sandbox logs` says when earlier output was
  dropped. A sandbox's own writes to its workspace and rootfs are not bounded.
- **Filesystem access beyond directory granularity.** Virtualization.framework
  offers no per-file-operation hook, so sandbox cannot express "allow
  `~/.ssh/config`, deny `~/.ssh/id_rsa`".

## Install

Requires Apple silicon and macOS 26. Building needs Xcode 26 and Go 1.25.6+.

Building from source is currently the only way to install. Once a release is
cut it will be installable from a tap:

```console
$ brew install satishbabariya/tap/sandbox
```

The formula in `packaging/` builds from source rather than pouring a bottle:
the binary has to be codesigned with `com.apple.security.virtualization` on the
machine it runs on, and a bottle would arrive without a signature macOS
accepts. [docs/RELEASING.md](docs/RELEASING.md) describes cutting a release.

Until then:

```console
$ git clone https://github.com/satishbabariya/sandbox && cd sandbox
$ make install            # builds release, signs it, installs to /usr/local/bin
$ sandbox kernel install  # guest kernel, ~280 MiB download
$ sandbox doctor          # check everything at once
```

Runs that are killed — a timeout, a crash, a machine going to sleep — leave a
rootfs behind, since nothing gets to clean up after a signal that cannot be
caught. `sandbox doctor` reports how much that is holding and `sandbox prune`
reclaims it. During development 280 of them had accumulated here, holding 52 GB.

`doctor` also reports what it occupies in total, split into the cached
agent environments — which `sandbox agents cache --clear` reclaims — and the
pulled image layers, which it does not offer to clear: doing so leaves cached
agents referencing content by a digest that is no longer there, which was
tested rather than assumed.

`make install` takes `PREFIX` if `/usr/local` is not where you want it, and
`make uninstall` removes both binaries again. To work from the checkout without
installing anything, `make build` puts the CLI at `.build/debug/sandbox`, which
finds its gateway in the build tree.

`make package VERSION=v0.1.0` builds the archive a release publishes and checks
it: that the entitlement survived being copied and tarred, that the gateway is
in there, and that the binary runs. An archive that lost its signature would
install cleanly and then fail at VM start with an error about entitlements
rather than about the download.

The CLI **must** be codesigned with `com.apple.security.virtualization` or
Virtualization refuses to start the VM. `make build` always signs; a bare
`swift build` produces a binary that fails at VM start with an opaque error —
`sandbox doctor` catches exactly that.

## Agents

`sandbox run claude` works without you knowing which image, egress rules, or
credential it needs — the agent profile carries all three, and mounts the
current directory as the workspace.

```console
$ sandbox agents ls
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
$ sandbox agents edit claude   # writes ~/.sandbox/agents/claude.json
$ sandbox agents cache         # what is built, and how much disk it uses
```

## MCP servers

```console
$ sandbox run claude --mcp github --mcp filesystem
```

sandbox runs MCP servers **inside** the sandbox, not on the host behind a
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

Substituting a credential means terminating TLS, so the guest is given a CA to
trust. That CA is used **only for the domains a credential is bound to**:
asked to verify against sandbox's CA alone, `api.anthropic.com` does and
`example.com` does not — the guest sees the real chain for everything else.
The private key stays on the host and is never shared into the sandbox.

A brokered request is addressed to the name whose certificate the broker
verified, not to whatever the guest put in its `Host:` header — otherwise a
guest could put a real secret on a request addressed anywhere it liked, and a
virtual-hosted endpoint may route by that name.


```console
$ sandbox secret set anthropic          # stored in the macOS Keychain
$ sandbox run claude-image --secret anthropic -- claude
```

Inside the sandbox, `ANTHROPIC_API_KEY` reads `sandbox-managed`. The real value
is substituted on the host, per request, and only for `api.anthropic.com` — so a
sentinel copied out of the sandbox is worthless.

### Reusing an OAuth sign-in

If you are already signed in to Claude Code on the host, sandbox reuses that
sign-in without the token entering the sandbox:

```console
$ sandbox run claude --secret claude
```

The token is read from the host keychain at request time and injected by the
broker. macOS will ask you to authorise that the first time, which is correct —
it is your credential, and something else wants it.

Verified: inside the sandbox, a bare `curl` with **no authorisation header** gets
`HTTP 200` from `api.anthropic.com`, while the token appears **zero** times in
the guest's environment. The sandbox authenticates with a credential it does not
have.

An expired sign-in is reported rather than injected — a dead token would surface
as a confusing 401 from inside the sandbox. An explicitly stored secret always
wins over an OAuth token, since setting one is a deliberate act.

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
$ sandbox run docker:28-dind --docker --allow '*.docker.io' -- /bin/sh
```

dockerd gets its own ext4 disk at `/var/lib/docker`. Containers it starts are
behind the same single interface, so **they inherit the same egress policy** with
nothing extra wired up.

`docker compose` works. Verified end to end: a compose stack inside the sandbox
serving nginx, reached from the host through a published port, while a nested
container is still refused a denied host.

Implies `--privileged`. The guest kernel does not expose the nf_tables netlink
API, so sandbox points iptables at the legacy backend when the nft shim is
broken — otherwise dockerd cannot create its NAT chain.

## Usage

```console
# Nothing gets out unless you say so
$ sandbox run alpine:3.20 -- /bin/sh -c 'wget example.com'
sandbox: no --allow rules; this sandbox reaches nothing

# Permit specific hosts
$ sandbox run alpine:3.20 --allow '*.anthropic.com' --allow registry.npmjs.org -- /bin/sh

# Deny beats allow
$ sandbox run alpine:3.20 --allow '*.github.com' --deny gist.github.com -- /bin/sh

# See every decision the gateway made
$ sandbox run alpine:3.20 --allow example.com --show-policy-log -- \
    /bin/sh -c 'wget -q -O/dev/null http://example.com'
allow tcp 104.20.23.154:80 allow-rule example.com

# Why was that blocked?
$ sandbox policy log my-sandbox --denied
2026-08-26 07:38:15  deny  dns www.iana.org           no-allow-rule
2026-08-26 06:21:27  deny  tcp 172.66.147.243:443     sni-denied  [blocked.example.net]

# Live view of every sandbox and its decisions
$ sandbox top

# Watch decisions as they happen
$ sandbox policy log my-sandbox --follow

# Check a rule without booting anything
$ sandbox policy check evilexample.com --allow '*.example.com'
deny   evilexample.com  (no allow rule matched)
```

## Long-lived sandboxes

```console
$ sandbox run claude --name feature-x -d      # detach, print the name
$ sandbox exec feature-x -- git status        # same VM, same policy
$ sandbox cp ./patch.diff feature-x:/workspace/
$ sandbox ls / logs / stop / rm / prune
```

Each detached sandbox is held by its own supervisor process with its own
gateway — no daemon to manage, and no shared component between sandboxes.

## Importing Docker Sandboxes kits

```console
$ sandbox kit inspect ./aider                  # what it would become
$ sandbox kit inspect ./aider --with ./neovim  # with a mixin layered on
$ sandbox kit import ./aider                   # then: sandbox run aider
```

Kits are the extension format `sbx` uses, and there is a body of existing ones.
`sandbox` reads a faithful subset and **reports what it cannot honour** rather
than quietly producing a sandbox the kit author did not describe — a dropped
deny rule would be a weaker sandbox than the one they wrote.

Measured against all 41 kits in `docker/sbx-kits-contrib`: **21 sandbox kits
translate and all 20 mixins compose onto one**, with no parse errors. Across
that corpus **4 declarations are reported as unhonoured**, and all four are the
same thing: an OAuth flow. `sandbox` reuses a sign-in already on the host but
does not perform the flow itself.

Credentials are taken from what the kit declares, not from a list sandbox ships
— a kit states the environment variable, domain, header and format for each
one, which is enough to broker a service sandbox has never heard of, across as
many domains as the credential is valid for.

Everything else translates: `permissions.network`, `credentials` with a
binding, `environment`, `setup.install`, `setup.files` (written at the declared
mode), `setup.startup` — including `background: true` commands, which are
started and left running rather than waited for — and `agentInstructions`.

`agentInstructions` is delivered **only under `--clone`**, and sandbox says so
when it withholds it. An agent reads its instructions from the working
directory, which by default is a live share of your own tree: writing there
would be a kit adding a file to your repository. `--clone` gives the agent a
tree of its own, and that one is fair game.

Composition follows the same rules as `sbx`: allow rules union (a mixin can
only widen egress, never narrow it), install and startup concatenate with the
base first, and environment and files are keyed with the mixin winning.

## Templates

```console
$ sandbox run shell --name box -d
$ sandbox exec box -- <configure it by hand>
$ sandbox snapshot box my-setup
$ sandbox run shell --template my-setup
```

An agent environment is reproducible from its profile. A template is the other
thing: a sandbox you configured by hand — extra packages, a checked-out branch,
a logged-in CLI — captured so the next one starts from it. The filesystem is
frozen for the copy, so a template is consistent rather than a snapshot of a
half-written state.

## Defaults

```console
$ sandbox config set defaultAgent claude   # then just: sandbox run
$ sandbox config set cpus 8
$ sandbox config set deny internal.example.com
$ sandbox config show
```

Flags override config, with one deliberate exception: **`deny` is additive and
cannot be weakened by a flag.** An operator can pin a block for every sandbox
on the machine and rely on it. A config file that will not parse is an error,
never a silent fallback — quietly ignoring it could drop a deny rule the user
believes is in force.

## Agents run unprivileged

Agents run as an unprivileged user inside the sandbox, reusing whatever user at
uid 1000 the image already provides and creating one only if it does not. This
is not optional polish: Claude Code refuses `--dangerously-skip-permissions` as
root, so an agent running as root cannot work at all.

They still get passwordless `sudo` **inside the sandbox**, because installing
packages is a normal thing for an agent to do. That grants nothing beyond the
VM — egress is enforced outside it, and the host filesystem is not reachable.

## Mounts that agents write to

An agent rewrites its own configuration. A profile mount marked `:copy` gives
the guest a private duplicate rather than the host's file:

```console
$ sandbox run claude --mount ~/.myconfig:/root/.myconfig:copy
```

This is not a convenience. Binding an agent's real config read-write let a
sandboxed Claude Code truncate `~/.claude.json` on the host during development
— exactly the damage a sandbox exists to prevent. All built-in agent profiles
now use `:copy` for their config.

## Protecting your working tree

```console
$ sandbox run claude --clone
```

The agent gets a real git clone it can commit to, made from a read-only share
of your repository. It can `rm -rf` the lot and your tree is untouched — pull
the work back with `git fetch` when you are happy with it.

## Reaching a server the agent started

```console
$ sandbox run claude -p 3000:3000 --name web -d
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

The matcher is implemented twice: in Swift for `sandbox policy check`, and in Go
where enforcement actually happens. Both read
[`testdata/host-patterns.json`](testdata/host-patterns.json), and
`make -C netstack check-vectors` fails the build if they drift. A CLI that
disagreed with the enforcement point would be worse than no CLI.

## Layout

| Path | What |
|---|---|
| `Sources/SandboxKit/Policy` | Pattern matching, deny-wins evaluation |
| `Sources/SandboxKit/Network` | `GuestLink`, `SandboxInterface`, gateway supervisor |
| `Sources/SandboxKit/Runtime` | Sandbox lifecycle |
| `Sources/SandboxKit/Credentials` | Keychain store, bindings, sentinel |
| `netstack/` | Pinned upstream SHA + our patches. Upstream is not vendored, so the entire security-relevant diff is reviewable in one directory |

## Status

**Working:** agent profiles with cached environments, enforced egress (DNS, dial, ICMP
and SNI gates), policy audit log, named persistent sandboxes (`run --detach`,
`exec`, `ls`, `stop`, `rm`, `logs`, `prune`), `cp`, published ports, credential
brokering via the Keychain, a private dockerd per sandbox, workspace and
arbitrary mounts, `--clone`, `--privileged`, in-sandbox MCP servers, a config
file, templates and snapshots, Docker kit import and mixin composition,
interactive terminals, `policy log`, `top`, `doctor`, `kernel install`,
`secret check`,
provisioned files and startup commands (including background daemons).

**Not yet:** dynamic filesystem approval (`VZHotplugProvider`),
host-side MCP gateway parity with sbx (a deliberate
divergence — see above), OAuth flows beyond a host sign-in already present
(sandbox reuses one but does not perform the sign-in itself), kit `extends`
chains, a TUI, x86 emulation.

**Known limitation, unverified:** whether revoking a shared directory closes
file descriptors the guest already holds open. Until that is settled, revocation
is not offered as a security control.

## License

Apache-2.0. `netstack/` patches apply to
[gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock), also
Apache-2.0.
