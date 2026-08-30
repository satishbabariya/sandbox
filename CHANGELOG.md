# Changelog

Notable changes to sandbox. Dates are the release date; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A mixin now imports directly onto the agent it belongs to. `sandbox kit
  import code-server` reads the mixin's `requires.agent: claude`, layers it
  onto the built-in claude agent, and produces a runnable composed agent —
  web VS Code with Claude Code, served on a published port. `--onto <agent>`
  overrides the target.

## [0.1.6] — 2026-08-30

### Fixed

- A detached sandbox had no credentials: the supervisor lives outside the
  user's security session and cannot read the keychain, so a detached
  agent's first API call answered an unexplained 401. The launcher now
  resolves secrets and hands them to the supervisor over stdin — never the
  spec file, never the environment.
- `exec` carried none of the environment the main command boots with — no
  credential sentinel, no `NODE_EXTRA_CA_CERTS`, so Node run via
  `sandbox exec` failed TLS against the gateway. Exec'd processes now
  inherit the sandbox's base environment; explicitly passed variables win.
- A detached sandbox now ends when its command does, the way a container
  ends with PID 1. Before, the record said "running" for as long as the
  supervisor lived, and `exec` failed against the dead init with a vmexec
  error instead of "not running".

- Kits from Docker's own template images did not actually work. Those images
  bake in `USER agent`, which silently made every root-assuming bootstrap —
  the CA trust store, kit startup commands, `/etc/hosts` — run unprivileged
  and fail, several of them into `2>/dev/null`. Kit-imported agents now use
  sandbox's own privilege drop like the built-ins: the container starts as
  root, the bootstraps do their work, and the agent runs as the image's
  unprivileged user.
- A kit install step's `user:` declaration was ignored, so `uv tool install`
  ran as root and put the tool in `/root/.local` — where the kit's entrypoint
  never looks and the agent cannot follow. Steps naming an unprivileged user
  now run as the same identity the agent gets at runtime. Startup steps
  honour `user:` the same way.

### Fixed

- A download could hang forever when one address of a multi-homed host was
  unreachable. The gateway answered the guest's connect before its own
  upstream connection existed, so the client sat on a "connected" socket that
  went nowhere instead of trying the host's next address — with one of
  GitHub's four release-asset addresses blackholed by the local network,
  every `uv`, `wget` and `fetch` against that host stalled inside the sandbox
  while the same URL worked on the host. The gateway now dials upstream
  first, bounded to 8 seconds, and answers a failed dial with the reset that
  address fallback needs.

## [0.1.5] — 2026-08-30

### Added

- A curl-able installer. `curl -fsSL
  https://raw.githubusercontent.com/satishbabariya/sandbox/main/install.sh |
  sh` verifies the release checksum, installs the signed binaries with no
  toolchain needed, and upgrades when re-run.

### Changed

- Agents see the workspace at its host path. Coding agents key project
  history, trust and session resume on the working directory, so a guest
  where every project was `/workspace` made every project the same project.
  `/workspace` remains as a symlink; plain image runs are unchanged. A
  session started on the host is now resumable inside the sandbox in the
  same project.
- Claude Code's status screen inside a sandbox no longer carries a page of
  warnings: the auto-updater is off (a cached environment updates via
  `--rebuild`, not from inside), and the native-install path the seeded
  config references now exists in the guest.

### Fixed

- Interrupting an agent build under load could leave a half-built rootfs
  behind: the cleanup raced the in-flight image unpack and lost. It now
  re-removes what reappears, and `prune` remains the backstop.

## [0.1.4] — 2026-08-29

### Changed

- Agents now keep their own configuration between runs. It is seeded from
  your `~/.claude` (or `~/.codex`, `~/.gemini`) the first time, and everything
  the agent saves — session names, model choice, settings — survives to the
  next run. Your real config is still never written. `sandbox agents reset
  <name>` discards the agent's copy and re-seeds from yours.
- `sandbox run claude` starts in about half a second. It used to copy the
  whole of `~/.claude` — 700 MB and 14,000 files here — into the guest at
  every start, which took 45 seconds before the agent ran anything, and threw
  the copy away at exit.

### Fixed

- A run that was killed rather than stopped — Ctrl-C twice, a timeout, a
  crash — leaked its gateway process forever, and `prune` could not see it:
  the process still held its runtime directory, and a missing directory was
  the only sign `prune` looked for. Sixteen were found running on the
  development machine, the oldest for two days. A gateway whose owner died is
  now recognised by its parent, and `prune` stops it and removes what the
  killed run left in /tmp.
- An alpine-based agent with an unprivileged user never started: busybox
  ships a `setpriv` without the flags the privilege drop uses, and finding it
  was treated as being able to use it. It is now probed by running it, and
  the drop falls back to `su` where it fails.

## [0.1.3] — 2026-08-28

### Fixed

- `brew install` could never have worked. SwiftPM compiles `Package.swift`
  inside its own `sandbox-exec`, Homebrew builds inside a sandbox of its own,
  and macOS refuses to nest the two: the build died with `sandbox_apply:
  Operation not permitted` before reading a line of source. The formula now
  passes `--disable-sandbox`, which is safe because brew's sandbox is already
  the outer constraint.
- An installed binary did not work at all. The gateway path, `doctor`'s
  entitlement check, and the re-exec that backs detached sandboxes were all
  derived from `argv[0]`, which is the bare name `sandbox` when the binary is
  found on PATH — so they resolved against whatever directory the user happened
  to be in. An installed CLI hunted for its gateway in the current directory and
  never started one, and `doctor` called a correctly signed binary unsigned.
- A binary installed by Homebrew reported its version as `0.0.1-dev`. The
  release workflow stamps a checkout it builds itself, but the source tarball
  keeps the placeholder, and the formula built from the tarball.

## [0.1.2] — 2026-08-27

### Fixed

- A pattern that could never match anything was accepted in silence. `--allow
  "example.com, github.com"` produced a sandbox that reached neither host and
  said nothing about why. Patterns are now checked against what a hostname can
  contain, and the error names the offending character.
- A config file was rejected as "not valid JSON" when it simply predated a
  field, so adding one would have broken every config already on disk. Every
  key is optional now.
- A bad rule in `config.json` reported the pattern without saying which file it
  came from, sending the reader to the command they had just typed rather than
  to a file that had been wrong since they wrote it.
- A sandbox record missing a field added in a later version was dropped in
  silence, so a sandbox that was still running disappeared from `ls` while its
  VM held memory, and `stop` answered with a decoding error. Records now decode
  with defaults, and one that genuinely cannot be read is reported by name
  rather than ignored.

## [0.1.1] — 2026-08-27

### Fixed

- The published checksum file named the path it was built at (`dist/…`) rather
  than the archive, so `shasum -a 256 -c` failed for anyone who downloaded both.
  The hash itself was correct; the file was unusable for the one thing it is
  for.
- The release workflow did not build the gateway before running the tests, so
  one test that boots the real gateway failed and no release could be published.
  CI had the same fault and had been fixed; the release workflow had not.

## [0.1.0] — 2026-08-27

First release. Runs coding agents in Apple Virtualization VMs whose network
egress they cannot bypass.

### Enforcement

- **Four gates.** DNS (a name outside policy is never resolved), dial (an
  address our resolver never vouched for is refused), ICMP (gated on the same
  rule as a dial), and SNI (policy applied to the name the ClientHello actually
  asks for). Deny is evaluated before allow everywhere, including across names
  sharing a CDN address.
- **The boundary is the host end of the guest's only network device**, not
  anything inside the guest. Verified against `--privileged` root holding every
  Linux capability with the default route replaced: still contained.
- **An audit log that answers "why was that refused"**, via `sandbox policy log`,
  naming the rule that decided each connection.

### Credentials

- Secrets are brokered, never handed to the guest: it sees `sandbox-managed`
  while the real value is substituted on the host. Verified with a live Claude
  Code session — the token appears zero times inside the sandbox.
- Interception is scoped to the domains a credential is bound to. A bound domain
  verifies against sandbox's CA; an unbound one does not, so the guest sees the
  real chain for everything else. The CA private key never enters the sandbox.
- An existing Claude Code sign-in on the host is reused rather than re-entered.

### Agents and kits

- Five built-in agents (claude, codex, gemini, opencode, shell), each installed
  once into a cached environment and cloned per run.
- Agents run unprivileged and can still install packages inside their own VM.
- Docker Sandboxes kits import and run. Measured against all 41 kits in
  `docker/sbx-kits-contrib`: 21 sandbox kits translate, all 20 mixins compose,
  and 4 declarations are reported as unhonoured — all of them OAuth flows.

### Sandboxes

- Named, persistent sandboxes with `run --detach`, `exec`, `ls`, `stop`, `rm`,
  `logs`, `prune`, plus `cp`, published ports, snapshots and templates.
- A private dockerd per sandbox; a container started inside inherits the policy
  with nothing extra wired up.
- `--clone` gives an agent a private git clone so your working tree is not at
  risk from what it does.

### Limits, stated rather than hidden

- A hypervisor escape is the floor.
- Exfiltration through an *allowed* host is not prevented. This is a network
  control, not a data-loss control.
- Disk-fill from inside the sandbox is bounded, not prevented: what the guest
  drives is capped, its own workspace and rootfs are not.
- Pulled image layers cannot be reclaimed — tested, because clearing them breaks
  cached agents.

Full detail, including everything that is verified and how, is in the README.

[Unreleased]: https://github.com/satishbabariya/sandbox/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/satishbabariya/sandbox/releases/tag/v0.1.2
[0.1.1]: https://github.com/satishbabariya/sandbox/releases/tag/v0.1.1
[0.1.0]: https://github.com/satishbabariya/sandbox/releases/tag/v0.1.0
