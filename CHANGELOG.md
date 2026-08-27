# Changelog

Notable changes to sandbox. Dates are the release date; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
