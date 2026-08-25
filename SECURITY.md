# Security policy

## Reporting a vulnerability

Please report privately via GitHub's ["Report a vulnerability"][advisory]
button rather than opening a public issue.

Include what you can: the airlock version (`airlock --version`), macOS version,
and the smallest reproduction you have. A working escape is more useful than a
theory, but a well-argued theory is welcome too.

[advisory]: https://github.com/satishbabariya/airlock/security/advisories/new

## What is in scope

airlock's claim is that a process inside a sandbox — **including one running as
root with every Linux capability** — cannot reach a network destination its
policy forbids. In scope:

- Reaching a denied host from inside a sandbox by any means.
- Recovering a brokered secret from inside a sandbox.
- Reading host files outside the directories explicitly shared in.
- Escaping the VM.
- One sandbox observing or influencing another.
- Any command that lets an unprivileged local user control a sandbox they did
  not start.

## What is out of scope

These are documented limitations, not vulnerabilities. They are listed in the
README under "What this does NOT protect against":

- **Exfiltration through an allowed host.** `--allow '*.github.com'` permits
  pushing a repo anywhere on GitHub. Policy is a network control, not a
  data-loss control.
- **Anything written into a mounted workspace.** That is what the mount is for.
- **Side channels** — timing, or data encoded in DNS names inside an allowed
  zone.
- **Sub-directory filesystem policy.** Virtualization.framework exposes no
  per-file-operation hook, so airlock cannot express "allow `~/.ssh/config`,
  deny `~/.ssh/id_rsa`". Share the narrower directory instead.
- A Virtualization.framework or hypervisor escape. Report those to Apple; we
  will track and mitigate what we can.

## Known unverified behaviour

Revoking a shared directory from a running sandbox may not close file
descriptors the guest already holds open. This is why airlock does **not**
offer revocation as a security control. If you can establish the answer either
way, that is a valuable contribution.

## Supported versions

Pre-1.0: only the latest release receives fixes.
