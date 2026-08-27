---
name: Bug report
about: Something behaves differently from what the README says it does
labels: bug
---

## What happened

<!-- What you ran and what it did. -->

## What you expected

<!-- If the README says otherwise, quoting it helps. -->

## Output of `sandbox doctor`

<!--
This covers most of what would otherwise be a round of questions: the
entitlement, the guest kernel, the gateway, disk, and anything stray.
-->

```
$ sandbox doctor

```

## If it is about networking

A refusal inside a sandbox looks like a timeout or a DNS failure; the reason is
only visible in the audit log.

```
$ sandbox policy log <name> --denied

```

## Version and machine

- `sandbox --version`:
- macOS version:
