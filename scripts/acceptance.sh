#!/bin/bash
# End-to-end acceptance for airlock. Every case boots a real VM.
#
# This exists because the project's central claim — that a compromised agent
# cannot get out — is not something unit tests can establish. Exits non-zero if
# any claim made in the README fails to hold.
#
# Usage: make acceptance   (or: scripts/acceptance.sh)
set -uo pipefail
cd "$(dirname "$0")/.."

B="${AIRLOCK_BIN:-.build/debug/airlock}"
IMAGE="${AIRLOCK_TEST_IMAGE:-docker.io/library/alpine:3.20}"
CLONE_IMAGE="${AIRLOCK_CLONE_IMAGE:-shell}"
PASS=0
FAIL=0

check_absent() { # check_absent <name> <regex-that-must-not-appear> <actual>
  if printf '%s' "$3" | grep -qE "$2"; then
    echo "  FAIL  $1"
    echo "        did not want /$2/ in:"
    printf '%s\n' "$3" | sed 's/^/          /'
    FAIL=$((FAIL + 1))
  else
    echo "  PASS  $1"
    PASS=$((PASS + 1))
  fi
}

check() { # check <name> <expected-regex> <actual>
  if printf '%s' "$3" | grep -qE "$2"; then
    echo "  PASS  $1"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $1"
    echo "        wanted /$2/ in:"
    printf '%s\n' "$3" | sed 's/^/          /'
    FAIL=$((FAIL + 1))
  fi
}

if [ ! -x "$B" ]; then
  echo "airlock not built at $B; run: make build"
  exit 1
fi

echo "== egress boundary =="

out=$($B run "$IMAGE" -- /bin/sh -c \
  'nslookup example.com >/dev/null 2>&1 && echo RESOLVED || echo REFUSED' 2>&1)
check "default-deny refuses DNS" "REFUSED" "$out"

out=$($B run "$IMAGE" --allow example.com -- /bin/sh -c \
  'wget -T 8 -q -O /dev/null http://example.com && echo FETCHED || echo BLOCKED' 2>&1)
check "allowed host is reachable" "FETCHED" "$out"

# Skipping DNS must not skip policy: an address our resolver never handed out
# is refused even though the sandbox has a working network.
IP=$(dig +short example.com | head -1)
out=$($B run "$IMAGE" --allow '*.anthropic.com' -- /bin/sh -c \
  "wget -T 8 -q -O /dev/null http://$IP && echo FETCHED || echo BLOCKED" 2>&1)
check "hardcoded IP is refused" "BLOCKED" "$out"

# The load-bearing case: every capability, route rewritten, still contained.
out=$($B run "$IMAGE" --privileged --allow '*.anthropic.com' -- /bin/sh -c \
  "ip route del default 2>/dev/null
   ip route add default via 192.168.127.1 dev eth0 2>/dev/null
   wget -T 8 -q -O /dev/null http://$IP && echo ESCAPED || echo BLOCKED" 2>&1)
check "privileged root cannot escape" "BLOCKED" "$out"

echo "== SNI inspection =="

# The case the resolution ledger cannot decide: one address, two names. The
# dial check must permit it — an allowed name really does live there — so only
# the ClientHello can refuse the connection.
out=$($B run "$CLONE_IMAGE" --no-tty --allow example.com -- /bin/sh -c '
  IP=$(getent hosts example.com | head -1 | cut -d" " -f1)
  curl -s -m 12 -o /dev/null https://example.com && echo CONTROL_REACHED || echo CONTROL_BLOCKED
  curl -s -m 12 -o /dev/null --resolve "evil.example.org:443:$IP" https://evil.example.org/ \
    && echo ATTACK_REACHED || echo ATTACK_BLOCKED' 2>&1)
# Without the control this would pass even if the gateway had simply crashed,
# which is exactly how an earlier version of it lied.
check "control: TLS to the allowed name works" "CONTROL_REACHED" "$out"
check "vouched address with a different SNI is refused" "ATTACK_BLOCKED" "$out"

echo "== workspace =="

WORK=$(mktemp -d)
echo host-wrote-this >"$WORK/in.txt"
out=$($B run "$IMAGE" -w "$WORK" -- /bin/sh -c \
  'cat /workspace/in.txt; echo guest-wrote-this > /workspace/out.txt' 2>&1)
check "workspace is readable" "host-wrote-this" "$out"
check "workspace is writable" "guest-wrote-this" "$(cat "$WORK/out.txt" 2>&1)"
rm -rf "$WORK"

echo "== interactive terminal =="

# A full-screen agent cannot render or receive keystrokes without a PTY, so
# this is load-bearing for the tool being usable at all. Needs a real
# terminal, which the test harness allocates.
out=$(scripts/pty-probe.py 40 120 240 "$B" run "$CLONE_IMAGE" -- \
  /bin/sh -c 'test -t 0 && echo STDIN_IS_TTY
              test -t 1 && echo STDOUT_IS_TTY
              stty size
              echo "env $COLUMNS $LINES"' 2>&1)
check "guest stdin is a terminal" "STDIN_IS_TTY" "$out"
check "guest stdout is a terminal" "STDOUT_IS_TTY" "$out"
check "window size reaches the guest" "40 120" "$out"
check "size is in the environment from the start" "env 120 40" "$out"

echo "== clone mode =="

# The agent must not be able to damage the user's working tree, however hard
# it tries.
REPO=$(mktemp -d)
(
  cd "$REPO" || exit 1
  git init -q
  echo original-content >file.txt
  git add -A
  git -c user.email=t@t -c user.name=t commit -q -m initial
)
out=$($B run "$CLONE_IMAGE" -w "$REPO" --clone -- /bin/sh -c \
  'echo AGENT-OVERWROTE >/workspace/file.txt; rm -rf /workspace/.git; cat /workspace/file.txt' 2>&1)
check "agent sees its own copy" "AGENT-OVERWROTE" "$out"
check "host tree is untouched" "original-content" "$(cat "$REPO/file.txt")"
check "host git history survives" "initial" "$(git -C "$REPO" log --oneline 2>&1)"
rm -rf "$REPO"

echo "== lifecycle =="

$B rm acceptance-box --force >/dev/null 2>&1
$B run "$IMAGE" --name acceptance-box --allow example.com -d -- \
  /bin/sh -c 'while true; do sleep 3600; done' >/dev/null 2>&1
check "detached sandbox is listed as running" "acceptance-box.*running" "$($B ls 2>&1)"
check "exec reaches it" "ok-from-exec" \
  "$($B exec acceptance-box -- /bin/sh -c 'echo ok-from-exec' 2>&1)"
check "exec inherits the policy" "BLOCKED" \
  "$($B exec acceptance-box -- /bin/sh -c \
    'wget -T 8 -q -O /dev/null http://pypi.org && echo FETCHED || echo BLOCKED' 2>&1)"
$B stop acceptance-box >/dev/null 2>&1
check "stop marks it stopped" "acceptance-box.*stopped" "$($B ls 2>&1)"
$B rm acceptance-box >/dev/null 2>&1
check_absent "rm removes it" "acceptance-box" "$($B ls 2>&1)"

echo "== config precedence =="

# A deny in config is a machine-wide block. If a flag could lift it, an
# operator could not rely on it, so this is a security property not a
# preference.
CONFIG="$HOME/.airlock/config.json"
SAVED=""
[ -f "$CONFIG" ] && SAVED=$(cat "$CONFIG")

"$B" config unset deny >/dev/null 2>&1
out=$($B run "$CLONE_IMAGE" --no-tty --allow example.com -- /bin/sh -c \
  'curl -s -m 8 -o /dev/null http://example.com && echo REACHED || echo BLOCKED' 2>&1)
check "control: allowed host is reachable" "REACHED" "$out"

"$B" config set deny example.com >/dev/null 2>&1
out=$($B run "$CLONE_IMAGE" --no-tty --allow example.com -- /bin/sh -c \
  'curl -s -m 8 -o /dev/null http://example.com && echo REACHED || echo BLOCKED' 2>&1)
check "config deny cannot be flagged away" "BLOCKED" "$out"

"$B" config unset deny >/dev/null 2>&1
if [ -n "$SAVED" ]; then printf '%s' "$SAVED" >"$CONFIG"; fi

echo "== credentials =="

SECRET="sk-acceptance-not-a-real-key"
printf '%s' "$SECRET" | $B secret set anthropic --stdin >/dev/null 2>&1
out=$($B run "$IMAGE" --secret anthropic -- /bin/sh -c \
  'echo "KEY=$ANTHROPIC_API_KEY"; echo "LEAKS=$(env | grep -c sk-acceptance)"' 2>&1)
check "guest sees only the sentinel" "KEY=airlock-managed" "$out"
check "real secret never enters the guest" "LEAKS=0" "$out"
$B secret rm anthropic >/dev/null 2>&1

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
