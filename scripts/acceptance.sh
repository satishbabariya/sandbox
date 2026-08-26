#!/bin/bash
# End-to-end acceptance for airlock. Every case boots a real VM.
#
# This exists because the project's central claim — that a compromised agent
# cannot get out — is not something unit tests can establish. Exits non-zero if
# any claim made in the README fails to hold.
#
# Usage: make acceptance   (or: scripts/acceptance.sh)
# The scripts a case runs inside the sandbox are single-quoted on purpose: the
# expansions in them belong to the guest's shell, not this one. That is SC2016,
# and it is the intended behaviour throughout this file.
# shellcheck disable=SC2016

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

B="${AIRLOCK_BIN:-.build/debug/airlock}"
# Absolute, because a case that runs airlock from a workspace it just created
# has to cd there first, and a relative path stops resolving the moment it does.
case "$B" in /*) ;; *) B="$PWD/$B" ;; esac
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

# A bare `swift build` -- or a `swift test`, which rebuilds the executable --
# replaces the signed binary with an unsigned one. Every case then fails with
# "the process doesn't have the com.apple.security.virtualization entitlement",
# which looks like sixty broken features rather than one missing signature.
if ! codesign -d --entitlements - "$B" 2>&1 | grep -q virtualization; then
  echo "$B is not signed with com.apple.security.virtualization, so no sandbox"
  echo "can start. A plain 'swift build' or 'swift test' strips it."
  echo "run: make build"
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

echo "== egress by other protocols =="

# ICMP echo carries a payload and elicits a reply, so forwarding one to any
# address the guest names is both a reachability oracle and a channel out.
# Upstream forwards them unconditionally: before this was gated, a sandbox with
# no allow rules -- one airlock reports as reaching nothing -- pinged 1.1.1.1
# successfully, and nothing appeared in the audit log.
out=$($B run "$IMAGE" --no-tty -- /bin/sh -c \
  'ping -c1 -W3 1.1.1.1 >/dev/null 2>&1 && echo ESCAPED || echo BLOCKED' 2>&1)
check "ping to an address outside policy is refused" "BLOCKED" "$out"
check_absent "and does not get out" "ESCAPED" "$out"

# The control: gating ICMP must refuse what policy refuses, not break ping.
out=$($B run "$IMAGE" --no-tty --allow example.com -- /bin/sh -c '
  ping -c1 -W5 example.com >/dev/null 2>&1 && echo ALLOWED_OK || echo ALLOWED_BLOCKED
  ping -c1 -W3 1.1.1.1 >/dev/null 2>&1 && echo OUTSIDE_ESCAPED || echo OUTSIDE_BLOCKED' 2>&1)
check "control: an allowed host is still pingable" "ALLOWED_OK" "$out"
check "while another address is not" "OUTSIDE_BLOCKED" "$out"

# A refusal nobody can see is indistinguishable from a network fault.
$B rm icmpaudit --force >/dev/null 2>&1
$B run "$IMAGE" --no-tty --name icmpaudit -- /bin/sh -c \
  'ping -c1 -W3 1.1.1.1 >/dev/null 2>&1' >/dev/null 2>&1
check "the refusal is recorded" "deny  icmp 1.1.1.1" "$($B policy log icmpaudit 2>&1)"
$B rm icmpaudit --force >/dev/null 2>&1

# Naming another resolver is the obvious way around a gateway that is the only
# one configured.
out=$($B run "$IMAGE" --no-tty --allow example.com -- /bin/sh -c \
  'nslookup evil.example.org 8.8.8.8 >/dev/null 2>&1 && echo RESOLVED || echo REFUSED' 2>&1)
check "a resolver the guest picked itself is unreachable" "REFUSED" "$out"

# IPv6 would be a second stack to police; the guest is given no route to one.
out=$($B run "$IMAGE" --no-tty -- /bin/sh -c '
  ping -6 -c1 -W3 2606:4700:4700::1111 >/dev/null 2>&1 && echo V6_ESCAPED || echo V6_BLOCKED
  wget -T5 -q -O/dev/null "http://[2606:4700:4700::1111]/" 2>&1 >/dev/null && echo V6_TCP_ESCAPED || echo V6_TCP_BLOCKED' 2>&1)
check_absent "there is no IPv6 way out" "ESCAPED" "$out"

echo "== DNS over TCP is policed like DNS over UDP =="

# The resolver answers on TCP as well as UDP, and a gate applied to only one of
# them would be no gate at all. Asked with a real DNS/TCP client rather than
# nslookup -vc, whose output does not distinguish a refusal from a failure.
out=$($B run docker.io/library/python:3.12-alpine --no-tty --allow example.com -- python3 -c '
import socket, struct

def query(name):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    msg = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)
    s = socket.create_connection(("192.168.127.1", 53), timeout=8)
    s.sendall(struct.pack(">H", len(msg)) + msg)
    n = struct.unpack(">H", s.recv(2))[0]
    resp = s.recv(n)
    s.close()
    return resp[3] & 0x0F, struct.unpack(">H", resp[6:8])[0]

for name in ["example.com", "evil.example.org"]:
    try:
        rcode, answers = query(name)
        print(f"{name} rcode={rcode} answers={answers}")
    except Exception as e:
        print(f"{name} failed {e}")
' 2>&1)
# rcode 5 is REFUSED, which is what the gate returns; 0 with answers is a
# genuine resolution.
check "control: an allowed name resolves over TCP" "example.com rcode=0 answers=[1-9]" "$out"
check "a denied name is refused over TCP too" "evil.example.org rcode=5 answers=0" "$out"

echo "== the guest cannot publish itself to the host =="

# Upstream serves its port-forwarding control API inside the virtual network,
# so a VM can ask for forwards. The guest is the untrusted party here and the
# endpoint needs no credential: a sandbox with no allow rules opened a listener
# on the host at *:19099 -- every interface, not loopback -- pointed at a
# service of its own, which `airlock ports` did not show because airlock had
# published nothing.
$B rm exposecase --force >/dev/null 2>&1
$B run docker.io/library/python:3.12-alpine --name exposecase --detach --no-tty -- /bin/sh -c '
  mkdir -p /srv && echo GUEST_PUBLISHED_ITSELF >/srv/index.html
  (cd /srv && python3 -m http.server 8099 >/dev/null 2>&1) &
  sleep 2
  wget -T6 -q -O- --post-data="{\"local\":\":19099\",\"remote\":\"192.168.127.2:8099\"}" \
    --header="Content-Type: application/json" \
    http://192.168.127.1/services/forwarder/expose >/dev/null 2>&1
  sleep 60' >/dev/null 2>&1
sleep 6

check "the control API is not reachable from the guest" "refused" \
  "$($B exec exposecase -- /bin/sh -c \
     'wget -T4 -q -O- http://192.168.127.1/services/forwarder/all 2>&1' 2>&1)"
check_absent "no host port appears" "LISTEN" \
  "$(lsof -nP -iTCP:19099 -sTCP:LISTEN 2>/dev/null || true)"
check_absent "and the host cannot reach the guest service" "GUEST_PUBLISHED_ITSELF" \
  "$(curl -s --max-time 4 http://127.0.0.1:19099/index.html 2>&1 || true)"
$B rm exposecase --force >/dev/null 2>&1

# The control: closing that path must not stop the user publishing a port.
$B rm publishcase --force >/dev/null 2>&1
$B run docker.io/library/python:3.12-alpine --name publishcase --detach --no-tty -p 18232:8232 -- \
  /bin/sh -c 'mkdir -p /srv && echo USER_PUBLISHED_THIS >/srv/index.html && cd /srv && python3 -m http.server 8232' >/dev/null 2>&1
for _ in 1 2 3 4 5 6 7 8; do
  curl -sf --max-time 2 http://127.0.0.1:18232/index.html >/dev/null 2>&1 && break
  sleep 1
done
check "control: a port the user published still works" "USER_PUBLISHED_THIS" \
  "$(curl -s --max-time 6 http://127.0.0.1:18232/index.html 2>&1)"
# ...and only on loopback, unlike the forward the guest had been able to make.
check "and binds loopback, not every interface" "127.0.0.1:18232" "$($B ports publishcase 2>&1)"
$B rm publishcase --force >/dev/null 2>&1

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

echo "== docker inside the sandbox =="

# Skippable: it pulls a dind image and is the slowest case here.
if [ "${AIRLOCK_SKIP_DOCKER:-0}" = "1" ]; then
  echo "  skipped (AIRLOCK_SKIP_DOCKER=1)"
else
  out=$($B run docker.io/library/docker:28-dind --docker --no-tty \
    --allow '*.docker.io' --allow '*.docker.com' -- /bin/sh -c '
      docker version --format "server={{.Server.Version}}" 2>&1 | tail -1
      # Registries are the flakiest thing this suite touches, and a pull that
      # failed would produce neither marker below -- which reads exactly like
      # a blocked request, i.e. a pass for the wrong reason.
      for attempt in 1 2 3; do
        docker pull -q docker.io/library/alpine:3.20 >/dev/null 2>&1 && break
        sleep 3
      done
      docker run --rm docker.io/library/alpine:3.20 sh -c \
        "echo NESTED_RAN; wget -T5 -q -O/dev/null http://example.com \
           && echo NESTED_ESCAPED || echo NESTED_BLOCKED"' 2>&1)
  # dockerd needs writable sysctls; without clearing readonlyPaths it dies at
  # "failed to set IP forwarding", which this catches.
  check "dockerd starts" "server=" "$out"
  # Without this control, a nested container that never started would look
  # identical to one that started and was correctly refused.
  check "control: a nested container runs at all" "NESTED_RAN" "$out"
  # A container started inside the sandbox is behind the same interface, so it
  # inherits the same policy with nothing extra wired up.
  check "a nested container inherits the policy" "NESTED_BLOCKED" "$out"
  check_absent "the nested container did not get out" "NESTED_ESCAPED" "$out"
fi

echo "== agents run unprivileged =="

# Claude Code refuses --dangerously-skip-permissions as root, so an agent
# profile that ran as root could not work at all. Running unprivileged is also
# the right posture: an agent has no business being root inside its own VM.
# Uses the shell agent rather than a large one: a changed install step would
# otherwise rebuild a multi-minute environment in the middle of the suite.
out=$($B run "$CLONE_IMAGE" --no-tty -- /bin/sh -c 'echo "uid=$(id -u)"; sudo -n true 2>/dev/null && echo sudo-ok' 2>&1)
check "agent is not root" "uid=1000" "$out"
# But it must still be able to install things, which is a normal agent action.
check "agent can still escalate inside its own VM" "sudo-ok" "$out"

echo "== host files are not writable through a copy mount =="

# An agent rewrites its own config. Binding the host's real one read-write let
# a sandboxed agent truncate it — which happened, and is exactly the host
# damage a sandbox exists to prevent. Copy mounts give the guest its own.
STAGE=$(mktemp -d)
echo "host-original" >"$STAGE/config.json"
BEFORE=$(shasum -a 256 "$STAGE/config.json" | cut -d" " -f1)
"$B" run "$CLONE_IMAGE" --no-tty --mount "$STAGE/config.json:/tmp/cfg.json:copy" -- \
  /bin/sh -c 'echo guest-overwrote >/tmp/cfg.json; cat /tmp/cfg.json' >/tmp/airlock-copy.log 2>&1
check "guest can write its copy" "guest-overwrote" "$(cat /tmp/airlock-copy.log)"
check "host file is untouched" "^$BEFORE$" "$(shasum -a 256 "$STAGE/config.json" | cut -d' ' -f1)"
rm -rf "$STAGE" /tmp/airlock-copy.log

echo "== the audit log explains refusals =="

# A refusal at DNS is the commonest kind, and until it was recorded the log had
# nothing to show for exactly the case users hit most.
"$B" rm audit-box --force >/dev/null 2>&1
"$B" run "$CLONE_IMAGE" --name audit-box -d --no-tty --allow example.com -- \
  /bin/sh -c 'while true; do sleep 3600; done' >/dev/null 2>&1
sleep 4
"$B" exec audit-box --no-tty -- /bin/sh -c \
  'curl -s -m 6 -o /dev/null https://www.iana.org; curl -s -m 8 -o /dev/null https://example.com' \
  >/dev/null 2>&1
LOG=$("$B" policy log audit-box 2>&1)
check "a DNS refusal is recorded with its name" "deny  dns www.iana.org" "$LOG"
check "an allowed dial names the rule" "allow-rule 'example.com'" "$LOG"
check_absent "--denied shows no allows" "allow " "$("$B" policy log audit-box --denied 2>&1)"
"$B" rm audit-box --force >/dev/null 2>&1

echo "== sandbox isolation =="

# Every sandbox gets the same private subnet, so the question is whether two of
# them can reach each other. They cannot: each gateway is a separate userspace
# network, and there is no address by which one sandbox can name another.
"$B" rm iso-server --force >/dev/null 2>&1
"$B" rm iso-client --force >/dev/null 2>&1
"$B" run docker.io/library/python:3.12-alpine --name iso-server -d --no-tty -- \
  /bin/sh -c 'echo isolated-server >/tmp/i.html; cd /tmp && python3 -m http.server 8000 --bind 0.0.0.0' \
  >/dev/null 2>&1
"$B" run "$CLONE_IMAGE" --name iso-client -d --no-tty -- \
  /bin/sh -c 'while true; do sleep 3600; done' >/dev/null 2>&1
sleep 8

# The control matters: without it this passes whenever the server failed to
# start, which is exactly how an earlier version of it lied.
check "control: the server is reachable from its own sandbox" "isolated-server" \
  "$("$B" exec iso-server --no-tty -- /bin/sh -c \
    'wget -q -O- -T5 http://192.168.127.2:8000/i.html' 2>&1)"
check "another sandbox cannot reach it at the same address" "unreachable" \
  "$("$B" exec iso-client --no-tty -- /bin/sh -c \
    'curl -s -m 6 http://192.168.127.2:8000/i.html || echo unreachable' 2>&1)"

"$B" rm iso-server --force >/dev/null 2>&1
"$B" rm iso-client --force >/dev/null 2>&1

echo "== cleanup =="

count_gateways() { pgrep -f "bin/gvairlock" 2>/dev/null | wc -l | tr -d " "; }
count_supervisors() { pgrep -f "airlock supervise" 2>/dev/null | wc -l | tr -d " "; }
# Other sandboxes may legitimately be running; compare against a baseline
# rather than assuming this machine is otherwise idle.
BASELINE_GATEWAYS=$(count_gateways)
count_dirs() {
  set -- /tmp/airlock-*
  [ -e "$1" ] && echo "$#" || echo 0
}

# An ephemeral run must leave nothing behind. One stray directory per
# invocation is invisible until there are hundreds.
"$B" prune >/dev/null 2>&1
BEFORE_DIRS=$(count_dirs)
"$B" run "$CLONE_IMAGE" --no-tty -- /bin/true >/dev/null 2>&1
check "ephemeral run leaves no state" "^$BEFORE_DIRS$" "$(count_dirs)"

# Ctrl-C must take the gateway with it, or every interrupted run leaks a VM.
"$B" run "$CLONE_IMAGE" --no-tty -- /bin/sh -c "echo READY; sleep 120" >/tmp/airlock-sigint.log 2>&1 &
SIG_PID=$!
SPENT=0
while ! grep -q READY /tmp/airlock-sigint.log 2>/dev/null && [ "$SPENT" -lt 120 ]; do
  sleep 2
  SPENT=$((SPENT + 2))
done
RUNNING=$(count_gateways)
if [ "$RUNNING" -gt "$BASELINE_GATEWAYS" ]; then
  echo "  PASS  gateway runs while the sandbox does"
  PASS=$((PASS + 1))
else
  echo "  FAIL  gateway runs while the sandbox does (baseline $BASELINE_GATEWAYS, now $RUNNING)"
  FAIL=$((FAIL + 1))
fi
kill -INT "$SIG_PID" 2>/dev/null
sleep 8
check "SIGINT stops the gateway" "^$BASELINE_GATEWAYS$" "$(count_gateways)"
rm -f /tmp/airlock-sigint.log
"$B" prune >/dev/null 2>&1

echo "== credentials =="

SECRET="sk-acceptance-not-a-real-key"
printf '%s' "$SECRET" | $B secret set anthropic --stdin >/dev/null 2>&1
out=$($B run "$IMAGE" --secret anthropic -- /bin/sh -c \
  'echo "KEY=$ANTHROPIC_API_KEY"; echo "LEAKS=$(env | grep -c sk-acceptance)"' 2>&1)
check "guest sees only the sentinel" "KEY=airlock-managed" "$out"
check "real secret never enters the guest" "LEAKS=0" "$out"
$B secret rm anthropic >/dev/null 2>&1

echo "== snapshot and templates =="

# A snapshot is only worth anything if what the sandbox wrote comes back. The
# control matters as much as the assertion: a template that restored an empty
# filesystem would also produce no marker, and would look identical.
$B rm snaptest --force >/dev/null 2>&1
$B templates rm accepttpl >/dev/null 2>&1
$B run "$IMAGE" --name snaptest --detach --no-tty -- /bin/sh -c 'sleep 300' >/dev/null 2>&1
$B exec snaptest -- /bin/sh -c 'echo snapshot-marker >/root/marker.txt' >/dev/null 2>&1
out=$($B snapshot snaptest accepttpl 2>&1)
check "snapshot reports what it saved" "saved template 'accepttpl'" "$out"
check "the template is listed" "accepttpl" "$($B templates list 2>&1)"

out=$($B run --template accepttpl "$IMAGE" --no-tty -- \
  /bin/sh -c 'cat /root/marker.txt 2>&1; echo "ALIVE=yes"' 2>&1)
check "control: a sandbox from the template runs" "ALIVE=yes" "$out"
check "what the sandbox wrote survives into the template" "snapshot-marker" "$out"

# A fresh sandbox on the same image must NOT have it, or the marker proves
# nothing about the template.
out=$($B run "$IMAGE" --no-tty -- /bin/sh -c 'cat /root/marker.txt 2>&1' 2>&1)
check_absent "an ordinary sandbox has no trace of it" "snapshot-marker" "$out"

echo "== copying files in and out =="

PAYLOAD="cp-payload-$$"
printf '%s\n' "$PAYLOAD" >/tmp/airlock-cp-in.txt
rm -f /tmp/airlock-cp-out.txt
$B cp /tmp/airlock-cp-in.txt snaptest:/root/copied.txt >/dev/null 2>&1
check "a copied file arrives in the guest" "$PAYLOAD" \
  "$($B exec snaptest -- /bin/sh -c 'cat /root/copied.txt' 2>&1)"

$B cp snaptest:/root/copied.txt /tmp/airlock-cp-out.txt >/dev/null 2>&1
check "and comes back unchanged" "$PAYLOAD" "$(cat /tmp/airlock-cp-out.txt 2>&1)"
rm -f /tmp/airlock-cp-in.txt /tmp/airlock-cp-out.txt

$B rm snaptest --force >/dev/null 2>&1
$B templates rm accepttpl >/dev/null 2>&1
check_absent "removing a template removes it" "accepttpl" "$($B templates list 2>&1)"

echo "== provisioned files and startup commands =="

# Content is deliberately hostile: a quote, a $, and a backtick. If any of it
# were interpolated into the generated script rather than encoded, this either
# corrupts the file or executes in the guest's own bootstrap.
AGENTS_DIR="$HOME/.airlock/agents"
mkdir -p "$AGENTS_DIR"
rm -f "$AGENTS_DIR/acceptprov.json"
cat >"$AGENTS_DIR/acceptprov.json" <<'PROFILE'
{"name":"acceptprov","displayName":"provisioning acceptance",
 "image":"docker.io/library/python:3.12-alpine",
 "command":["/bin/sh","-c","sleep 3; cat '/etc/airlock probe/data.txt'; /usr/local/bin/probe; wget -q -O- http://127.0.0.1:8231/data.txt 2>&1 | head -1"],
 "files":[
   {"path":"/etc/airlock probe/data.txt","content":"it's $HOME `whoami` VERBATIM\n"},
   {"path":"/usr/local/bin/probe","mode":"0755","content":"#!/bin/sh\necho PROBE_EXECUTED\n"}],
 "startup":[
   {"argv":["/bin/sh","-c","cp '/etc/airlock probe/data.txt' /srv-data.txt 2>/dev/null; mkdir -p /srv && cp '/etc/airlock probe/data.txt' /srv/data.txt"]},
   {"argv":["/bin/sh","-c","python3 -m http.server 8231 --directory /srv"],"background":true},
   {"argv":["/bin/false"]}]}
PROFILE

# Without this control, a profile that failed to register would fail every
# assertion below at once, and the seven failures would say nothing about why.
# The registry drops a profile it cannot decode rather than complaining.
check "control: the provisioning profile is registered" "acceptprov" \
  "$($B agents ls 2>&1)"

out=$($B run acceptprov --no-tty 2>&1)
rm -f "$AGENTS_DIR/acceptprov.json"

# Written verbatim: the shell that wrote the file must not have expanded any of it.
check "file content is written verbatim" 'it.s \$HOME `whoami` VERBATIM' "$out"
check "a file mode is applied" "PROBE_EXECUTED" "$out"
# Ordering: a startup command must find the files already written.
check "startup commands run after the files exist" "VERBATIM" "$out"
# The daemon only answers if it was started and left running.
check "a background command keeps running" "VERBATIM" "$out"
check "a failing startup command is reported" "startup command failed" "$out"
# ...and does not stop the sandbox, or nothing above would have printed.
check_absent "a failing startup command does not stop the sandbox" "PROBE_EXECUTED_NEVER" "$out"

# Resolving its own hostname cost 10s per lookup before /etc/hosts was seeded,
# which is long enough that ordinary daemons looked like they had hung.
out=$($B run "$IMAGE" --no-tty -- /bin/sh -c \
  'S=$(date +%s); getent hosts "$(hostname)" >/dev/null 2>&1; echo "ELAPSED=$(($(date +%s)-S))"' 2>&1)
check "the sandbox resolves its own hostname immediately" "ELAPSED=0" "$out"

echo "== published ports =="

# Two servers, one port published. Publishing must expose exactly what was
# asked for: a sandbox that opened every listening port to the host would be a
# far larger surface than the user agreed to.
$B rm portcase --force >/dev/null 2>&1
$B run docker.io/library/python:3.12-alpine --name portcase --detach --no-tty \
  -p 18231:8231 -- /bin/sh -c '
    mkdir -p /a /b
    echo PUBLISHED_PORT >/a/index.html
    echo UNPUBLISHED_PORT >/b/index.html
    python3 -m http.server 8232 --directory /b &
    python3 -m http.server 8231 --directory /a' >/dev/null 2>&1

# Give both servers time to bind before concluding anything about either.
for _ in 1 2 3 4 5 6 7 8; do
  curl -sf --max-time 2 http://127.0.0.1:18231/index.html >/dev/null 2>&1 && break
  sleep 1
done

check "airlock ports names the mapping" "18231 -> 8231" "$($B ports portcase 2>&1)"
check "a published port is reachable from the host" "PUBLISHED_PORT" \
  "$(curl -s --max-time 8 http://127.0.0.1:18231/index.html 2>&1)"
# The control above proves the guest is up and serving, so a failure here is
# the port being closed rather than the sandbox being dead.
check_absent "an unpublished port is not reachable from the host" "UNPUBLISHED_PORT" \
  "$(curl -s --max-time 5 http://127.0.0.1:8232/index.html 2>&1)"
# ...and the unpublished server really is listening inside the guest, or the
# check above would pass for the wrong reason.
check "control: the unpublished server is up inside the guest" "UNPUBLISHED_PORT" \
  "$($B exec portcase -- /bin/sh -c 'wget -q -O- http://127.0.0.1:8232/index.html' 2>&1)"

$B rm portcase --force >/dev/null 2>&1

echo "== MCP servers are declared to the agent =="

# Every built-in agent that declares MCP servers also drops privilege and names
# a config path under /root. Writing that file after the drop cannot work, and
# the symptom is an agent that simply has no servers.
rm -f "$AGENTS_DIR/acceptmcp.json"
cat >"$AGENTS_DIR/acceptmcp.json" <<'PROFILE'
{"name":"acceptmcp","displayName":"mcp acceptance",
 "image":"docker.io/library/debian:bookworm-slim",
 "runAsUser":"agent","mcpConfigPath":"/root/.mcp.json",
 "mcp":[{"name":"demo","command":"/bin/true"}],
 "command":["/bin/sh","-c","echo uid=$(id -u); cat $HOME/.mcp.json 2>&1"]}
PROFILE
check "control: the MCP profile is registered" "acceptmcp" "$($B agents ls 2>&1)"
out=$($B run acceptmcp --no-tty 2>&1)
rm -f "$AGENTS_DIR/acceptmcp.json"

check "control: the agent is unprivileged" "uid=1000" "$out"
check "the server reaches the agent's own config" '"demo"' "$out"
check_absent "the config is not left unwritten" "could not write" "$out"

# The flag cannot work without an agent -- the server is installed into an
# agent's cached environment and declared where its profile says -- so it is
# refused rather than ignored after booting a VM.
out=$($B run "$IMAGE" --no-tty --mcp filesystem -- /bin/true 2>&1)
check "--mcp without an agent is refused, not ignored" "needs an agent" "$out"

echo "== console output is captured =="

$B rm logcase --force >/dev/null 2>&1
$B run "$IMAGE" --name logcase --detach --no-tty -- \
  /bin/sh -c 'echo ON_STDOUT; echo ON_STDERR >&2; sleep 60' >/dev/null 2>&1
for _ in 1 2 3 4 5 6; do
  $B logs logcase 2>&1 | grep -q ON_STDOUT && break
  sleep 1
done
out=$($B logs logcase 2>&1)
check "a detached sandbox's stdout is kept" "ON_STDOUT" "$out"
# Both streams, or a crash message would be the thing you could not read.
check "and its stderr with it" "ON_STDERR" "$out"
$B rm logcase --force >/dev/null 2>&1

echo "== image references are spelled the way everyone spells them =="

# Every other container tool takes alpine:3.20, and so does every kit: 14 of
# the 21 sandbox kits in docker/sbx-kits-contrib name their image without a
# registry. Rejecting that reads as the image being wrong, not the spelling.
out=$($B run alpine:3.20 --no-tty -- /bin/sh -c 'echo BARE_REFERENCE_RAN' 2>&1)
check "a bare Docker Hub reference runs" "BARE_REFERENCE_RAN" "$out"
check_absent "and is not rejected as a bad domain" "invalid domain" "$out"

# A reference that already names a registry must be left alone, or a private
# registry would silently become Docker Hub.
out=$($B run "$IMAGE" --no-tty -- /bin/sh -c 'echo QUALIFIED_RAN' 2>&1)
check "a fully qualified reference still runs" "QUALIFIED_RAN" "$out"

# No tag is what a user types first, and the image store rejects one outright.
out=$($B run alpine --no-tty -- /bin/sh -c 'echo UNTAGGED_RAN' 2>&1)
check "an untagged reference defaults to latest" "UNTAGGED_RAN" "$out"

# A mistyped agent name is treated as an image, so without this the answer is
# whatever the registry says about an image nobody meant to pull.
out=$($B run notanagent-notanimage --no-tty -- /bin/true 2>&1)
check "a name that is neither agent nor image lists the agents" "agents: claude" "$out"
check "and says it looked for an image too" "treated as an image" "$out"

echo "== kit instructions reach a clone, never your tree =="

rm -f "$AGENTS_DIR/acceptinstr.json"
cat >"$AGENTS_DIR/acceptinstr.json" <<'PROFILE'
{"name":"acceptinstr","displayName":"instructions acceptance",
 "image":"docker.io/library/debian:bookworm-slim",
 "agentInstructions":{"filename":"AGENTS.md","content":"KIT_GUIDANCE_DELIVERED\n"},
 "command":["/bin/sh","-c","echo pwd=$(pwd); cat AGENTS.md 2>&1"]}
PROFILE
check "control: the instructions profile is registered" "acceptinstr" "$($B agents ls 2>&1)"

INSTR_DIR=$(mktemp -d)
echo original >"$INSTR_DIR/kept.txt"

# Default workspace is a live share of the user's tree: a kit must not add a
# file to it, and must say why the agent did not get its guidance.
out=$(cd "$INSTR_DIR" && $B run acceptinstr --no-tty 2>&1)
check_absent "nothing is written into your own working tree" "KIT_GUIDANCE_DELIVERED" "$out"
check "and airlock says why not" "Use --clone" "$out"
check_absent "your tree gains no file" "AGENTS.md" "$(ls -a "$INSTR_DIR" 2>&1)"

# A clone is the agent's own tree, so the guidance belongs there.
out=$(cd "$INSTR_DIR" && $B run acceptinstr --no-tty --clone 2>&1)
check "a cloned workspace receives the guidance" "KIT_GUIDANCE_DELIVERED" "$out"
check_absent "and your tree still gains no file" "AGENTS.md" "$(ls -a "$INSTR_DIR" 2>&1)"
check "your own files are untouched" "original" "$(cat "$INSTR_DIR/kept.txt" 2>&1)"

rm -rf "$INSTR_DIR"
rm -f "$AGENTS_DIR/acceptinstr.json"

echo "== orphaned processes are reaped =="

# A sandbox is two processes: a supervisor holding the VM, and a gateway
# holding its policy. Lose the record that names them -- a crash, an
# interrupted rm -- and both keep running with nothing to belong to. The
# supervisor is the one that matters: it holds the VM's memory.
$B rm orphancase --force >/dev/null 2>&1
$B prune >/dev/null 2>&1
BASE_GW=$(count_gateways)
BASE_SUP=$(count_supervisors)
$B run "$IMAGE" --name orphancase --detach --no-tty -- /bin/sh -c 'sleep 120' >/dev/null 2>&1
for _ in 1 2 3 4 5 6; do
  [ "$(count_gateways)" -gt "$BASE_GW" ] && break
  sleep 1
done
check "control: a running sandbox has a gateway" "yes" \
  "$([ "$(count_gateways)" -gt "$BASE_GW" ] && echo yes || echo no)"
check "control: and a supervisor holding its VM" "yes" \
  "$([ "$(count_supervisors)" -gt "$BASE_SUP" ] && echo yes || echo no)"

# Remove the record behind its back, which is the state a crash leaves.
rm -f "$HOME/.airlock/sandboxes/orphancase.json"
out=$($B prune 2>&1)
check "prune says it stopped the supervisor" "orphaned supervisor" "$out"
check "prune says it stopped the gateway" "orphaned gateway" "$out"
sleep 2
check "and the VM is not still resident" "yes" \
  "$([ "$(count_supervisors)" -le "$BASE_SUP" ] && echo yes || echo no)"
check "and the gateway is gone" "yes" \
  "$([ "$(count_gateways)" -le "$BASE_GW" ] && echo yes || echo no)"

# The harder case: the directory holding both pid files is removed while the
# processes still run, so nothing recorded anywhere can name them. They are
# found by what they say about themselves on their own command line.
$B rm straycase --force >/dev/null 2>&1
$B run "$IMAGE" --name straycase --detach --no-tty -- /bin/sh -c 'sleep 120' >/dev/null 2>&1
for _ in 1 2 3 4 5 6; do
  [ "$(count_supervisors)" -gt "$BASE_SUP" ] && break
  sleep 1
done
rm -f "$HOME/.airlock/sandboxes/straycase.json"
rm -rf /tmp/airlock-straycase
check "doctor reports a process still holding a VM" "holding a VM" "$($B doctor 2>&1)"
out=$($B prune 2>&1)
check "prune finds a process whose directory is gone" "stray supervisor" "$out"
sleep 2
check "and stops it" "yes" \
  "$([ "$(count_supervisors)" -le "$BASE_SUP" ] && echo yes || echo no)"

echo "== a kit is imported and run =="

# Translating a kit and running one are different things: three bugs that made
# every real kit fail to install got through a suite that only ever inspected
# them. This kit is self-contained -- it installs from a printf, not from a
# GitHub release -- so the case tests airlock rather than the network.
$B kit import testdata/kits/selftest --name acceptkit --force >/dev/null 2>&1
check "control: the kit imports" "acceptkit" "$($B agents ls 2>&1)"

printf '%s' "sk-selftest-not-a-real-key" | $B secret set selftest --stdin >/dev/null 2>&1
out=$($B run acceptkit --no-tty --secret selftest 2>&1)

# The install step is a multi-line bash program with a case block and a command
# substitution, which is what the old assembly could not survive.
check "a multi-line install step runs" "INSTALLED_BY_KIT" "$out"
check "a declared file is written" "DECLARED_FILE_WRITTEN" "$out"
check "a startup command runs" "STARTUP_RAN" "$out"
# The kit names a service airlock ships no preset for; the binding and the
# variable both have to come from the kit, or the tool is never told there is
# a key at all.
check "a kit-declared credential reaches the tool" "KEY=airlock-managed" "$out"
check_absent "and the real value does not" "sk-selftest-not-a-real-key" "$out"

$B secret rm selftest >/dev/null 2>&1
$B agents rm acceptkit >/dev/null 2>&1
check_absent "an imported kit can be removed again" "acceptkit" "$($B agents ls 2>&1)"

echo "== a real agent, end to end =="

# Opt-in: this one spends API tokens and needs a Claude Code sign-in already on
# the host. It is the claim the whole project rests on -- an agent doing real
# work without ever holding the credential -- so it is here rather than only in
# somebody's memory of having tried it once.
if [ "${AIRLOCK_AGENT_E2E:-0}" != "1" ]; then
  echo "  skipped (set AIRLOCK_AGENT_E2E=1 to run; needs a host sign-in)"
else
  E2E_DIR=$(mktemp -d)
  cat >"$E2E_DIR/calc.py" <<'PYFILE'
def add(a, b):
    return a - b


def test_add():
    assert add(2, 3) == 5
PYFILE

  out=$(cd "$E2E_DIR" && $B run claude --no-tty --secret claude -- \
    claude --dangerously-skip-permissions -p \
    'Run: python3 -m pytest calc.py -q. It fails. Fix the bug in calc.py, rerun, and reply with the final pytest summary line.' 2>&1)

  check "the agent gets the tests passing" "1 passed" "$out"
  check "and its fix is on the host afterwards" "a \+ b" "$(cat "$E2E_DIR/calc.py" 2>&1)"

  # The point of the exercise: it reached the real API while never holding the
  # token that let it.
  leak=$($B run claude --no-tty --secret claude -- /bin/sh -c \
    'echo "KEY=$ANTHROPIC_API_KEY"; echo "LEAKS=$(env | grep -c sk-ant)"' 2>&1)
  check "the guest saw only the sentinel" "KEY=airlock-managed" "$leak"
  check "the real token never entered the guest" "LEAKS=0" "$leak"
  rm -rf "$E2E_DIR"
fi

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
