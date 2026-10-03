# Review of the proposed fix for GHSA-97w4-f4rq-mgqm

**Verdict: the fix works. Three things to change before merge, one of which is a regression the PR introduces.**

Everything below was measured, not read. I hand-applied both halves of the diff to the compiled
2.3.8 artifacts in an isolated copy of the lab from the original report and re-ran probes
against them on `127.0.0.1`. `./run-fix-review.sh` reruns every row; raw output is in
`evidence.txt` next to this file.

---

## The fix itself is correct

The reported attack is dead:

| Probe (`maxRedirection: 2`, two-node alternate cycle) | 2.3.8 | patched |
|---|---|---|
| `Link: rel=alternate` cycle | 60 requests (our stop, not theirs) | **2 requests**, `Redirect loop detected` |
| HTML `<link rel=alternate>` cycle | 60 requests (our stop) | **2 requests**, `Redirect loop detected` |
| caller aborts mid-chain | still running 4.5 s after abort | **throws ~7 ms after the abort, `error === reason`** |

Three further things in the diff are right and worth keeping:

- `getRemoteDocument(currentUrl, …)` instead of `getRemoteDocument(url, …)` in
  `packages/fedify/src/utils/docloader.ts` fixes a separate latent bug: relative alternate
  links after a redirect previously resolved against the pre-redirect URL whenever
  `response.url` was empty.
- `return (url, options) => load(url, options)` stops an external caller seeding `redirected`
  or `visited`. That matters more than it looks — a shared `visited` set passed in from
  outside would be a cross-request oracle.
- The cycle tests are genuinely good. `redirect-intermediate` and
  `tracks fallback redirects after alternates` cover interleavings I would not have thought to
  write.

---

## 1. Regression: the patch clamps a configured `maxRedirection` to 20 (fedify only)

`follow()` hardcodes `DEFAULT_MAX_REDIRECTION`, and it runs on **every** hop — including plain
`3xx` redirects, because it is called from the new `validateRedirect`. `maxRedirection` is
destructured three lines above and forwarded to `doubleKnock`, so the two limits now disagree
and the hardcoded one wins whenever the caller asked for more than 20.

Measured, `getAuthenticatedDocumentLoader(…, { maxRedirection: 50 })` against a plain 302 chain
of distinct URLs:

```
2.3.8    THREW  Too many redirections (51)   requestsServed: 51    <- honours the caller
patched  THREW  Too many redirections (21)   requestsServed: 21    <- silently clamped to 20
```

No alternate links involved. This is a behaviour change to the redirect path that the advisory
does not mention and no test covers.

**Fix:** compute the limit from the option, as `vocab-runtime` already does for its redirect
path, and use it in `follow()`:

```ts
const maximumRedirection = maxRedirection ?? DEFAULT_MAX_REDIRECTION;
…
if (redirected >= maximumRedirection) { … }
```

`doubleKnock`'s own per-call counter then becomes the looser of the two and `follow()` stays the
authoritative global budget across alternate hops, which is what the changelog describes.

## 2. The alternate hop still ignores `maxRedirection` (both packages)

Same root cause, other direction, and this one leaves a reduced form of the reported bug in
place: a caller who asks for a tight budget does not get it on the alternate hop. Chain of
distinct URLs, so only the counter is under test:

| loader | `maxRedirection` | 302 chain | alternate chain |
|---|---|---|---|
| `getDocumentLoader` | 2 | 2 hops ✓ | **20 hops** ✗ |
| `getDocumentLoader` | 0 | 0 hops ✓ | **20 hops** ✗ |
| `getDocumentLoader` | 50 | 50 hops ✓ | 20 hops (under-follows) |
| `getAuthenticatedDocumentLoader` | 2 | 2 hops ✓ | **20 hops** ✗ |

`maxRedirection: 0` — "follow nothing" — still yields 20 outbound requests plus 20
`validatePublicUrl` lookups from a single inbound signature verification. Bounded, so not the
original advisory, but it is not the contract either.

Same one-line fix as #1: use `maximumRedirection` in the alternate closure in
`packages/vocab-runtime/src/docloader.ts`, not `DEFAULT_MAX_REDIRECTION`.

## 3. Same defect class, still live, in a third place: the Accept-Signature challenge redirect

Not in this PR's diff, but it is the same bug and you are in the file.

`packages/fedify/src/sig/http.ts:2001-2011` — the RFC 9421 `Accept-Signature` challenge branch —
follows its redirect by calling the **public** `doubleKnock()`, which defaults `redirected = 0`
and `visited = new Set()`. Unlike the two sibling redirect branches in the same function, it has
no `redirected >= maximumRedirection` check and no `visited.has()` check. Every hop resets both.

A server that answers `401` with a fulfillable `Accept-Signature` and then `302` on the challenge
retry loops forever. Measured against 2.3.8 with `doubleKnock` called exactly as
`packages/fedify/src/federation/send.ts:338` calls it (no `maxRedirection`):

```json
{"outcome":"RESOLVED 200","requestsServed":1000,"elapsedMs":3783,"stopAfterWasOurs":true}
```

1000 requests in 3.8 s, ~260/s, and the stop was the test server's, not the library's. The
challenge header needed is just `Accept-Signature: sig1=("@method" "@target-uri")` — with no
`alg` or `keyid` parameters `fulfillAcceptSignature()` accepts it from any signer.

Your patch bounds this **for the document loader** as a side effect, because `follow()` now runs
inside `validateRedirect`; the same server against the patched `getAuthenticatedDocumentLoader`
stops at 4 requests with `Redirect loop detected`. But `send.ts:338` passes no `maxRedirection`
and has no outer budget, so outbound delivery to a hostile inbox is still unbounded. The
trigger is being a delivery target, which any remote actor can arrange.

**Fix:** give that branch the same two checks its siblings have, and recurse into
`doubleKnockInternal(…, redirected + 1, visited)` rather than the public entry point.

## 4. The fix is at the wrong layer — `getRemoteDocument` is public API

Both halves of the patch add near-identical hop accounting at the two call sites, in two
packages. That duplication is exactly how the original bug happened: one caller threaded the
state, the other did not.

`getRemoteDocument` is tagged `@internal` but it is exported from `packages/vocab-runtime/src/mod.ts`
and appears in the published `dist/mod.d.ts` export list, so third parties can and do build
loaders on it. Its `fetch` parameter is documented only as *"The function to fetch the document"* —
nothing says the callback must enforce a hop budget and loop detection. Anyone who writes the
obvious callback reproduces this advisory in their own code.

Either move the budget inside `getRemoteDocument` (take an optional `{ redirected, visited, max }`
and let it do the checks), or state the contract on the parameter's tsdoc. I would do the former;
the latter is at least honest.

## 5. Docs overstate the guarantee

The new tsdoc and both changelog entries say *"At most 20 HTTP redirects and alternate document
links are followed in total per call."* That is false whenever `maxRedirection` is set — and
after #1 and #2 are fixed it will be false in both directions. Say "the configured limit
(`maxRedirection`, 20 by default)".

## 6. Test gap that would have caught #1 and #2

Every new test constructs its loader without `maxRedirection`, which is precisely why both bugs
are invisible to a green suite. Parameterising the existing hop test over
`maxRedirection ∈ {0, 2, undefined, 50}` and asserting the alternate chain stops at the
configured value — not at 20 — is about six lines and pins the contract.

Smaller notes:

- `packages/fedify/src/utils/docloader.test.ts` now mixes `@std/assert`
  (`assertEquals`/`assertRejects`) with `node:assert/strict` (`deepStrictEqual`/`ok`/`rejects`)
  in the same file. Works, reads as two authors.
- The vocab-runtime abort test asserts only `{ name: "AbortError" }` while the fedify one asserts
  `error === reason`. The stronger assertion is the useful one — a caller's abort reason
  surviving the hop is the part that regressed.

---

## Summary

| # | Severity | Where | Ship blocker |
|---|---|---|---|
| 1 | regression | `fedify/src/utils/docloader.ts` `follow()` | yes |
| 2 | correctness | both `follow()` / alternate closure | yes |
| 3 | vulnerability, out of diff | `fedify/src/sig/http.ts:2001-2011` | separate advisory |
| 4 | design | `vocab-runtime` `getRemoteDocument` contract | no |
| 5 | docs | tsdoc + `CHANGES.md` | trivial |
| 6 | tests | both new suites | recommended |

Findings 1, 2 and 3 are each fixed by a handful of lines. The core of the patch — shared budget,
shared visited set, `options` threaded so cancellation survives the hop — is the right shape and
demonstrably closes what was reported.
