# <Finding title — the behaviour, not the bug class>

**<Target>** · `<GHSA-id>` · reported <date> · fixed in `<version>`

| | |
|---|---|
| **Target** | `<org/repo>`, <deployment mode> |
| **Affected** | `>= x.y.z, < a.b.c`. <State any release line that is NOT affected> |
| **Fixed in** | `<version>`, released <date> — [PR #N](url), merge commit `<sha>` |
| **Class** | `CWE-NNN: <name>` |
| **Severity** | CVSS 3.1 `<vector>` → **<score> <rating>** |
| **Identifier** | `<GHSA-id>` / `<CVE-id>`, or the honest absence of one |
| **Reported by** | <name> |

---

## Summary

The finding in one paragraph. A non-specialist should get the impact from this
alone. Name the component, the actor's privilege level, and what they end up with.

Then one paragraph on what makes it non-obvious — the thing a reviewer of that code
would have had to notice.

---

## The architecture that made it possible

The transferable half. Answer: what property of the design made this reachable, and
where else does that property appear?

Aim for a statement that survives outside this codebase. If the section could be
summarised as "a route forgot a check," it is not finished.

---

## Impact

**The boundary crossed:** <one line>.

What the attacker obtains, concretely:

- <item, verbatim where it was observed>

### Prerequisites, stated plainly

- <privilege level, with the file:line that establishes it>
- <required pre-existing state>
- <what is NOT being claimed — SSRF, internal reachability, default configuration>

No additional privilege is needed at any step. / <or state exactly where it is>.

### On the severity

Defend only the contested vector components. Name the conservative calls as
conservative.

---

## Reproduction

`evidence/repro.sh` runs it end to end against a <stock compose / documented> deployment:

```bash
<invocation>
```

<Any gotcha that cost time — host header, network name, port binding.>

**Setup.** <principals, roles, the configuration under test>

### Control 1 — <the intended behaviour>

Establish what is *correct* before showing what is wrong. Without this, the finding
reads as a complaint about a feature.

### Control 2 — <the product's own standard for this pattern, if one exists>

The strongest control is the same product refusing the same operation somewhere
else. It makes the finding a missed instance rather than an opinion.

### The finding

Step-by-step, with the real HTTP. Diff it against Control 1 explicitly — "identical
except <field>" is the sentence that does the work.

### Determinism

```
run 1  <marker transition>  <hash>  PASS
run 2  …
run 3  …
```

Say what the hash proves. A byte-identical artifact proves preservation, not
re-derivation.

---

## Root cause

`<path>:<line>`, `<function>`.

```js
<the code, trimmed to what matters>
```

State the absent comparison or check directly. Quote any comment that reveals the
author's intent — those are the tells.

### <The same class elsewhere, if it exists>

Guarded sibling, prior fix commits, or the variant that is still open.

---

## The fix, as shipped

[PR #N](url), merged <date>, released in `<version>`.

```js
<the shipped guard>
```

Compare it to what you proposed. If theirs is better, say how and why — it is the
most credible paragraph in the writeup.

**Does it cover the class?** Then the residuals, most important first:

1. <what the fix does not reach, and the configuration where that matters>
2. <design question left open>

---

## Outcome

| Date | Event |
|---|---|
| <date> | Reported privately via <route> |
| <date> | <maintainer action> |
| <date> | <release> |
| <date> | <publication / decline / silence> |

Record disagreements rather than smoothing them. If a classification was declined,
state the argument once, state what you did about it, and credit what the maintainer
got right.

---

## How I found it

Honestly. Including:

- the question you were actually asking when you found it
- the leads that died, and what the negatives taught you
- **what the tooling did and did not do** — if a harness produced the evidence, say
  so, and say the finding came from reading

---

## Credit and ethics

Thanks to <maintainer> for <what they actually did well>.

All testing against a local self-hosted instance with synthetic data. No hosted
service or third-party deployment touched. Credentials in the reproduction are lab
markers. Published after the fix was released.

---

## Evidence bundle

| File | What it is |
|---|---|
| `evidence/repro.sh` | |
| `evidence/*.http.txt` | |
| `evidence/versions.txt` | Pinned tag, commit, image digests |

## References

- <fix PR>
- <related advisories / CVEs>
- <CWE>
