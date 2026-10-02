# Security writeups

Vulnerability research writeups by [Adel Zaitri](https://github.com/adelzaitri).

Each entry documents one finding against an open-source project: what it was, the
architecture that allowed it, how it was found including the leads that died, the
evidence, and whether the shipped fix covers the class or only the reported path.

Everything here was reported privately first, reproduced against a local
self-hosted instance with synthetic data, and published after a fix was available.
No hosted service and no third-party deployment was ever touched.

---

## Findings

| Target | Finding | Identifier | Severity | Status |
|---|---|---|---|---|
| [Langfuse](langfuse/GHSA-pvwh-5gff-vx9m-remote-experiment-credential-redirect/) | Project MEMBER redirects a dataset remote-experiment webhook and receives the stored credentials | `GHSA-pvwh-5gff-vx9m` (unpublished) | 8.5 High | Fixed in `4.16.0`. No CVE assigned — CNA-LR request pending |

---

## What a writeup here contains

The same sections in the same order, so they can be read against each other:

- **Summary** — the finding in one paragraph, plainly enough that a non-specialist
  gets the impact.
- **The architecture that made it possible** — the transferable part. "Authorization
  implemented as a helper each route must remember to call" generalises; "route X
  missed a check" does not.
- **Impact** — the boundary crossed, what an attacker obtains, and the
  prerequisites stated plainly rather than minimised.
- **Reproduction** — a runnable script, the full HTTP exchanges, and a determinism
  log. Controls first: the behaviour that is *intended* gets established before the
  behaviour that is wrong.
- **Root cause** — file and line, the code, and whether the same class exists
  elsewhere in the product.
- **The fix, as shipped** — including where it is better than what was proposed, and
  what residual remains. This is where variant hunting on your own report starts.
- **Outcome** — the disclosure timeline, including declines and disagreements,
  recorded rather than smoothed over.
- **How I found it** — honestly, including the leads that died. "I expected X, found
  the guard, went looking at Y instead" is more useful than a clean narrative.



---

## Layout

```
<target>/<identifier>-<short-slug>/
├── README.md        the writeup
└── evidence/        reproduction script, HTTP exchanges, logs, pinned versions
```

`TEMPLATE.md` is the skeleton for a new one.

---

## Licence

Writeups and evidence are released under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Reproduction scripts may
be reused freely with attribution.
