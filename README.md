# Security writeups

Vulnerability research by [Adel Zaitri](https://github.com/adelzaitri) — offensive security,
with a focus on AI and document-processing systems.

Each entry documents one finding against an open-source project: what it was, the architecture
that allowed it, how it was found including the leads that died, the evidence, and whether the
shipped fix covers the class or only the reported path.

Everything here was reported privately first and reproduced against a local instance with
synthetic data only. Each writeup is published after the vendor has shipped a fix — or, where a
vendor declined to act, after they recommended public disclosure. No hosted service and no
third-party deployment was ever touched.

---

## Findings

| # | Target · Finding | Class | Outcome | Fix | Writeup | Evidence |
|---|---|---|---|---|---|---|
| 4 | **Fedify** — the alternate-document hop resets the `CVE-2026-34148` redirect cap and visited-URL set, and discards the caller's `AbortSignal`: one inbound request drove 2,827 outbound in six seconds | Resource exhaustion ·<br>bypass of a patched CVE | **Fix merged in 2 days, backported to 4 release lines, and the maintainer requested a CVE unprompted.** Advisory `GHSA-97w4-f4rq-mgqm` in draft, CVE pending. [Public credit already live in `CHANGES.md`](https://github.com/fedify-dev/fedify/blob/main/CHANGES.md) | [`2.3.9`](https://github.com/fedify-dev/fedify/commit/2659f5ae56) | [Read](fedify/GHSA-97w4-f4rq-mgqm-alternate-document-hop-redirect-cap-reset/) | [repro](fedify/GHSA-97w4-f4rq-mgqm-alternate-document-hop-redirect-cap-reset/evidence/repro.sh) · [control](fedify/GHSA-97w4-f4rq-mgqm-alternate-document-hop-redirect-cap-reset/evidence/control.http.txt) · [attack](fedify/GHSA-97w4-f4rq-mgqm-alternate-document-hop-redirect-cap-reset/evidence/attack.http.txt) · [abort proof](fedify/GHSA-97w4-f4rq-mgqm-alternate-document-hop-redirect-cap-reset/evidence/screenshot-3-abortsignal.png) · [version matrix](fedify/GHSA-97w4-f4rq-mgqm-alternate-document-hop-redirect-cap-reset/evidence/range.txt) · **[my review of their patch](fedify/GHSA-97w4-f4rq-mgqm-alternate-document-hop-redirect-cap-reset/evidence/REVIEW-proposed-fix.md)** |
| 3 | **Docling** — `validate_url_safety` checks a host `requests` never connects to; one backslash in the authority splits the two parsers and defeats the SSRF guard | SSRF · TOCTOU<br>`CWE-918` `CWE-367` | **Advisory published, credited as reporter** — [`GHSA-pc36-qwjq-x68c`](https://github.com/docling-project/docling/security/advisories/GHSA-pc36-qwjq-x68c), 4.0 Medium. Fixed in 48h; advisory description extended to cover the differential | [`2.132.0`](https://github.com/docling-project/docling/pull/4420) | [Read](docling/GHSA-pc36-qwjq-x68c-url-parser-differential-ssrf-bypass/) | [repro](docling/GHSA-pc36-qwjq-x68c-url-parser-differential-ssrf-bypass/evidence/repro.sh) · [controls](docling/GHSA-pc36-qwjq-x68c-url-parser-differential-ssrf-bypass/evidence/control.http.txt) · [attack](docling/GHSA-pc36-qwjq-x68c-url-parser-differential-ssrf-bypass/evidence/attack.http.txt) · [screens](docling/GHSA-pc36-qwjq-x68c-url-parser-differential-ssrf-bypass/evidence/screenshot-2-attack.png) · [repeat 3/3](docling/GHSA-pc36-qwjq-x68c-url-parser-differential-ssrf-bypass/evidence/repeat.log) |
| 2 | **Langfuse** — a project MEMBER repoints a dataset remote-experiment webhook and receives the administrator's stored credentials plus a valid request signature | Credential exposure<br>`CWE-522` | **Fixed, advisory unpublished, CVE declined as "hardening."** CVE requested from the CVE Program's CNA of Last Resort 2026-10-02, pending. [Why I disagree](langfuse/GHSA-pvwh-5gff-vx9m-remote-experiment-credential-redirect/#outcome) | [`4.16.0`](https://github.com/langfuse/langfuse/pull/16307) | [Read](langfuse/GHSA-pvwh-5gff-vx9m-remote-experiment-credential-redirect/) | [repro](langfuse/GHSA-pvwh-5gff-vx9m-remote-experiment-credential-redirect/evidence/repro.sh) · [controls](langfuse/GHSA-pvwh-5gff-vx9m-remote-experiment-credential-redirect/evidence/control.http.txt) · [attack](langfuse/GHSA-pvwh-5gff-vx9m-remote-experiment-credential-redirect/evidence/attack.http.txt) · [collector](langfuse/GHSA-pvwh-5gff-vx9m-remote-experiment-credential-redirect/evidence/collector.log) · [repeat 3/3](langfuse/GHSA-pvwh-5gff-vx9m-remote-experiment-credential-redirect/evidence/repeat.log) |
| 1 | **Open Policy Agent** — `allow_net` does not restrict `unix://` destinations in `http.send`; one allowed hostname reaches any local UNIX socket, including a container-runtime socket | SSRF<br>`CWE-918` | **No identifier.** Maintainers declined a GHSA and a CVE and recommended a public issue — filed as [opa#9320](https://github.com/open-policy-agent/opa/issues/9320). Unfixed at time of writing; nothing in the finding was refuted | — | [Read](opa/allow-net-unix-socket-bypass/) | [repro](opa/allow-net-unix-socket-bypass/evidence/repro.sh) · [4 controls](opa/allow-net-unix-socket-bypass/evidence/control.http.txt) · [attack](opa/allow-net-unix-socket-bypass/evidence/attack.http.txt) · [SDK path](opa/allow-net-unix-socket-bypass/evidence/screenshot-3-sdk-embedder.png) · [repeat 3/3](opa/allow-net-unix-socket-bypass/evidence/repeat.log) |

**Every row ships a runnable reproduction, a control proving the guard works before it is
broken, and a determinism log.** Nothing here rests on a single lucky run.

---

## If you are reviewing this quickly

The four things worth knowing, and where to check each one:

**1. Every finding is proved against the product's own standard, not against my opinion.** The
most load-bearing artifact in each writeup is a *control* — the same operation refused by the
same software. Langfuse's guarded sibling router refusing the identical credential redirect
([Control 2](langfuse/GHSA-pvwh-5gff-vx9m-remote-experiment-credential-redirect/#control-2--the-products-own-standard-for-this-pattern));
Docling's own guard raising its own error text on the exact destination the bypass reaches
([Control 2](docling/GHSA-pc36-qwjq-x68c-url-parser-differential-ssrf-bypass/#control-2--with-the-feature-on-the-guard-refuses-a-loopback-url)).
That turns a finding from a severity argument into a missed instance of a class.

**2. The findings came from reading, and the tooling came after.** Each writeup says which was
which. Langfuse came from noticing a guard that was *present* in one router and asking where else
the pattern lived. Docling came from reading a function's **type signature** — a validator
returning `None` cannot constrain the action that follows it. Fedify came from reading someone
else's CVE fix and asking which hops it did not cover.

**3. I review the vendor's patch, and once that found a second bug.** For Fedify I applied the
proposed fix to the compiled artifacts by hand and re-ran every probe against it. The fix worked
— and it had **silently clamped a caller-configured `maxRedirection` of 50 down to 20 on the
ordinary redirect path**, a regression no test covered and the advisory did not mention.
[The review is in the repo](fedify/GHSA-97w4-f4rq-mgqm-alternate-document-hop-redirect-cap-reset/evidence/REVIEW-proposed-fix.md).

**4. The disagreements are published too, in both directions.** A finding that was confirmed,
fixed, and still earned no identifier is in here with that outcome stated plainly — and so is the
case where I was the one who got it wrong. Docling closed my report as a duplicate and
[I explain why that call was correct](docling/GHSA-pc36-qwjq-x68c-url-parser-differential-ssrf-bypass/#outcome); OPA declined entirely and
[I say what I would do differently](opa/allow-net-unix-socket-bypass/#outcome).

---

## What a writeup here contains

The same sections in the same order, so they can be read against each other:

- **Summary** — the finding in one paragraph, plainly enough that a non-specialist gets the
  impact.
- **The architecture that made it possible** — the transferable part. "A validator that returns
  `None` cannot constrain the action it authorises" generalises; "route X missed a check" does
  not.
- **Impact** — the boundary crossed, what an attacker obtains, and the prerequisites stated
  plainly rather than minimised. Where a finding needs a non-default configuration, that is the
  first sentence, not a footnote.
- **Reproduction** — a runnable script, full HTTP exchanges, and a determinism log. Controls
  first: the behaviour that is *intended* is established before the behaviour that is wrong.
- **Root cause** — file and line, the code, and whether the same class exists elsewhere.
- **The fix, as shipped** — including where it is better than what I proposed, and what residual
  remains. This is where variant hunting on my own report starts.
- **Outcome** — the disclosure timeline including declines and disagreements, recorded rather
  than smoothed over.
- **How I found it** — honestly, including the leads that died.


---

## Layout

```
<target>/<identifier>-<short-slug>/
├── README.md        the writeup
└── evidence/        reproduction script, HTTP exchanges, screenshots, logs, pinned versions
```

`TEMPLATE.md` is the skeleton for a new one.

---

## Licence

Writeups and evidence are released under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Reproduction scripts may be reused
freely with attribution.
