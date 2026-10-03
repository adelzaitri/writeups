# `validate_url_safety` checks a host that `requests` never connects to: a backslash in the authority splits the two parsers

**Docling** · credited on [`GHSA-pc36-qwjq-x68c`](https://github.com/docling-project/docling/security/advisories/GHSA-pc36-qwjq-x68c) · reported 2026-09-30 · fixed in `2.132.0`

| | |
|---|---|
| **Target** | Docling (`docling-project/docling`) |
| **Affected** | `docling >= 2.91.0, < 2.132.0`; `docling-slim >= 2.92.0, < 2.132.0` |
| **Fixed in** | `2.132.0`, released 2026-10-01 — [PR #4420](https://github.com/docling-project/docling/pull/4420), merge commit `5e469137` |
| **Class** | `CWE-918: SSRF` + `CWE-367: TOCTOU` |
| **Severity** | CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N` → **4.0 Medium** (maintainer-assigned) |
| **Identifier** | Published advisory [`GHSA-pc36-qwjq-x68c`](https://github.com/docling-project/docling/security/advisories/GHSA-pc36-qwjq-x68c), credited as reporter. My own draft `GHSA-r3j5-hf3x-pc2j` was closed as a duplicate and merged into it. No CVE assigned |
| **Reported by** | Adel Zaitri (co-credited with `DavidCarliez`) |

---

## Summary

`validate_url_safety` is Docling's single SSRF chokepoint, and its docstring states the guarantee
plainly:

> Reject URLs that resolve to a non-public IP address. Guards against SSRF by requiring the URL's
> host to resolve to a globally routable address.

It parses the URL with `urllib.parse`, validates what it finds, and returns `None`. **It pins
nothing.** The caller then hands the *original string* to `requests`, which parses it again with
`urllib3`.

Those two parsers disagree about where the authority ends. `urllib3`'s authority group is
`(?://([^\\/?#]*))?` — the backslash terminates it. CPython's `_splitnetloc` looks only for `/`,
`?` and `#`, so a backslash is an ordinary character, the whole run is netloc, and `_hostinfo`
takes the host after the **last** `@`.

So for `http://127.0.0.1:18099\@1.1.1.1/x.png`:

- the guard checks `1.1.1.1` — globally routable, **passes**
- `requests` opens a socket to `127.0.0.1:18099`

**The guard decides on a parse. The fetch acts on a string.** One backslash is the whole
exploit.

### The mechanism, in one picture

One string, parsed twice, by two libraries that disagree about where the authority ends. The
left branch decides; the right branch connects.

```mermaid
flowchart TB
    URL["ONE string, supplied by the document<br/><code>http://127.0.0.1:18099#92;@1.1.1.1/x.png</code>"]

    URL --> G["<b>The guard</b><br/>validate_url_safety<br/>parses with urllib.parse"]
    URL --> R["<b>The fetch</b><br/>session.get(src_loc)<br/>parses with urllib3"]

    G --> GP["_splitnetloc stops only at / ? #<br/>so the backslash is ordinary<br/>_hostinfo takes the host after the LAST @"]
    R --> RP["authority regex is (?://([^#92;/?#]*))?<br/>so the backslash ENDS the authority"]

    GP --> GH["host = <b>1.1.1.1</b><br/>is_global = True"]
    RP --> RH["host = <b>127.0.0.1:18099</b><br/>backslash demoted into the path"]

    GH --> OK(["PASSES — returns None<br/>nothing is pinned"])
    RH --> CONN(["CONNECTS to loopback<br/>carrying docling's own Range header"])

    OK -.->|"the guard's decision<br/>constrains nothing"| CONN

    G2["<b>The shipped fix, 2.132.0</b><br/>resolve once, require EVERY address global,<br/>bind the pool to a validated address"]
    CONN --> G2

    classDef guard fill:#e8f0fe,stroke:#1a73e8,stroke-width:1px,color:#111
    classDef fetch fill:#fce8e6,stroke:#d93025,stroke-width:1px,color:#111
    classDef neutral fill:#f1f3f4,stroke:#5f6368,color:#111
    classDef fixed fill:#e6f4ea,stroke:#137333,stroke-width:1px,color:#111
    class G,GP,GH,OK guard
    class R,RP,RH,CONN fetch
    class URL neutral
    class G2 fixed
```

---

## The architecture that made it possible

This is the transferable half, and it generalises well past Docling.

The guard's signature is the defect. `validate_url_safety(url) -> None` can only ever answer a
question about a *representation*; it cannot constrain the action that follows, because it hands
back nothing the caller is obliged to use. Everything the function learned — the parsed host, the
resolved address, the decision that it was safe — is discarded at `return`. The caller is then
free to re-derive all of it, by a different route, and it does.

That shape is a **validate-then-reparse** gap, and it has two independent failure modes baked in:

1. **Parser disagreement.** Two libraries parse the same string differently. This is what the
   backslash exploits, and it needs no DNS infrastructure and no timing — it is deterministic and
   offline.
2. **Resolver disagreement.** The guard calls `gethostbyname` (A records only); `urllib3` calls
   `getaddrinfo(..., AF_UNSPEC)`. A host publishing a public A and a loopback AAAA passes on the
   A and connects on the AAAA. And because no address is pinned, an ordinary DNS rebind between
   the two lookups works too — which is the classic TOCTOU, and why the published advisory carries
   `CWE-367` alongside `CWE-918`.

The invariant that would have prevented all of it: **a check and the action it authorises must
operate on the same object, not on two derivations of the same string.** For network egress that
means validating and then *connecting to the validated address* — not re-resolving a hostname the
check happened to approve.

Any security check whose return type is `None` or `bool` is worth a second look for this reason.
A function that answers "is this safe?" invites the caller to then do the thing by its own route;
a function that answers "here is the safe thing to use" does not.

---

## Impact

**Server-side request forgery past the control that exists to prevent it**, in any deployment
that has enabled remote image fetching.

The fetch originates from the Docling process, so it reaches loopback services and anything else
on the deployment network that the document's author cannot address directly — cloud metadata
endpoints, local admin interfaces, internal APIs. The request carries Docling's own
`Range: bytes=0-20971519` header and a `python-requests` user agent.

**This is blind SSRF, and I did not claim otherwise.** The response goes to `Image.open` and is
discarded unless it decodes as an image. What an attacker reliably gets is the *request*, not the
reply. The published advisory frames it the same way: "Response content is exposed only when it
decodes as an image or is rendered into the page screenshot."

**Delivery is an ordinary document.** For HTML it is a single `<img src="…">` tag. Five backends
construct `ImageResourceLoader` — HTML, EPUB, Markdown, AsciiDoc and JATS — and ODF reaches it
too through `opendocument_backend.py:867`.

### The non-default requirement, stated first rather than buried

`enable_remote_fetch` defaults to `False`, as does `fetch_images`. A deployer must have turned
remote fetching on. That is the main drag on severity and it is not worth arguing away — it is
why the maintainers scored this 4.0 Medium with `AC:H`, and that is a defensible number.

But it is also precisely the population `validate_url_safety` was written to protect. A guard
that only exists in the configuration where it fails is not much of a guard, and the first
control row below demonstrates the default so nobody has to take my word for the scoping.

---

## Reproduction

Automated in `evidence/repro.sh`, run end to end from a clean state before the report was
written:

```bash
./repro.sh all      # up -> parsers -> control x2 -> attack -> reverse -> repeat 3 -> down
```

**Every row runs with `--network none`, and the lab makes no DNS query at all.** The payload's
post-`@` host is a literal IP, so the guard takes its literal-IP branch and never calls
`gethostbyname`. Nothing is ever sent to `1.1.1.1` — the socket opens to `127.0.0.1`. The
listener lives inside the same container, because that is where `urllib3` connects.

One install note that matters for attribution: the metapackage `docling` resolves to
`docling-slim[standard]`, which pulls torch. Nothing on this path touches it, so the lab installs
`docling-slim[format-html]==2.130.0` and `repro.sh` **asserts torch is absent** — so the result
cannot be attributed to a different dependency set.

### The differential, with no Docling involved

Establishing the parser disagreement in isolation first means the rest of the report is about
Docling's use of it, not about whether it exists:

```
 python 3.12.14   urllib3 2.8.0   docling 2.130.0

 url: http://127.0.0.1:18099\@1.1.1.1/<marker>.png
   guard checks (urllib.parse.urlparse().hostname) : 1.1.1.1      is_global=True
   socket opens to (urllib3.util.parse_url().host) : 127.0.0.1:18099

 url: http://1.1.1.1\@127.0.0.1:18099/<marker>.png
   guard checks (urllib.parse.urlparse().hostname) : 127.0.0.1    is_global=False
   socket opens to (urllib3.util.parse_url().host) : 1.1.1.1:None
```

### Control 1 — the feature is off by default

```
outcome        : REFUSED (OperationNotAllowed)
error          : Fetching remote resources is only allowed when set explicitly.
                 Set options.enable_remote_fetch=True.
socket_opened  : False
```

### Control 2 — with the feature ON, the guard refuses a loopback URL

```
outcome        : REFUSED (ValueError)
error          : Access to restricted IP address not allowed: 127.0.0.1
socket_opened  : False
```

**This is the load-bearing control.** It is their guard, raising their error text, on the exact
destination the attack row reaches. Without it, "a request arrived" would prove nothing at all.

![Control: the guard refuses loopback](evidence/screenshot-1-control.png)

### The attack — one backslash

```
outcome        : FETCHED
socket_opened  : True

The listener, inside the same container, on 127.0.0.1:18099, received:
  GET /%5C@1.1.1.1/<marker>.png
    Range      : bytes=0-20971519
    User-Agent : python-requests/2.34.2
```

The path is `/%5C@1.1.1.1/...` — the backslash percent-encoded and everything after it demoted to
the path. **That is urllib3's parse, visible on the wire.** The `Range` header is Docling's own,
from `image_resource_loader.py:202`, which is how you know the request came from inside the
library rather than from the harness.

![Attack: the loopback listener receives the fetch](evidence/screenshot-2-attack.png)

### The reverse row — this must fail closed, and it does

```
url            : http://1.1.1.1\@127.0.0.1:18099/<marker>.png
outcome        : REFUSED (ValueError)
error          : Access to restricted IP address not allowed: 127.0.0.1
socket_opened  : False
```

Swap the halves and the guard sees `127.0.0.1` and refuses. So the finding is the parser
**disagreement**, not "the guard never works" — and this row rules out the lazier reading before
a reviewer has to ask for it.

### Determinism

Three consecutive reproductions, fresh container each time. 3/3, transcript in
`evidence/repeat.log`.

---

## Root cause

`docling/backend/utils/image_resource_loader.py`, at `v2.130.0`.

The guard resolves, validates, and discards:

```python
:48    parsed = urlparse(url)
:49    hostname = parsed.hostname
:58            ip_str = socket.gethostbyname(hostname)
```

`validate_url_safety` returns `None`. **No address is returned; nothing is pinned.** The caller:

```python
:199            validate_url_safety(src_loc)
:227            response = session.get(
:228                src_loc, stream=True, headers=headers, timeout=(5, 30)
```

`src_loc` is the original string, unmodified.

**And this is the single chokepoint** — `grep -rn "validate_url_safety" docling/` returned
exactly three lines: the definition at `:34`, the call at `:199`, and the redirect hook at
`:223`. There is nowhere else the invariant could have been enforced.

### Two further instances of the same missing invariant

I reported these in the same report rather than separately, because one fix closes all three, and
because the second shown alone invites a fair *"unavoidable without a custom resolver"* reply.
**Both were inferred from reading and not demonstrated, and the report said so explicitly rather
than letting the framing imply otherwise.**

- **The redirect hook inherits it.** `:223` validates the `Location` header as a string, and
  nothing constrains `requests`' own parse of that header when it resolves the redirect —
  structurally identical, one hop later.
- **The guard resolves and the fetch resolves again.** `:58` is `gethostbyname` (A records only);
  urllib3's `create_connection` calls `getaddrinfo(..., AF_UNSPEC)`. A public A plus a loopback
  AAAA passes the check and connects internally. And with no address pinned, a plain DNS rebind
  across `:58` and `:227` works too.

Both of those need DNS infrastructure the deliberately-contained lab did not have. They are also
the half of the published advisory that the other credited reporter demonstrated — see
[Outcome](#outcome).

---

## The fix, as shipped

[PR #4420](https://github.com/docling-project/docling/pull/4420), *"fix(html): validate every
resolved address and scope fetch headers to the source origin"*, merged 2026-09-29, released in
`2.132.0` on 2026-10-01. It rewrites `image_resource_loader.py` (+293/−84), adds a fake image
server for tests, and touches the HTML backend, CLI and backend options.

It fixes the class rather than the payload, which is the right call:

- `resolve_public_addresses` resolves the host **once** via
  `socket.getaddrinfo(host, None, AF_UNSPEC, SOCK_STREAM)` and requires **every** returned address
  to be globally routable — IPv4 and IPv6, including IPv4-mapped, 6to4 and NAT64 forms. The
  docstring states the reasoning directly: *"All addresses are validated, since a connection may
  use any of them."*
- The connection pool is then **bound to a validated address**, trying the next validated address
  if one fails. The check and the connection now use the same parsed host and the same resolved
  address.
- Browser rendering no longer makes its own requests — they go through the same loader, and the
  browser itself stays offline.
- Configured headers are scoped to the source origin (that half addresses a separate advisory,
  `GHSA-p3fw-7699-7926`, reported by someone else).

The maintainer's verification, quoted from the closure comment:

> With your payload `http://127.0.0.1:18099\@1.1.1.1/x.png` on 2.132.0, the connection goes to
> `1.1.1.1` and the loopback listener receives nothing.

**Does it cover the class?** Yes, and more completely than my suggested fix would have. I
proposed pinning the validated address; they pinned it *and* closed the resolver-disagreement and
rebinding paths I had only inferred, *and* removed the browser's independent egress. Binding the
pool rather than patching the parse is the correct altitude — it makes the parser differential
irrelevant instead of special-casing a backslash, which is what a backslash-stripping fix would
have done and what I would have been tempted by.

One residual worth noting, flagged in the advisory itself rather than by me: when a proxy is
configured through environment variables, requests go through the proxy, which then resolves and
connects on its own — so the address validation cannot apply. That is an honest limitation of the
design rather than a gap in the fix, and the advisory says so.

---

## Outcome

| Date | Event |
|---|---|
| 2026-09-27 | Confirmed in the lab, 3/3, with controls and the reverse row |
| 2026-09-30 | Reported via GitHub Private Vulnerability Reporting as draft `GHSA-r3j5-hf3x-pc2j` |
| 2026-09-29 | Maintainers merge [#4420](https://github.com/docling-project/docling/pull/4420) |
| 2026-10-01 | Released in `2.132.0`. [`GHSA-pc36-qwjq-x68c`](https://github.com/docling-project/docling/security/advisories/GHSA-pc36-qwjq-x68c) published, 4.0 Medium |
| 2026-10-02 | My draft closed as a duplicate of it, **with credit added and the advisory description extended to cover the backslash parser differential** |

The maintainer's closure, verbatim:

> Thanks for the clear report and the reproduction. We're closing this as a duplicate of
> GHSA-pc36-qwjq-x68c, which tracks bypasses of the same remote-fetch address check, and adding
> you to its credits. Its description now covers the backslash parser differential.
>
> The issue is fixed in docling 2.132.0 by #4420. The loader now connects to an address validated
> from the same parsed host, instead of handing the original string to requests. [...]
>
> The issue has been there since the check was introduced in 2.91.0, so the affected range on
> GHSA-pc36-qwjq-x68c (>= 2.91.0, < 2.132.0) covers it.

**On the duplicate classification: they were right, and it is worth saying why.**

I framed this as a parser differential. They framed the advisory as *"bypasses of the same
remote-fetch address check"* — one defect, several routes through it. Under my framing the
backslash is a distinct bug from DNS rebinding. Under theirs they are the same bug, because the
missing invariant is identical: the check does not constrain the connection. Their framing is
the one that produced a fix covering routes neither reporter had demonstrated, so it was the more
useful abstraction, and the duplicate call follows from it rather than from triage convenience.

My report had in fact *named* the resolver-disagreement and rebinding instances as further cases
of the same missing invariant, while being explicit that I had not demonstrated them. The other
credited reporter had. The merge was the correct outcome: two reporters, two halves of one
defect, one advisory and one fix.

**On the affected range:** I declined to guess it, said the window presumably opened at commit
`d876cbcf` (PR #3725, 2026-07-01) and that the range was theirs to set. They set it at
`>= 2.91.0` — where the check was introduced. Declining to guess cost nothing and the published
record is more accurate than my guess would have been.

No CVE is attached to the advisory. I have not asked for one and do not intend to: the advisory
is published, the range is correct, the credit is recorded, and that is the artifact that matters
to anyone deciding whether to upgrade.

---

## How I found it

By reading the guard's **signature**, not its body.

I was auditing Docling's remote-fetch path and `validate_url_safety` looked, on first read, like a
competent SSRF check — it parses, it resolves, it rejects every non-global range, and the
docstring is accurate about its intent. The thing that stood out was `-> None`. A function that
validates a URL and returns nothing has to be followed by a caller that re-derives the
destination independently, and that re-derivation is where the interesting question lives: *by
the same route?*

Three lines of `grep` established the chokepoint was genuinely single, which made it worth the
time. Then it was a question of whether `urllib.parse` and `urllib3` agree on every input —
and their authority regexes are a known-divergent pair.

Two things that could have gone wrong and inform how I'd run it again:

- **I nearly reported only the resolver disagreement**, which is the more famous bug class
  (rebinding, A-vs-AAAA) and which I found first by reading. It is also the one a maintainer can
  fairly call hard to avoid without a custom resolver, and I could not demonstrate it in a
  network-isolated lab. The backslash was the version that was deterministic, offline and
  reproducible in a container with no DNS at all. **The demonstrable instance of a class is worth
  more than the impressive one** — and in the end the inferred instances did land, through the
  other reporter's evidence rather than my prose.
- **I checked the provenance before framing it.** The guard postdates Docling's 2026-06-02
  advisory burst by a month, so this is not an incomplete fix of a published advisory, and saying
  so pre-empted the first question a triager would ask.

**What the tooling did and did not do.** The harness built the container, drove the five rows,
asserted the socket state, and proved torch was absent so the result could not be blamed on a
different dependency set. It did not find the bug. Reading a type signature did.

---

## Credit and ethics

Thanks to the Docling maintainers for a fix in under 48 hours that was broader than what I
proposed, for extending the advisory description rather than silently folding the report in, and
for adding credit on a duplicate — none of which is obligatory, and all of which makes the next
report to them worth writing. Co-credit to `DavidCarliez`, who demonstrated the half I could only
infer.

All testing was performed in a container with **no network namespace at all** (`--network none`)
against a synthetic listener. No external host was contacted; the payload's public-looking IP
was never dialled. Published after the fix was released and the advisory was public.

---

## Evidence bundle

| File | What it is |
|---|---|
| [`evidence/repro.sh`](evidence/repro.sh) | End-to-end: parser differential, both controls, attack, reverse row, 3× repeat |
| [`evidence/control.http.txt`](evidence/control.http.txt) | Both controls — default-off refusal, and the guard refusing plain loopback |
| [`evidence/attack.http.txt`](evidence/attack.http.txt) | The bypass, and the verbatim request the loopback listener received |
| [`evidence/screenshot-1-control.png`](evidence/screenshot-1-control.png) | The guard refusing, with its own error text |
| [`evidence/screenshot-2-attack.png`](evidence/screenshot-2-attack.png) | The listener receiving the fetch with Docling's own `Range` header |
| [`evidence/repeat.log`](evidence/repeat.log) | Three reproductions, fresh container each time |
| [`evidence/versions.txt`](evidence/versions.txt) | Pinned versions: docling, requests, urllib3, Python; torch-absent assertion |
| [`evidence/lab/`](evidence/lab/) | `Dockerfile` and the synthetic listener |

## References

- [`GHSA-pc36-qwjq-x68c`](https://github.com/docling-project/docling/security/advisories/GHSA-pc36-qwjq-x68c) — the published advisory
- [docling-project/docling#4420](https://github.com/docling-project/docling/pull/4420) — the fix
- [CWE-918: SSRF](https://cwe.mitre.org/data/definitions/918.html) · [CWE-367: TOCTOU](https://cwe.mitre.org/data/definitions/367.html)
- urllib3 authority regex `URI_RE` / `_URI_RE`; CPython `urllib.parse._splitnetloc` and `_hostinfo`
