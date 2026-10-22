# Handoff — Asset Inventory & Scorecard Cycle

**Written:** 2026-10-22 · **Branch:** `feat/asset-inventory` (4 commits, unpushed)
**Base:** `5863222` (`origin/dev`) · **Suite:** 352 passing, `py_compile` clean, `git diff --check` clean

> **Scope of this document.** This is the handoff for the 2026-10-22 cycle only.
> The canonical long-form engineering handoff lives in `cti-radar-improvement.md`
> (gitignored, `/cti-*.md`) and the operator doc in `app/HOW_TO_RUN.md`
> (also gitignored). Read those for history before this file; read this one
> first for what just changed and what will bite you.

---

## 1. TL;DR for the next agent

Four slices landed on top of `dev`, all additive — no existing behaviour was
removed and no stored finding schema changed:

| Commit | Slice |
|---|---|
| `9057699` | Certificate + software/CVE asset inventory (`/api/certificates`, `/api/software`) |
| `f76e69c` | Email/DNS posture: SPF, DMARC, DKIM, DNSSEC, CAA, MTA-STS, takeover (`/api/dns-posture`) |
| `5823976` | Framework/CMS detection **+ fix for HTTP/2 body loss** (`/api/software` enriched) |
| `de91389` | Per-domain A–F scorecard over the above (`/api/scorecard`) |

Suite went **198 → 352**. ~4.2k lines added, ~2.9k of them new modules + tests.

**Nothing is pushed.** All four commits are local on `feat/asset-inventory`.

---

## 2. Read this before you touch the scanner

### 2.1 The HTTP/2 body bug (fixed here — do not reintroduce)

`curl -D - -o -` separates the header block from the body with `CRLF CRLF` on
HTTP/1.1 but a **bare `LF LF` on HTTP/2**. The original code partitioned on
`"\r\n\r\n"` only, so **every HTTP/2 response produced an empty body**.

That silently disabled title capture, `<meta generator>`, body tech
signatures, login-form detection and body-derived version parsing on most of
the modern web. Verified live: `wordpress.org`, `example.com`, `github.com` —
all HTTP/2, all body length 0.

The fix is `_split_headers_body()` and it takes whichever separator appears
first. **If you touch fingerprinting, keep that helper.** Regression tests:
`tests/test_tech_detect.py::test_split_headers_body_*` and
`::test_http2_body_reaches_detection`.

Why the existing tests missed it: they fed synthetic `\r\n\r\n` input. Any new
fingerprint test should include an HTTP/2-shaped fixture.

### 2.2 `unknown` vs `missing` is load-bearing

Three separate bugs in this cycle came from collapsing "the lookup failed" into
"the record is absent":

- `dns_posture._query` returns `None` on failure and `[]` on NoAnswer. Callers
  must preserve the difference. `None` → `unknown` verdict, excluded from
  scoring, **never** a finding.
- `tech_detect` DKIM-style probes use `None` (not `False`) for "could not
  determine".
- `scorecard` distinguishes "fingerprinted hosts, no versioned software"
  (`assessed=True`) from "no host was ever fingerprinted" (`assessed=False`).

If you add a data source, decide explicitly which of the three states it can
produce. A resolver outage must never read as a finding, and an unexamined
pillar must never score as clean.

### 2.3 TXT records longer than 255 bytes

Most real SPF policies span several TXT character-strings and stringify as
`'"part1" "part2"'`. Naive quote-stripping corrupts them (GitHub's SPF parsed
as `ip4:62.253.2" "27.114`). `dns_posture._txt_values` extracts quoted chunks
and concatenates **without** stripping inter-chunk whitespace. Test:
`test_txt_values_joins_quoted_chunks`.

### 2.4 Legacy `tech` labels are still noisy (NOT fixed)

`_TECH_SIGNATURES` in `scanner.py` matches loose substrings and still reports
**"f5 big-ip"** and **"vmware horizon"** on `wordpress.org`. The new
`tech_detect` module is precise and is the one wired into the inventory and CVE
matching, but the legacy label list still feeds the AI triage prompt
(`_select_ai_hosts`, prompt enrichment) and the `tech` field in fingerprints.
Cleaning that up is a contained, worthwhile follow-up — see §6.

---

## 3. Architecture of what was added

```
app/tech_detect.py    pure: detect(html, headers, generator, cookies) -> detections
                      source of truth for framework/CMS identity + versions

app/dns_posture.py    pure analysis (analyze_spf/dmarc/caa/dnssec, evaluate_domain)
                    + bounded gather() using dnspython; assess() = gather+evaluate

app/scorecard.py      pure: build(domains, meta, rows...) -> per-domain cards

app/cti_correlation.py  read layer: certificates() / software() / dns_posture()
                        / scorecard() — all join against scan meta
app/main.py             four GET endpoints, all auth-gated
app/dashboard.html      four panels (Certificates, Software & CVEs,
                        Email & DNS posture, Security scorecard)
```

All three new modules are **pure where it matters**: the judgement is a function
of already-captured data, so it is unit-testable offline. Only
`dns_posture.gather()` does network I/O.

### Where data persists

Scan meta (`findings.json` → `meta`) gained exactly two keys:

- `meta.certificates` — `{host: {port, issuer_cn, issuer_org, subject_cn,
  not_before, not_after, days_left, expired, expiring_soon, self_signed,
  hostname_ok, chain_trusted, chain_error, san_count, sans, key_bits}}`
- `meta.dns_posture` — list of `evaluate_domain()` verdicts

Software/framework data rides on the pre-existing `meta.fingerprints[host]` via
two added keys: `versions` (pre-existing shape, now includes framework
versions) and `tech_detail` (the detection list with kind/confidence/source).

`meta.fingerprints` is **already persisted** — nothing new was needed for the
grade to survive a restart.

---

## 4. Scoring model — the parts that were wrong first time

`app/scorecard.py`. Pillars sum to 100:

```
vulnerability  40   CVE-bearing software, attributed PER PRODUCT
certificates   25   expired / expiring / mismatch / untrusted / self-signed
email_dns      25   reuses dns_posture's 0-100 score (never re-derives it)
exposed        10   high-risk ports (RDP, SMB, Redis, Mongo, MySQL, ...)
```

Three rules, each of which I got wrong on the first pass:

1. **Unknown is not good.** Excluding a missing pillar from the average is
   correct (an outage must not read as a finding) but it let a barely-examined
   domain score 100/A. Now: coverage is tracked, the grade is capped when
   coverage < 100, and a card under 30% coverage reports `?`.
2. **Critical exposure caps the grade.** A CRITICAL CVE caps the score at 60.
   Clean certificates and DMARC must not launder an exploitable host into a B.
3. **No double counting.** A host is attributed to exactly one registered
   domain, so registering both `example.com` and `www.example.com` does not
   score the same host twice.

Also: `summarize()` derives the header grade conservatively so it can never
exceed the cards beneath it. There is a test for exactly that
(`test_header_grade_never_exceeds_card_grade`).

**Tuning lives in `scorecard.py`** — `WEIGHTS`, `HIGH_RISK_PORTS`,
`_CVE_POINTS`, `_CERT_POINTS`. Nothing is env-configurable on purpose: a
rating that changes with an env var is not reproducible.

---

## 5. Verification

```bash
cd cti-dashboard
. .venv/bin/activate
python -m pytest tests/ -q          # 352 passed
python -m py_compile app/*.py
node -e "..."                       # dashboard.html inline JS syntax check
```

`node --check` on a written temp file is blocked by the Mimosa hook; the
working approach is to read `dashboard.html` in node and `new vm.Script(...)`
the inline block (see the command in §7).

**Live checks performed this cycle** (worth repeating after changes):

- `scanner._tls_cert()` against `example.com`, `self-signed.badssl.com`,
  `expired.badssl.com` → correct issuer, days, self-signed, chain-trust.
- `scanner._fetch_fingerprint()` against `jquery.com` → jQuery 4.0.0 + WordPress 7.1.
- `dns_posture.assess()` against `google.com`, `example.com`, `github.com`.
- Full `generate_org` with mocked enum/probe but **real** TLS + real DNS.
- dnspython-absent simulation (block the import for a whole scan): 0 findings,
  grade `?`, scan completes.
- Rescan: DNS findings dedupe by `identity_key`, no duplicates.

---

## 6. Open items, in priority order

1. **Clean up legacy `_TECH_SIGNATURES`** (see §2.4). Replace the loose
   substring list with `tech_detect`, or at minimum drop the
   `F5|BIG-IP` and `horizon|view client|blast` patterns that false-positive on
   ordinary marketing pages. This pollutes the AI prompt today.
2. **Scorecard in the PDF report.** `exports.py` renders findings only; the
   scorecard is dashboard-only, so it cannot currently be sent to a manager.
   This is the single highest-value addition for "executive reporting".
3. **Score history / trend.** Each scan scores afresh and the previous card is
   not retained. `cti_correlation.append_history` already writes per-scan
   events — appending the org rollup there would give "continuous monitoring"
   and a trend line without a new store.
4. **Feed `risk.py` P1–P4 bands into the exposed pillar.** Your preserved
   local branch (`local-work-20261022`) has `risk.py` with KEV/EPSS-driven
   scoring that is not on `dev`. Merging it would let the scorecard weight
   findings by actual exploitation likelihood.
5. **Certificate gaps** — no revocation check (OCSP/CRL), no signature-algorithm
   or key-size grading, no comparison against CT-log issuance.
6. **SBOM ingestion** — the software side is banner/markup-based and cannot see
   dependencies inside an app bundle. Deliberately out of scope so far.

---

## 7. Verification command for the dashboard JS

```bash
node -e "
const fs=require('fs'),vm=require('vm');
const src=fs.readFileSync('app/dashboard.html','utf8');
const b=[...src.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/g)][0][1];
new vm.Script(b); console.log('JS OK');
"
```

Writing the extracted JS to a temp file via Bash is refused by the Mimosa hook
("直接写源码/安全配置会绕过 Write/Edit 安全扫描"). Use the read-and-compile form
above instead.

---

## 8. Env tunables added

| Variable | Default | Effect |
|---|---|---|
| `CTI_CERT_EXPIRY_WARN_DAYS` | 30 | window for "expiring soon" findings |
| `CTI_CERT_SAN_CAP` | 50 | SANs stored per certificate |
| `CTI_MAX_CERT_FINDINGS` | 100 | cert findings emitted per scan |
| `CTI_DNS_POSTURE` | 1 | set 0 to disable the whole DNS stage |
| `CTI_DNS_MAX_DOMAINS` | 10 | domains assessed per scan |
| `CTI_DNS_TAKEOVER_HOSTS` | 25 | CNAME probes per scan |
| `CTI_TECH_DETECT_CAP` | 16 | detections kept per host |

New dependency: **`dnspython==2.9.0`** (needed for TXT/DMARC/DKIM/DNSSEC/CAA).
Imported lazily — without it the DNS stage degrades to `unknown` and everything
else works. This is asserted by a test.

---

## 9. Worktree / branch state

- `feat/asset-inventory` — this cycle, 4 commits ahead of `origin/dev`, unpushed.
- `local-work-20261022` (tag) / `local/pre-remote-sync-20261022` (branch) —
  **preserved work from before the remote sync**: 4,054 uncommitted lines plus
  modules that exist on **no remote** (`risk.py`, `threat_intel.py`, `audit.py`,
  `authz.py`, `exports.py`, 9 extra test modules). Do not delete these refs.
- `origin/main` is now a **Rust rewrite** (`rust/src/*.rs`, nuclei runner).
  `origin/dev` is still the Python integration branch this work is based on.
  **Decide the Python-vs-Rust direction before starting anything large.**
- `.mimosa/` is agent hook state and is gitignored — never commit it.

Per the project workflow: `main` = stable (squash-merged PRs only), `dev` =
integration, `feat/<slice>` per slice. Never commit directly on `main`.

---

## 10. What this scorecard is and is not

Also documented in README §"What this scorecard is and is not". Repeated here
because it is the thing most likely to be over-claimed downstream:

**It is** a deterministic, itemized, externally-evidenced rating for domains you
own. Useful for: which of my domains is worst, did it improve, what do I fix
first, what is my supply-chain surface.

**It is not** a SecurityScorecard/BitSight equivalent. Specifically absent:

- **No peer benchmarking population.** Commercial ratings are calibrated
  against millions of companies; this is scored against a fixed rubric. **An A
  here is not comparable to an A there.**
- No internal telemetry (agents, EDR, SIEM) — nothing inside the network.
- No questionnaire-based vendor/TPRM assessment (self-attested controls,
  contracts, certifications).
- No compliance control mapping (SOC 2 / ISO 27001 / PCI DSS).
- No real-time alerting, incident response, or general threat feeds beyond
  KEV + EPSS.

Do not describe this as a SecurityScorecard alternative in any external-facing
material without those caveats.
