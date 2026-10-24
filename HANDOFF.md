# Handoff — Asset Inventory & Scorecard Cycle

## Accuracy: verified ports, service classification, confidence (2026-10-25)

- **What "open" means now:** `scanner._verify_services` runs after the banner
  grab. A port is *confirmed* when its greeting identifies the protocol
  (`_identify_protocol`), *plausible* when it accepts silently on a protocol
  that does not greet first, and *unconfirmed* when a greet-first protocol
  (FTP, SSH, POP3, IMAP, MySQL, VNC) stays silent. A host with at least
  `CTI_BLANKET_CANARY_MIN` (4) plausible ports gets three canary connects to
  unused high ports; if two or more accept, it is a "blanket" host and its
  plausible ports become unconfirmed. `meta.services[h].open` keeps confirmed
  and plausible ports only, so ratings and findings ignore the artifacts;
  `unconfirmed`, `port_confidence` and `blanket` record the rest.
- **Why:** on a real org, port 21 was "open" on 416 hosts but greeted on 2,
  and one host answered all 22 probed ports. That produced hundreds of
  service findings, "Database service exposed on TCP 21" titles, and an AI
  finding judging ports that were never open.
- **Classification:** `_classify_service` maps the observed service to
  category, title, severity and fix (severities match the rating model's
  high-risk ports). The hostname keyword table (`_classify_infra`) is now a
  hint stored as `evidence.name_hint`; it sets nothing. Web findings use the
  page itself (`_admin_product`); login severity uses the page title.
- **Stored findings:** `_apply_accuracy_rules` (before reconciliation) marks
  OPEN findings on unconfirmed ports, AI findings on blanket hosts, and
  protocol-only "versions" (HTTP/1.1) as `FALSE_POSITIVE` (`fp_by: scanner`,
  `fp_reason`), and reclassifies hostname-classified records once
  (`classified_by: service`; AI-graded severity kept). A scanner false
  positive reopens if a later scan verifies the same port; an analyst's
  (`fp_by: analyst`, settable in the status editor) is final.
- **Confidence:** `cc.finding_confidence(f)` gives every finding a level and
  reason (stamped by the scanner where it has direct evidence, else by
  source). It is on the list projection, the detail view and the card tag.
- `posture.MODEL_VERSION = 5`: trends do not compare across the change.
- Dry run on the real org's stored data: verified ports 657 → 238, 543
  findings retired (438 service, 105 version), open findings 944 → 401. The
  one 21-port host needs the live canary check, so rescan to finish.

## Public data and docs (2026-10-23, late)

- **Real data removed from the public repo:** `data/orgs.json` on `main` had
  two real client orgs (one with OpenHack enabled) since commit `8e16865`.
  Restored to the sample org via the existing unmerged fix (`75063e9`) and
  guarded by `tests/test_public_repo_data.py` (tracked registries may only
  use reserved example domains; scan output must stay ignored). The names
  remain in git history; rewriting it is the owner's call.
- **Docs:** README gained a dark hero screenshot, a Python quick start with a
  persistent `CTI_DATA_DIR`, env rows for the Python-only features, and a
  Screens gallery (`screenshots/parallax-*.png`, fictional `acme.example`
  demo, 256-colour PNGs). The old CTI Radar JPEGs were removed.

## Merge of origin/main (2026-10-23)

`feat/parallax-platform` merges `origin/main` (Rust rewrite, AI-config CRUD,
passive/Nuclei vuln lookup, benchmarks). Conflicts and how they were settled:
- `app/dashboard.html`: the new UI wins; main's features were ported into it
  (Workspace → Vulnerability lookup with one engine select and one button,
  fixing main's duplicate `vulnengine` id; AI assistant → Custom models for
  the profile editor; GLM 5.3 Flash as the OpenHack default). Main's login
  `value="admin"` was dropped on purpose (see the login follow-up below).
- `README.md`: Parallax intro plus a "Two backends" note. **The posture
  features (ratings, hosts, planner, packages, live CVEs, AI assistant,
  portfolio) exist only in the Python backend.** The Rust binary embeds this
  dashboard; on a backend without `/api/posture` the overview says so instead
  of loading forever. Porting them to Rust is open work.
- `data/ai_config.example.json`: main's `cline` example kept (OpenCode is now a
  built-in preset). `.gitignore`: both sides' additions kept.
- `app/cve_data.json` is also embedded by Rust; its parser is lenient JSON, so
  MEDIUM severities, `null` fix versions and the new `withdrawn` key are safe
  (checked by reading `rust/src/cve_match.rs`; no Rust toolchain here to build).
Validation after the merge: 569 Python tests (including main's AI-config,
Nuclei and vuln-scan suites), dashboard JS checks, and both merged views in a
browser.

## Follow-up: host ratings and two false positives (2026-10-23, evening)

Triggered by an assistant transcript on a real org: it could not name the
weakest subdomain, and its leadership summary leaned on false criticals.

- **Withdrawn advisory:** CVE-2023-38408 (ssh-agent PKCS#11, client-side) is
  removed from server-banner matching and recorded in `cve_data.json`
  `withdrawn` with reason and source. `cve_match.withdrawn_ids()` feeds the
  inventory's historical-finding filter, so old findings cannot resurrect it.
  It had put every OpenSSH 5.5–9.3 host under the critical cap.
- **HTTPS false positive:** the fingerprint curl lacked `--insecure`, so a host
  with an expired/mismatched/self-signed certificate fell back to HTTP and
  scored "served without HTTPS" on top of its certificate deductions. The
  fetch now uses `--insecure` (observation only; `_tls_cert` judges validity),
  and scoring ignores `no-https` for any host with a captured certificate
  (`tls_seen`), which corrects existing scans without a rescan.
- **Host ratings:** `scorecard.build_hosts` scores each observed host with the
  same model (own evidence + its domain's DNS verdict; takeovers only on their
  own host). Order: critical exposure, then score; unrated hosts last and with
  `score: None`. `cc.hosts()`, `GET /api/hosts`, Assets → Hosts, Overview →
  Weakest hosts.
- **Assistant:** `hosts`/`host` tools and `weakest_hosts` in context; prompt
  now asks for plain-language leadership summaries backed by `plan`, calls
  CVE matches "version matches to verify", and forbids "data unavailable"
  before trying the relevant tool. Citations carry readable labels.
- `posture.MODEL_VERSION = 4`. Live-verified with Codex gpt-6.1-sol on demo
  data: the weakest-subdomain question is answered from host scores in one
  step; the leadership summary quotes the planner's projection.

Validation: **546 Python tests passed**, `node tests/test_dashboard_state.js`
passes, JS compiles, all referenced element IDs exist, and the Hosts view was
checked in a browser.

## Local login follow-up (2026-10-23)

Removed the hardcoded `cti_admin` username from the login form: the local
launcher uses `admin`, so the default was misleading. Login now suppresses
duplicate in-flight submissions and displays the server's retry duration.
The rate limiter's Retry-After includes the actual remaining failure window
instead of repeatedly suggesting a retry before the IP unlocks. Validation:
25 focused auth/correctness tests, dashboard state checks, and compilation
pass. A server restart clears existing in-memory login lockouts.

## Follow-up: organization names and rating integrity (2026-10-23)

Current working-tree additions, on top of the platform work described below:

- **Rename organization:** the selector's Rename link opens Workspace & scans
  → Organization → Display name. `PATCH /api/orgs/{slug}` validates a nonblank
  name (maximum 200 characters, no control characters), requires authentication,
  and atomically updates only the name under the registry lock. Names update in
  the selector, portfolio and reports; identity, domains and data paths stay
  stable. The UI handles failures and switching organizations during a save.
- **Rating model v3:** an unprobed domain's service factor is unknown even if
  another domain has service observations. Comparison scope includes usable
  web responses and which pages actually had asset capture, so a lost page
  observation cannot be credited as verified improvement.
- **Honest trends:** overview charts break their lines when assessed domains
  or coverage change, including gaps with no assessed domains. Portfolio
  sparklines show only the latest comparable segment. Existing v1/v2 scores
  remain in history but are excluded from v3 trend comparisons.
- **Advisory correction:** CVE-2023-26116 applies to AngularJS through 1.8.3,
  with CVSS 5.3/MEDIUM, an angular.copy() ReDoS description and no listed fixed
  version. Modern Angular no longer matches it. Source is recorded in
  `app/cve_data.json`. Matching/synthesis now preserve moderate severities.
  Current inventory also rejects historical finding CVEs contradicted by the
  current bundled map, so old false matches cannot repopulate the posture.
  Stored historical findings are retained.

Validation: **527 Python tests passed** with the installed uvloop policy;
Python compilation, `git diff --check`, and
`node tests/test_dashboard_state.js` pass. The JS check covers inline script
syntax, asynchronous rename state and segmented trend markup. The user's
`127.0.0.1:8766` instance was not reachable from this execution environment;
API integration tests use FastAPI TestClient and isolated temporary registries.
Reload/restart the serving backend to pick up the Python changes and refresh
the browser for the new UI. No live organization was renamed during testing.

## Follow-up: external posture platform (2026-10-23, working-tree changes)

**Product name: Parallax** (formerly CTI Radar), applied to everything users
see: page title, sidebar, login, PWA manifest and icons, report header,
FastAPI title, README/DEPLOYMENT, CycloneDX tool name and `parallax:`
property prefix. Deliberately unchanged: `cti-radar` data/config paths,
`CTI_*` env vars, `ctiRadar*` localStorage keys, the `cti-dashboard.service`
unit name and the AI-provider user agent, so existing installs keep working.

Goal from the owner: an outside-in overview of posture plus detail on
externally visible vulnerable packages, comparable to commercial rating
platforms, **without "scorecard" naming in anything user-facing** (code
module names are unchanged; `/api/scorecard` stays as an alias of
`/api/posture`).

- **Rating model v2** (`app/scorecard.py`, `posture.MODEL_VERSION = 2`): seven
  factors scored 0–100 each and weighted (vulnerability 25, exposed 20,
  certificates 15, email_dns 15, application 10, dependencies 10,
  disclosure 5). New factors read data already in `meta.fingerprints`
  (headers, cookies, assets). Every deduction has a `type` in `ISSUE_TYPES`
  (title, severity, why, fix). `gain` = exact re-score without the item
  (`exclude=`), so caps and budgets are honoured. Critical cap (60) now also
  applies to `dep-compromised` and `dns-takeover`; a takeover is always listed
  even when it costs no extra DNS points. KEV-listed CVEs become `vuln-kev`
  (ranked urgent, ≥24 factor points, no cap unless CVSS is critical).
- **DNS attribution** uses `dns_posture.CHECK_WEIGHTS`/`check_credit` (extracted
  from `_grade`, behaviour unchanged) so per-check deductions sum exactly to the
  points lost, and projections call `dns_posture._grade` on fixed checks.
- **Dependency checker** (`app/dependencies.py`, pure): scanner stores
  `snippet["assets"]` (present only when a 2xx document was examined; `[]` =
  looked, none). Query strings are dropped before storage. Read layer
  `cc.dependencies_from_meta` → packages (with CVEs, fix version, EOL, KEV),
  third-party origins, providers (from new raw `records` in DNS verdicts: MX,
  NS, TXT, all CNAME targets). Drift: `cc.dependency_snapshot` is recorded on
  scan events; `dependency_changes` compares only pages examined in both scans.
  CycloneDX 1.5 export declares `compositions: incomplete`.
- **Live CVEs** (`app/live_cve.py`): opt-in `CTI_CVE_NOW=1`. Scan-time only;
  stored at `meta.live_cves` (scan-owned key, set to None when off so stale
  intel never outlives its snapshot). Live CVSS overrides the vendored map in
  `_cve_severity_map(meta)`. `POST /api/orgs/{slug}/live-cves` re-captures for
  the current snapshot under the org job slot and refuses if a newer scan
  landed meanwhile. cve.now API facts verified 2026-10-23: `/stack?p=npm:a@1,
  npm:b@2&format=json` (entries carry `matched`), `/api/v1/entries/<id>`;
  `exploitation.kev = {dateAdded, dueDate}`; no key, no documented rate limit.
- **New routes**: `/api/posture`, `/api/posture/plan?fix=`, `/api/portfolio`,
  `/api/dependencies`, `/api/dependencies/cyclonedx`, `POST …/live-cves`.
- **UI revamp** (`app/dashboard.html`): app shell with sidebar and hash-routed
  views (`#/overview`, `#/packages`, `#/issues`, `#/assets`, `#/findings`,
  `#/graph`, `#/portfolio`, `#/activity`, `#/workspace`); plain anchors such
  as `#cert-section` open the view that holds them. Light and dark themes
  (OS default, toggle stored in `localStorage.ctiTheme`). All pre-existing
  element IDs used by the JS were kept; the old collapse toggles and mobile
  nav were removed. Charts are hand-written SVG (no new dependencies; CSP
  unchanged).

Traps:
- `posture._GUIDANCE` must have an entry for every factor in `WEIGHTS`
  (`test_every_factor_has_action_guidance`); a missing one crashed the posture
  API for any org with a deduction in that factor.
- Scans from before asset capture leave *Web dependencies* unknown, which caps
  the grade at C until rescanned. That is intended (unknown is not clean).
- The vendored map rates CVE-2020-11022 HIGH and maps `angular` versions
  `<16.2.0` to CVE-2023-26116, which is an AngularJS (1.x) CVE. Live data
  corrects the first; the second is a false positive for Angular 2+ and is
  not fixed here.
- Headless Chrome on Windows has a ~500px minimum window width; phone-layout
  screenshots taken narrower are cropped, not broken.

Validation: **507 tests passed**; inline JS compiles (§7 method); every view
rendered in light, dark and 504px-wide layouts through a token-adding preview
proxy against generated demo data, including planner selection and package
expansion; a live end-to-end fetch against cve.now succeeded.

**AI assistant** (`app/assistant.py`, view `#/assistant`): read-only agent
loop (≤5 steps) where the model replies with one JSON object, either a tool
request (`plan`, `issue`, `domain`, `package`, `findings`, `history`,
`providers`) or an answer with `cites`, which `_verify` checks against the
org's data. Providers (`ai_providers.PRESETS`): OpenCode Go
(`/inference/go/openai/v1`), OpenCode Zen (`/inference/openai/v1`), DeepSeek
(`api.deepseek.com`), and Codex via `codex exec` (`codex-cli` provider:
read-only sandbox, `--ephemeral --ignore-user-config --ignore-rules`, empty
scratch dir, server secrets stripped from its env). GLM Coding Plan was
dropped at the owner's request (Z.ai limits that plan to supported coding
tools). Verified live 2026-10-23 with the server user's ChatGPT sign-in:
`gpt-6.1-sol` (default) and `gpt-6-luna` both answer; a full agent run on
demo data used the planner and returned only verified citations. Tests use
a fake `codex` binary (`CTI_CODEX_BIN` in conftest) and never spend quota.
OpenCode serves GPT/Claude models only on Responses/Messages endpoints,
which this client does not speak yet.

Open next: port KEV/EPSS-weighted risk from `risk.py`; alerting on drift and
rating drops; scheduled rescans; compliance mapping only with verified
control IDs.

## Follow-up: posture workflow (2026-10-22, working-tree changes)

The current uncommitted follow-up adds:

- **Your next moves** in the scorecard: prioritized, deterministic actions
  from scored deductions and separate assessment-gap actions. Evidence links
  open the relevant inventory panel. These are not an exhaustive backlog.
- **Score history**: `scanner.record_scan_event()` saves a compact `posture`
  object on scan events, using the exact findings/meta snapshot already read.
  `app/posture.py` produces actions, versioned snapshots and comparisons.
  The API returns `actions` and `progress`; GET requests never write history.
  Comparison requires matching observed hosts, versioned product identities,
  assessed DNS controls, pillar coverage and scoring version. Missing evidence
  never counts as an improvement. The last eight scans are displayed; older
  ledger records are retained. No retroactive scores are invented.
- **Executive reporting**: the report begins with ratings, coverage, changes,
  ten next actions and pillar evidence. An auth-gated `report.html` route and
  **Executive brief** button work without Chromium. `report.pdf` now actually
  falls back to HTML when Chromium is absent (previously it returned 503).
- **Rating corrections**: critical CVEs are prioritized before the deduction
  budget is exhausted; the cap checks all product rows. Critical exposure is
  counted even when the score was already below the cap. A D grade limited by
  coverage no longer becomes C in the header.
- **Detection precision**: F5 and VMware Horizon legacy signatures require
  appliance-specific markup/text, not `F5`, `horizon`, or `blast` anywhere.

Tests are in `tests/test_posture_brief.py`. The existing provider URL test now
uses deterministic DNS and also checks resolver failure, avoiding its former
dependence on internet DNS. In this sandbox, the default asyncio loop hangs
even for an empty FastAPI TestClient app; run pytest with the installed uvloop
policy if needed. Validation: **369 tests passed**, Python compilation,
dashboard JavaScript syntax/rendering smoke checks and `git diff --check` pass.
Browser visual/PDF checks require a runnable Chromium;
the installed Snap launcher cannot write its runtime directories here.

When changing scoring semantics or comparison scope, increment
`posture.MODEL_VERSION` so historical scores are not silently compared under
different rubrics. The original handoff below describes the preceding commits.

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
