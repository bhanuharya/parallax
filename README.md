# Parallax — External Posture & Dependency Intelligence

**See your attack surface the way the internet does.** Parallax is a
self-hosted tool that rates the external security posture of the domains you
own and shows, in detail, which vulnerable packages and third-party
dependencies anyone can see from outside. It **scans domains passively**
(deterministic or AI-assisted), turns the evidence into an itemized **A–F
rating** with an exact what-if planner, inventories **packages, script origins
and service providers** with live CVE intel, **tracks findings** through a
mitigation lifecycle, builds a **correlation graph** (host ↔ IP ↔ CVE ↔ brand),
and exports executive reports and CycloneDX. All local, auth-gated, PII-masked,
and $0.

Built as a FastAPI backend and a single-file frontend (no build step, no
external assets, light and dark themes). It is **multi-tenant by org**:
register any workspace (a domain you own or are authorized to assess), scan
it, and compare organizations side by side.

> **Formerly CTI Radar.** Runtime paths (`~/.config/cti-radar`, `~/.local/share/cti-radar`),
> `CTI_*` environment variables and the systemd unit name are unchanged, so
> existing installs keep working.

> **Onboarding an agent or engineer?** Read [HANDOFF.md](HANDOFF.md) — current
> cycle state, the scanner traps that will bite you, and the open backlog.

> **Intended use:** authorized security teams assessing **their own** external
> footprint. Scanning is **passive / non-intrusive by default** (certificate
> transparency — crt.name / crt.sh / certspotter / hackertarget — plus DNS
> resolution, HTTP header probe, a TCP connect scan of common service ports, and
> InternetDB enrichment). Use it only on infrastructure you own or are explicitly
> authorized to test.

---

## Features

- **Organization names** — use **Rename** beside the organization selector,
  or **Workspace & scans → Organization → Display name → Save name**.
  Names are saved across restarts and used in the selector, portfolio and
  reports. The organization id, domains and scan history are preserved.
  API clients can send `PATCH /api/orgs/{slug}` with `{"name":"New name"}`
  using the same authentication as other workspace changes.

- **Comparable rating history** — rating model v3 treats services as unknown
  for domains with no probe evidence and tracks which pages had asset capture.
  Trend lines break when observation coverage or the assessed domain population
  changes; portfolio sparklines show the most recent comparable segment.
  Older model scores remain in the ledger but are not compared to v3 scores.

- **Multi-org / workspaces** — register any org (slug-validated), per-org data stays
  in `data/orgs/<slug>/`.
- **Dual-mode scanning** — `fast` (deterministic, $0) or `ai` (after deterministic
  capture, an optional LLM triages only the interesting hosts into `AI-ASSESSED`
  findings, then re-grades existing findings' severity/impact). AI never fails a
  scan; it degrades to the deterministic result.
- **OpenHack active assessment (separate from passive CTI scans)** — the
  `/openhack-scan` endpoint is fail-closed behind a server-level operator gate,
  exact target allowlist, and time-bounded ROE.
- **Passive service discovery** — for each resolved host/IP the scanner performs a
  TCP connect scan of common service ports (ssh, rdp, mysql, …), surfacing exposed
  services without payloads or banner grabbing.
- **Six passive enumeration sources** — certificate transparency (crt.name /
  crt.sh / certspotter) plus hackertarget, **Wayback Machine CDX** and
  **AlienVault OTX passive DNS**, so hosts that never had a TLS certificate are
  still found. **Wildcard-DNS filtering** drops names that only echo a `*.` record.
- **Offline version→CVE matching** — software versions parsed from headers,
  titles and service banners (SSH/FTP/SMTP/MySQL) are matched against a vendored
  high-impact CVE map (`app/cve_data.json`, 33 products / 59 CVEs). Matches are
  tiered **CORRELATED** with an explicit verify caveat and confidence
  (LOW/MED) badges — deterministic, offline, $0. Optional **NVD 2.0
  enrichment** (`CTI_NVD_ENRICH=1`) adds official CVSS score/vector,
  disk-cached and fail-open.
- **Security-header findings** — missing HSTS/CSP/X-Frame-Options/
  X-Content-Type-Options on reachable hosts (HSTS/CSP only expected on HTTPS;
  auth surfaces bumped to MEDIUM).
- **New-exposure diffing** — every scan is diffed against the previous scan's
  baseline: newly resolved hosts and newly open service ports become
  CONFIRMED findings, so attack-surface growth is tracked over time. A
  dashboard quick-filter isolates them.
- **Certificate inventory** — every HTTPS host's certificate is captured via a
  stdlib handshake (no payload) and stored in scan meta, so healthy certs are
  browsable, not just broken ones. Records subject/issuer, notBefore/notAfter,
  days remaining, SAN list, key size, and three independent verdicts:
  hostname match (RFC 6125 exact/wildcard/IP-SAN), chain trust against the
  system store, and self-signed. Expired, **expiring within 30 days**
  (`CTI_CERT_EXPIRY_WARN_DAYS`), hostname-mismatched, self-signed and
  untrusted-chain certs each become deterministic findings. Served by
  `GET /api/certificates` and the dashboard **Certificates** panel.
- **Software inventory** — disclosed product/version pairs per host, joined
  with matched CVEs, served by `GET /api/software` and the dashboard
  **Software & CVEs** panel. The inventory re-runs the offline CVE map itself,
  so a vulnerable version is flagged even when no finding was synthesized for
  it. CVEs are attributed **per product**, not per host, so a page running
  WordPress + jQuery + Bootstrap shows each component's own CVEs.
- **Framework & CMS detection** — `app/tech_detect.py` identifies the
  application stack, not just the web server, using only evidence a normal
  visitor receives: the `<meta name="generator">` tag (WordPress/Drupal/Joomla
  with versions), version-bearing asset paths (`jquery-3.6.0.min.js`,
  `bootstrap-5.3.0.min.css`, `ng-version="17.0.0"`), framework headers
  (`X-AspNet-Version`, `X-Drupal-Cache`, `X-Nextjs-Cache`) and session cookie
  names (`laravel_session`, `csrftoken`, `PHPSESSID`). Versioned detections
  feed CVE matching; identity-only detections (e.g. Next.js with no version in
  the markup) are inventory-only and are **never** CVE-matched, because a
  product name without a version cannot be matched to an affected range. Each
  row carries a kind (`cms`, `js-framework`, `server-framework`, …) and a
  confidence, and the UI distinguishes "no version" from a version.
- **External posture rating** — a per-domain A–F rating over seven risk
  factors, each scored 0–100 on its own and weighted into the total:

  | Factor | Weight | Evidence |
  |---|---|---|
  | Vulnerability exposure | 25 | CVE-bearing software and packages, per product |
  | Exposed services | 20 | high-risk ports (RDP, SMB, databases, caches, Docker API) |
  | Certificate hygiene | 15 | expired, mismatched, untrusted, self-signed, expiring |
  | Email & DNS posture | 15 | the DNS posture score below, attributed per check |
  | Application security | 10 | HTTPS, HSTS, CSP, clickjacking, nosniff, cookie flags |
  | Web dependencies | 10 | compromised CDNs, end-of-life libraries, mixed content, unpinned or unverified CDN assets |
  | Information disclosure | 5 | versions in `Server`, `X-Powered-By`, `X-AspNet-Version`, generator tags |

  Every deduction is itemized (`{code, type, label, points, detail}`) and
  belongs to a catalogued **issue type** with severity, why it matters and how
  to fix it, so the number is reproducible rather than an opinion. Each card
  reports its **coverage** and confidence.

  The rules that keep the rating honest:
  - **Unknown is not good.** A factor with no data is excluded from the
    average (an outage must not read as a finding), but the resulting grade is
    capped, because partial evidence cannot support a top score. A card below
    30% coverage reports `?` rather than a number.
  - **Critical exposure caps the rating at 60.** A critical CVE match, a page
    loading a compromised CDN, or a subdomain open to takeover cannot be
    laundered into a B by clean hygiene elsewhere. CVEs on CISA's Known
    Exploited list rank first in every action list.
  - **No double counting.** A host is attributed to exactly one registered
    domain, and CVEs in front-end packages are scored once, in the
    vulnerability factor.
  - **Exact projections.** The "gain" shown for an issue is computed by
    re-running the model without it, so caps and budgets are honoured: fixing
    one of two critical CVEs gains nothing while the other still holds the cap.

  Served by `GET /api/posture` (`/api/scorecard` remains as an alias). Weights,
  deduction tables and the issue catalog live in `app/scorecard.py`.

- **Host (subdomain) ratings** — every observed host is scored by the same
  model as its domain, from its own evidence plus its domain's email & DNS
  posture (a dangling-CNAME takeover stays on the host it was found on).
  Hosts with critical exposure are listed first, then weakest score; hosts
  with too little evidence are marked unrated rather than given a number.
  Served by `GET /api/hosts` and the **Hosts** table in Assets.

- **Issues & planner** — every deduction grouped by issue type with the
  org-wide rating gain of fixing it. Select issues and `GET /api/posture/plan?fix=`
  returns the projected rating per domain and for the org, from the same
  snapshot and model. **Next moves** turns deductions into concrete steps;
  missing evidence gets an **Assess** action. Gains are projections under the
  current model, not promises.

- **Packages & dependencies (outside-in dependency checker)** — what a site
  depends on, as any visitor can see it, read from the homepage markup the
  scan already downloads (no extra requests for assets):
  - **Packages**: server software and frameworks from banners and markup,
    front-end libraries from every `<script>`/stylesheet (cdnjs, jsDelivr,
    unpkg, Google Hosted Libraries, code.jquery.com, BootstrapCDN, known
    library file names, WordPress `?ver=` assets), and WordPress plugins and
    themes. Each package version carries its matched CVEs with severity, CVSS,
    fixed version, CISA KEV status and source, plus the exact URL or header it
    was seen in, and end-of-life status (AngularJS, jQuery 1–2, Bootstrap ≤4,
    Vue 2).
  - **Third-party script origins** with Subresource Integrity coverage, and
    known-compromised CDN hosts (polyfill.io and related domains).
  - **Service providers** a domain relies on, from MX, NS, SPF includes,
    verification TXT records, CNAME targets and script origins.
  - **Drift**: a new third-party script origin, package or version on a page
    examined in both the previous and the current scan, which is the
    externally visible signature of script injection. First looks and pages
    that failed to load are never reported as drift.
  - **CycloneDX 1.5 export** of the observed components and vulnerabilities
    (`GET /api/dependencies/cyclonedx`), declared `incomplete` because an
    outside-in view is not an application SBOM.

  Served by `GET /api/dependencies`. Query strings are dropped from stored
  asset URLs (they can carry API keys).

- **Live CVE advisories (cve.now, opt-in)** — with `CTI_CVE_NOW=1`, each scan
  asks [cve.now](https://cve.now) (CVE List, GitHub advisories, OSV, NVD,
  EUVD, CISA KEV, EPSS and Exploit-DB merged; free, no API key) for
  vulnerabilities affecting the exact npm package versions it saw, and for
  CVSS and exploitation status of CVEs the bundled map matched on server
  software. Only package names, versions and CVE ids are sent, never domains
  or hosts. Results are captured into the scan snapshot, so ratings stay
  reproducible and page loads never call out; live CVSS overrides the bundled
  map where present. `POST /api/orgs/{slug}/live-cves` re-captures them for
  the current snapshot. Fail-open and disk-cached (`CTI_CVE_NOW_TTL`).

- **AI assistant** — ask about an organization in plain language ("What is
  the fastest path to a B?", "Which known-exploited packages do we run?").
  The model works through read-only tools over the same data the dashboard
  shows (rating, issues, the exact planner, packages, findings, history), and
  every CVE, host, package, finding or issue it cites is checked against the
  org's evidence; invented ids are flagged. It cannot scan or change
  anything. Supported providers appear once connected:

  | Provider | How to connect |
  |---|---|
  | OpenCode Go (subscription) | `OPENCODE_GO_API_KEY` |
  | OpenCode Zen (pay as you go) | `OPENCODE_API_KEY` |
  | DeepSeek | `DEEPSEEK_API_KEY` |
  | Codex with a ChatGPT plan | `codex login --device-auth` as the server user |

  Keys are read from the server environment and never sent to the browser.
  Codex runs read-only in an empty scratch directory, without your Codex
  config or this server's secrets. The selected provider receives the
  question and the org's posture data, as the page states before you ask.
  Routes: `GET /api/ai/providers`, `POST /api/ai/providers/{id}/test`,
  `POST /api/orgs/{slug}/assistant`.

- **Portfolio** — every registered organization side by side with its rating,
  trend and open issues by severity (`GET /api/portfolio`).

- **Score history and trend** — completed scans retain compact, versioned
  domain scores in the history ledger. Each domain is compared with the
  preceding scan only when observed hosts, versioned product identities,
  assessed DNS controls and coverage match; losing evidence is flagged as a
  coverage change, not credited as improvement. The trend line plots only
  scans scored under the current model version.

- **Executive brief** — download a printable HTML report from the overview,
  or use **PDF report**. Both include the rating, risk factor grades, top
  issues with their rating gain, the first ten actions and factor-level
  evidence before the finding detail. HTML needs no browser installation on
  the server; PDF export falls back to HTML if Chromium is unavailable.
  `GET /api/orgs/{slug}/report.html` uses the same authentication, tenant
  checks, masking, and size limits as the PDF route.

  **Scope, stated plainly:** this is an *external*, evidence-based rating
  built from what a passive scan can observe. It is not equivalent to a
  commercial security-rating service: there is no internal/agent telemetry,
  no peer benchmarking dataset, no questionnaire-based vendor assessment, and
  no compliance framework mapping. See
  [What this rating is and is not](#what-this-rating-is-and-is-not).
- **Email & DNS posture** — per registered domain, a deterministic supply-chain
  posture check over public DNS: **SPF** (presence, `+all`/`~all` qualifier,
  RFC 7208 lookup budget), **DMARC** (policy none/quarantine/reject, `pct`,
  reporting), **DKIM** (common-selector probe; null keys with empty `p=`
  distinguished from usable keys), **DNSSEC** (DNSKEY + DS presence — reported
  as chain-present, never as validated), **CAA** (authorised issuers), and
  **MTA-STS**. Plus **dangling-CNAME takeover checks**: a subdomain pointing
  at an unclaimed third-party service (S3, GitHub Pages, Heroku, Azure, …)
  becomes a HIGH finding. Every check degrades to *unknown* — never a finding
  — when a lookup fails, and an absent record is worded as a posture gap, not
  a compromise. Served by `GET /api/dns-posture` and the dashboard **Email &
  DNS posture** panel with a per-domain A–F grade; disable with
  `CTI_DNS_POSTURE=0`.
- **Correlation engine** — derives NEW findings from existing ones: CVE fleet-spread,
  IP co-residency, InternetDB source-backed exposure.
- **Finding detail** — `found_date`, tier (CONFIRMED / CORRELATED / AI / CLEAN),
  reproduction steps, evidence snapshot, **PII masking**, NVD CVE links, Shodan /
  InternetDB source links.
- **Status lifecycle** — per-finding `OPEN / IN_PROGRESS / MITIGATED /
  ACCEPTED_RISK` with an audit `status_history[]` and per-org append-only **scan
  ledger** (new / resolved / changed diffs).
- **PDF report** — per-org printable report (title + severity summary + one section
  per finding) rendered via headless Chromium, with HTML fallback. Auth-gated,
  concurrency-limited, PII-masked.
- **Filter & sort** — by severity, recency, status, and a findings view tab
  (All / Detected / Correlated).
- **Bounded jobs** — scan, recheck, and correlation jobs are serialized per org.
  Terminal states (done/failed) are retained so status polling works reliably.
- **Responsive + mobile** — dark theme works on phones; graph is touch-friendly.

## Project layout

```
app/
  main.py              FastAPI server + all /api endpoints + PDF render
  ai_providers.py      AI provider abstraction (ollama + openai-compatible),
                       per-org profiles, SSRF validation
  cve_match.py         offline version->CVE matching + optional NVD enrichment
  cve_data.json        vendored high-impact CVE map (deterministic, offline)
  cti_correlation.py   core engine: registry, normalization, correlation,
                       PII masking, status lifecycle
  scanner.py           passive scan (6 enum sources, wildcard filter, DNS,
                       HTTP fingerprint, TCP service-port probe, banner
                       versions, TLS certs, InternetDB, baseline diff),
                       AI triage, recheck
  dashboard.html       single-file frontend (graph, cards, modal, workspace, history)
  static/
    vis-network.min.js vendored graph library (no CDN dependency)
data/
  orgs.json            org registry (slug -> name, domains, findings, baseline paths)
  ai_config.example.json  multi-profile AI provider config
  orgs/
    sample/            PUBLIC demo org (safe data, shipped in the repo)
    <slug>/            per-org: findings.json, baseline.txt, history.json (gitignored)
.env.example           environment variable template
requirements.txt
```

## Requirements

- **Python 3.11+**
- **fastapi** + **uvicorn** + **dnspython** (see `requirements.txt`).
  dnspython powers the SPF/DMARC/DKIM/DNSSEC/CAA lookups — the stdlib resolver
  only exposes A/AAAA. It is imported lazily: without it, the DNS posture
  stage degrades to "unknown" and every other scan stage still works.
- **One process on one host.** State is JSON files guarded by process-local
  locks with in-memory sessions/jobs — multiple workers or two instances
  sharing a data directory can lose updates. See
  [DEPLOYMENT.md](DEPLOYMENT.md) for the supported shape, hardened systemd
  unit, and reverse-proxy/trusted-proxy notes.
- **curl** (used by the passive scanner / fingerprinting)
- **Optional — headless Chromium** for PDF export
  (`~/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome` style path).
  If absent, the report falls back to a printable HTML download.
- **Optional — AI-assisted scanning:** configure one or more AI provider profiles
  (local Ollama, OpenCode, OpenRouter, vLLM, or any OpenAI-compatible endpoint)
  in `~/.config/cti-radar/ai_config.json` and set `CTI_AI_CONFIG_FILE` to that path
  (see `data/ai_config.example.json`). Alternatively set
  `OPENCODE_GO_B_API_KEY` for legacy single-key quick-start. Without AI config,
  `mode=ai` scans safely fall back to deterministic `fast`.
  See [How AI-assisted scanning works](#how-ai-assisted-scanning-works-modeai).

## Setup

```bash
cd cti-dashboard
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# Create private runtime locations outside the Git checkout
install -d -m 700 "$HOME/.config/cti-radar" "$HOME/.local/share/cti-radar"
install -m 600 .env.example "$HOME/.config/cti-radar/server.env"
# edit ~/.config/cti-radar/server.env with CTI_USER, CTI_PASSWORD, CTI_SCAN_TOKEN

# Serve on loopback by default; set CTI_HOST in the private env file to a
# specific private interface address when remote access is required.
set -a; source "$HOME/.config/cti-radar/server.env"; set +a
cti_host="${CTI_HOST:-127.0.0.1}"  # never 0.0.0.0
CTI_DATA_DIR="${CTI_DATA_DIR:-$HOME/.local/share/cti-radar}" \
.venv/bin/python -m uvicorn app.main:app --host $cti_host --port "${CTI_PORT:-8084}" --no-server-header
```

Or run under systemd (`~/.config/systemd/user/cti-dashboard.service`, `Linger=yes`
for reboot persistence).

Open the dashboard, sign in with the credentials from
`~/.config/cti-radar/server.env`, select an org
(default shipped demo **`sample`**), then use the workspace panel to register a new
org and scan it.

## Security model

- **All endpoints require authentication.** Every GET, POST, and PDF route is
  gated behind either a valid **session cookie** (from `POST /api/login` with
  `CTI_USER`/`CTI_PASSWORD`) or an **`X-CTI-Token`** header matching
  `CTI_SCAN_TOKEN`. There are no unauthenticated reads.
- **Unknown orgs are rejected.** If an org slug is not in the registry, the API
  returns 404 — it does not fall back to default or legacy data. This enforces
  strict tenant isolation.
- **Session cookie security:** the login cookie is `HttpOnly`, `SameSite=Lax`, and
  automatically gets the `Secure` flag when the request arrives over HTTPS
  (detected via `X-Forwarded-Proto` or request scheme).
- **Bind tailnet/LAN explicitly:** the server refuses to bind `0.0.0.0`.
  Always set `CTI_HOST` to a specific tailnet or LAN IP.
- **Input validation:** every `/org/{slug}` is validated against
  `^[a-z0-9-]{1,32}$` before any filesystem use (blocks path traversal).
  Domain names are strictly validated. Registration limits: max 20 domains,
  max 200-character name. Request bodies are Pydantic validated. No `eval`/`exec`.
- **Responses carry security headers:** CSP (no external script sources),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, `Permissions-Policy`.
- **PII masking:** finding evidence, description, impact, remediation,
  proof chains, AI provenance, status history, and related fields are masked
  on every read path — API responses, dashboard payloads, and PDF/HTML reports.
  Emails, phones, account numbers, tokens, and IPs in prose are all redacted.
- **PDF reports are auth-gated and resource-bounded:** single concurrent render
  (semaphore), max 500 findings, 5 MiB HTML input, 20 MiB PDF output, 45-second
  render timeout. Reports use normalized (masked) findings.
- **Frontend dependencies are vendored:** vis-network is shipped locally in
  `app/static/` — no external CDN requests. The Content-Security-Policy does
  not trust any third-party script origins.
- **Non-intrusive scanning:** certificate transparency (crt.name / crt.sh / certspotter / hackertarget) + DNS + HTTP
  reachability/header probe + service banner capture + TCP connect scan of common service ports +
  passive InternetDB only. No payloads, no brute-force, no exploitation.

### Scanner + provider SSRF protections

- `curl` commands use `--noproxy '*'` (bypass environment proxy settings),
  `--max-redirs 0` (no redirect following), and `--resolve` for DNS pinning
  to validated global IPs.
- DNS resolution rejects hostnames that resolve to any private, loopback,
  link-local, or multicast address (DNS rebinding protection). Only globally
  routable IPs are used.
- AI provider base URLs are validated at load time: private/reserved IPs are
  rejected, non-loopback HTTP is rejected, HTTPS is required when an API key
  is configured, and DNS rebinding checks are applied. Redirects are blocked
  and environment proxies are disabled on AI provider calls.

## Per-org data & git hygiene

For a local deployment, keep mutable/private runtime data outside the checkout:

```text
~/.config/cti-radar/server.env          credentials (mode 600)
~/.config/cti-radar/ai_config.json      optional provider profiles (mode 600)
~/.local/share/cti-radar/orgs.json      private workspace registry
~/.local/share/cti-radar/orgs/<slug>/   findings, baseline, and history
~/.local/state/cti-radar/                logs/reports/job state
```

Set `CTI_DATA_DIR=$HOME/.local/share/cti-radar`. Legacy registry paths such as
`data/orgs/<slug>/findings.json` are resolved beneath that runtime root, so
existing local registries remain compatible.

Real scan output (findings with evidence, masked-but-sensitive samples, baselines,
history) lives under the configured runtime root and is never committed. The
repository ships only `data/orgs/sample/` (safe demo data) plus a sample-only
`data/orgs.json`, so a fresh clone works without exposing a real organization.

## Architecture overview

```
Browser (dashboard.html)
   │  fetch (same-origin, auth cookie)
   ▼
FastAPI (main.py) — all routes auth-gated
   ├─ GET  /api/orgs, /api/orgs/{slug}, /api/summary|graph|fleet|ips|findings
   ├─ GET  /api/certificates, /api/software, /api/dns-posture  (asset inventory)
   ├─ GET  /api/posture  (alias /api/scorecard)  (per-domain A-F rating, factors, issues)
   ├─ GET  /api/posture/plan?fix=type,…       (projected rating with issues fixed)
   ├─ GET  /api/dependencies                  (packages, CVEs, origins, providers, drift)
   ├─ GET  /api/dependencies/cyclonedx        (CycloneDX 1.5 export)
   ├─ GET  /api/hosts                         (per-host ratings, critical/weakest first)
   ├─ GET  /api/portfolio                     (every org's rating side by side)
   ├─ GET  /api/ai/providers                  (supported AI providers + status)
   ├─ GET  /api/findings/{id}?org=          (normalized + masked + linked)
   ├─ GET  /api/orgs/{slug}/history          (append-only ledger)
   ├─ GET  /api/orgs/{slug}/report.pdf       (Chromium HTML→PDF, PII-masked)
   ├─ GET  /api/orgs/{slug}/scan/{job_id}    (job status polling)
   ├─ GET  /api/orgs/{slug}/correlate/{job_id}
   ├─ GET  /api/orgs/{slug}/recheck/{job_id}
   ├─ POST /api/login · /api/logout          (session management)
   └─ POST (auth-gated) /api/orgs/register · /{slug}/scan · /{slug}/recheck ·
                 /{slug}/correlate · /{slug}/findings/{id}/status ·
                 /{slug}/live-cves (opt-in cve.now refresh)
          │
          ▼
   scanner.py   passive enum → DNS+IP pinning → fingerprints → (optional AI) →
                findings.json  |  recheck (TCP probe per-finding IP/port)
   ai_providers.py  multi-profile AI (ollama / openai-compatible), SSRF validation
   cti_correlation.py  normalize (found_date, tier, links, repro steps, PII mask)
                         correlation (CVE-share / IP co-residency / InternetDB)
                         status lifecycle + per-org history diff
          │
          ▼
   <CTI_DATA_DIR>/orgs/<slug>/{findings.json, baseline.txt, history.json}
```

### How correlation works

Starting from seed domains (e.g. `*.example.com`), a scan enumerates subdomains
(crt.name, crt.sh, certspotter, hackertarget, Wayback CDX, OTX passive DNS —
with wildcard-DNS filtering), resolves them (inactive hosts
are dropped), probes HTTP(S) reachability (capturing status codes via curl) and
captures service banners (SSH/FTP/SMTP/etc. greetings) for every reachable port,
fingerprints reachable hosts, TCP-connects common service ports on resolved IPs, and enriches
IPs from InternetDB. It then derives **deterministic findings directly**:

1. **Certificate inventory** — every HTTPS host's cert is captured (subject,
   issuer, expiry, SANs, key bits) along with hostname-match, chain-trust and
   self-signed verdicts; problem certs become findings.
2. **Version→CVE match** (offline) — disclosed versions vs the vendored map →
   advisory CORRELATED finding per host with NVD links and confidence.
3. **Security headers** — missing HSTS/CSP/XFO/XCTO → LOW/MEDIUM finding.
4. **New exposure** — diff vs the previous scan's baseline (new hosts / newly
   open ports) → CONFIRMED finding.

And the correlation engine adds derived findings from existing ones:

5. **CVE correlation** — any host sharing a CVE with a known finding → new finding.
6. **IP co-residency** — other hosts on a confirmed finding's IP → new finding.
7. **InternetDB** — exposed vulnerable port/CPE → source-backed finding.

Generated findings are tagged `CORRELATED` / `AI-ASSESSED` and are distinct from
`CONFIRMED` originals; the dashboard's **Correlated** tab isolates them.
Advisory `scan-cve` findings never seed further correlation (no amplification).

### How AI-assisted scanning works (`mode=ai`)

A fast `mode=fast` scan is **always** the deterministic engine (subdomain
enumeration → DNS resolution → reachability probe → HTTP fingerprint → TCP
service-port scan) and costs **$0** — it runs first, unconditionally, and persists
`baseline.txt` + `findings.json` either way. `mode=ai` layers an **optional,
cheap-model-friendly classifier** on top of that captured data; it never replaces
the scan and never blocks it:

1. **Capture** — for each reachable host the scanner stores a small, PII-safe
   fingerprint (`url`, HTTP code, `server`, `x-powered-by`, `title`) plus the open
   service ports found by the TCP connect scan.

2. **Triage** — a deterministic pre-scorer keeps only the hosts worth a second
   look: exposed admin/DB/remote-access ports, interesting titles (`admin`,
   `jenkins`, `citrix`, …), version disclosures in server headers, or auth-gated
   consoles. Plain public websites are skipped. The set is capped by the profile's
   `max_hosts` (default 10).

3. **Classify** — the model sees one compact line per triaged host and returns a
   tiny verdict object:
   `{"results":[{"target","verdict":"confirm|dismiss","severity","reason"}]}`.
   The model provides *judgment only* — it does not write full findings, so it
   cannot drift the schema, invent CVEs, or emit unchecked prose. Ollama uses
   `format:"json"`; OpenAI-compatible endpoints use `response_format:
   json_object` (with a retry without it); both cap `max_tokens`/`num_predict`.

4. **Expand, validate, merge** — confirmed verdicts are expanded into findings by
   templates and tagged **`AI-ASSESSED`** (`source: ai-assess`), then strictly
   validated (target whitelist, canonical severities) and merged into
   `findings.json` deduplicated by `(target, title)`. On malformed JSON one
   self-repair retry is attempted; legacy full-finding responses are still
   accepted. Deterministic findings are never overwritten by AI output.

5. **Fail-safe** — the model call runs in a strict try/except with an absolute
   fallback: missing API key, a non-200 response, bad JSON, or a timeout all
   return `None`/`[]`, the event is recorded (`AI assessment failed/unavailable`),
   and the scan returns the **already-complete deterministic result**. An AI run
   can never take down or alter a fast scan.

### Provider configuration

Create `~/.config/cti-radar/ai_config.json` (copy from
`data/ai_config.example.json`) and set
`CTI_AI_CONFIG_FILE=$HOME/.config/cti-radar/ai_config.json`:

```json
{
  "default_profile": "hermes-local",
  "profiles": {
    "hermes-local": {
      "provider": "ollama",
      "base_url": "http://127.0.0.1:11434",
      "model": "hermes3",
      "timeout": 90,
      "max_hosts": 10
    },
    "opencode": {
      "provider": "openai-compatible",
      "base_url": "https://opencode.ai/zen/go/v1",
      "model": "muse-spark-1.2-contributor",
      "api_key_env": "OPENCODE_GO_B_API_KEY",
      "timeout": 90,
      "max_hosts": 10
    }
  }
}
```

Profiles are validated at load time: non-loopback HTTP is rejected, private IPs
are rejected, environment proxy settings are bypassed, and redirects are blocked.
API keys are referenced by environment variable name only — never stored in the
config file. `max_hosts` caps the pre-triaged set the model sees (default 10).
Structured JSON mode is requested (`format:"json"` for Ollama,
`response_format: json_object` for OpenAI-compatible, with a retry without it) and
generation is token-capped.

The split is deliberately clean: **deterministic capture is the source of truth,
$0, and self-healing; the LLM is an optional interpretive pass that adds
vulnerability-context findings on top.**

## What this rating is and is not

The rating is often compared to commercial security-rating products. The comparison is useful for framing
and misleading if taken literally, so the boundary is stated here explicitly.

**What it does, using only externally observable evidence:**

| Capability | Status here |
|---|---|
| Security rating per domain (A–F) | Yes: itemized, reproducible, seven weighted factors |
| Risk prioritization | Yes: issues sort by exact rating gain; known-exploited CVEs rank first |
| Continuous monitoring | Partly: score history, trend and script/package drift per scan; scheduling is up to you |
| Supply-chain / third-party surface | Yes: packages, script origins, service providers, drift |
| What-if planning | Yes: exact projected rating for any set of issue types |
| Executive reporting | Yes: HTML/PDF brief with factor grades, top issues and actions |

**What it explicitly does not do:**

- **No internal telemetry.** Everything derives from a passive external scan.
  Endpoint agents, EDR, SIEM correlation and internal asset inventory are out
  of scope by design — this tool never sees inside your network.
- **No peer benchmarking.** Commercially meaningful ratings are calibrated
  against an industry dataset of millions of companies. This rating is
  *absolute and self-referential*: it tells you which of your own domains is
  worst and whether it improved. Comparing your A to another company's A is
  not meaningful, because both are scored against the same fixed rubric rather
  than a population distribution.
- **No questionnaire-based vendor assessment.** TPRM in the commercial sense
  means scoring a *third party* on self-attested controls, contracts and
  certifications. Here, "vendor risk" means only the externally visible parts
  of your own supply chain (dangling CNAMEs to third-party services, disclosed
  framework versions).
- **No compliance framework mapping.** There is no SOC 2 / ISO 27001 / PCI
  DSS control mapping. Posture checks align with good practice, but this
  produces no audit evidence.
- **No incident response, threat feeds or real-time alerting.** Threat intel is
  limited to vulnerability advisories: the bundled CVE map, plus CVSS and
  CISA KEV status from the opt-in cve.now source.

The honest one-line framing: **it is a defensible, explainable external
security rating for domains you own — not a market-calibrated industry score.**

## OpenHack active-assessment authorization

OpenHack is an **active external assessment**, not the passive CTI scanner. Use it
only with written authorization and a time-bounded rules of engagement (ROE).
At request time the active gate requires `CTI_OPENHACK_ACTIVE=1`, `CTI_OPENHACK_ISOLATED=1`, and an explicit absolute `CTI_OPENHACK_BIN` (a disposable-container wrapper);
`CTI_OPENHACK_ALLOWED_DOMAINS` must list every registered target exactly (DNS names
only; no wildcards, URLs, paths, ports, IPs, or suffix matches), and
`CTI_OPENHACK_ROE_EXPIRES` must be a future timezone-aware RFC3339/ISO-8601
timestamp. The org's OpenHack opt-in and normal authentication are also required.

```dotenv
CTI_OPENHACK_ACTIVE=1
CTI_OPENHACK_ISOLATED=1
CTI_OPENHACK_ALLOWED_DOMAINS=example.com,api.example.com
CTI_OPENHACK_ROE_EXPIRES=2030-01-01T00:00:00Z
# Prefer a wrapper that launches OpenHack in a disposable container:
CTI_OPENHACK_BIN=/usr/local/bin/openhack-disposable-container-wrapper
```

Keep targets exact and scoped to the written ROE. Login throttling uses the directly connected source IP; configure rate limiting at the reverse proxy too for defense in depth. Do not point
`CTI_OPENHACK_BIN` at a host binary; use a disposable-container wrapper instead.

## Testing

```bash
cd cti-dashboard
. .venv/bin/activate
python -m pytest tests/ -v
```

352 tests covering: tenant authentication, unknown org rejection, graph XSS
prevention, PDF PII masking, job state retention, provider URL SSRF validation,
session cookie security, CSP enforcement, registration limits, the
cheap-model AI triage flow (pre-filter, compact prompt, classifier parsing,
template expansion, and self-repair retry), AI grading with exposure
verification (`still_open` read of the latest probe data), probe-evidence
refresh on existing findings, deterministic login-portal / version-disclosure
findings, the Wayback/OTX enum sources + wildcard-DNS filtering, the offline
version→CVE map (comparator edges, alias normalization, banner-derived
versions, no-correlation-amplification) + optional NVD enrichment
(cache, fail-open), security-header findings, baseline-diff new-exposure
sequencing, resolver-pool + InternetDB-cache behavior, evidence-based AI
prompt enrichment (CVE candidates, missing-header signals, sanitizer
neutralization), and the asset-inventory layer (certificate hostname matching
RFC 6125 exact/wildcard/IP-SAN, expiry and chain and name-mismatch findings,
inventory ordering and capping, software rows joined with CVEs both from the
map and from findings, plus the authenticated `/api/certificates` and
`/api/software` endpoints), and the DNS posture layer (SPF qualifier and
RFC 7208 lookup-budget scoring, DMARC policy/pct/reporting, null-vs-usable
DKIM keys, DNSSEC DNSKEY/DS presence, CAA issuer parsing, MTA-STS, takeover
provider matching plus dangling-target classification, unknown-vs-missing
semantics so a resolver outage never becomes a finding, deterministic
grading, and dedup by identity_key across rescans), and the framework-detection
layer (generator / asset-path / header / cookie signatures, version extraction
and validation, identity-only detections excluded from CVE matching, per-product
CVE attribution, plus the HTTP/1.1-vs-HTTP/2 curl response split that governs
whether any body analysis runs at all), and the external posture rating (weighted
factors, itemized deductions, per-product CVE attribution, unknown-vs-assessed
pillar handling, coverage-based grade capping, the critical-CVE cap, monotonic
grading so a card cannot be laundered by clean hygiene elsewhere, single-domain
host attribution to prevent double counting, and header/card grade
consistency).

## Preview

Screenshots below show the **previous (CTI Radar) interface** and have not
been retaken since the redesign:

![Previous CTI Radar dashboard 1](screenshots/cti-radar-01.jpeg)

![Previous CTI Radar dashboard 2](screenshots/cti-radar-02.jpeg)

![Previous CTI Radar dashboard 3](screenshots/cti-radar-03.jpeg)

![Previous CTI Radar dashboard 4](screenshots/cti-radar-04.jpeg)

## License / Disclaimer

This tool is for **authorized security assessment only**. The operator is
responsible for ensuring they have permission to scan every target. No warranty. The
scanner is intentionally non-intrusive; do not use it to attack systems you do not
own or lack written authorization to test.
