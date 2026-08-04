# HeaderHawk v2.6.0

[![Version](https://img.shields.io/badge/version-2.6.0-brightgreen.svg)](headerhawk.py)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![GitHub Stars](https://img.shields.io/github/stars/kabiri-labs/HeaderHawk.svg?style=social&label=Star)](https://github.com/kabiri-labs/HeaderHawk)

**HeaderHawk** is a security scanner for **HTTP header–based vulnerabilities**, covering both sides of the exchange: the request headers an attacker manipulates, and the response headers a product is supposed to send. Modern stacks trust a whole family of request headers for routing, identity and caching — `Host`, the `X-Forwarded-*` headers, `Forwarded`, client-IP headers, URL-override headers and more — and each of them is an attack surface. HeaderHawk exercises that surface systematically and reports the bugs it uncovers: Host header injection, SSRF, confirmed web cache poisoning, access-control bypass, open redirects and hidden virtual hosts.

Its focus is **signal over noise**. Findings are driven by evidence — unique per-scan markers, two-probe confirmation, real out-of-band correlation and stable-baseline differencing — so results are trustworthy enough to act on. And the output is built for real workflows: every finding carries a severity, reports export to JSON / Markdown / **SARIF 2.1.0**, and the process exit code lets a CI pipeline gate on the result.

---

## Table of Contents

- [Detection Coverage](#detection-coverage)
- [Control Mapping](#control-mapping)
- [Compliance Evidence](#compliance-evidence)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Options](#options)
  - [Exit Codes](#exit-codes)
  - [Examples](#examples)
- [Output](#output)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Contact](#contact)

---

## Detection Coverage

Each module targets a distinct class of header-driven weakness and the headers/vectors that trigger it:

| Attack class | Headers / vectors exercised |
| ------------ | --------------------------- |
| **Host header injection** (cache / password-reset / link poisoning) | `Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `X-Original-Host`, `X-HTTP-Host-Override`, `Forwarded`, `Base-Url`, and 10+ more routing headers — reflection of a unique marker in body, `Location` or any response header |
| **Host validation bypass** | Duplicate `Host` headers, absolute-URI request lines, indented (line-folded) headers, host overrides — sent with a raw HTTP/1.1 client |
| **Confirmed web cache poisoning** | Unkeyed headers (`X-Forwarded-Host`, `X-Host`, `X-Original-Host`, `Base-Url`, …) with a cache-buster and a clean re-request that proves the poisoned response is served |
| **Access-control bypass** | Internal `Host` / `X-Forwarded-For` / `X-Real-IP` / `True-Client-IP` values against 401/403 endpoints, plus path-override headers `X-Original-URL` / `X-Rewrite-URL` |
| **SSRF via routing headers** | `Host`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`, `Forwarded` pointed at internal hosts and cloud metadata endpoints |
| **Blind SSRF (out-of-band)** | Per-scan correlation id embedded in payloads, confirmed by polling your listener |
| **Open redirect** | `Host`-driven redirects whose `Location` host matches the injected value |
| **URL-parameter SSRF** | `url`, `next`, `redirect`, `dest`, `uri`, `path`, … against internal targets, with baseline differencing |
| **Virtual host discovery** | `Host`-header brute force (built-in or custom wordlist) with two-probe confirmation |
| **HTTP request smuggling** | `Content-Length` / `Transfer-Encoding` disagreement between front-end and back-end — CL.TE and TE.CL, detected by timing |
| **CORS origin validation** | `Origin` reflection, `null` origin, prefix / suffix / trailing-dot / subdomain allowlist bypasses and plaintext-origin trust — each confirmed by the server echoing the origin back in `Access-Control-Allow-Origin` |
| **Response header posture** | `Strict-Transport-Security`, `frame-ancestors` / `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`, and version banners (`Server`, `X-Powered-By`, …) |
| **Content-Security-Policy analysis** | `object-src` / `base-uri`, effective `script-src` (`'unsafe-inline'`, `'unsafe-eval'`, broad sources — with nonce, hash and `'strict-dynamic'` semantics applied), and violation reporting |
| **Cookie attributes** | `Secure`, `HttpOnly` (on session-like cookies), `SameSite`, `__Secure-` / `__Host-` name prefixes and the 4096-byte size limit, per `Set-Cookie` field |

---

## Control Mapping

Every finding carries the published security controls it is evidence against, so
a report answers *which requirement does this fail?* without a manual crosswalk.

| Finding | Controls |
| ------- | -------- |
| Host header injection / bypass, web cache poisoning | ASVS 5.0 **4.1.3** — an HTTP header field set by an intermediary layer cannot be overridden by the end user |
| Access-control bypass | ASVS 5.0 **4.1.3**, **8.3.1** — authorization enforced at a trusted service layer |
| SSRF, URL-parameter SSRF, blind SSRF | ASVS 5.0 **13.2.4**, **13.2.5** — allowlist of systems the application and server may call |
| Open redirect | ASVS 5.0 **3.7.2** — redirects to another hostname only to allowlisted destinations |
| CORS misconfiguration | ASVS 5.0 **3.4.2** — `Access-Control-Allow-Origin` is a fixed value or validated against an allowlist |
| HTTP request smuggling | ASVS 5.0 **4.2.1**, **4.2.2** — message boundaries determined consistently, `Content-Length` consistent with the body |
| Virtual host discovery | ASVS 5.0 **13.4.5** — internal documentation and monitoring endpoints not exposed |
| Response header posture | ASVS 5.0 **3.4.1** (HSTS), **3.4.3** (CSP), **3.4.4** (nosniff), **3.4.5** (Referrer-Policy), **3.4.6** (frame-ancestors), **3.4.7** (CSP reporting), **3.4.8** (COOP), **13.4.6** (version disclosure) |
| Cookie attributes | ASVS 5.0 **3.3.1** (Secure + name prefix), **3.3.2** (SameSite), **3.3.3** (`__Host-` prefix), **3.3.4** (HttpOnly on session values), **3.3.5** (size limit) |

The mapping surfaces in every format: a **Control Coverage** table and a per-finding
`Controls` line in Markdown, a `controls` field in JSON, and SARIF rule `tags` plus
`help` text so GitHub code scanning shows the requirement alongside the alert.

Control ids are transcribed from the published standard and each links to the
chapter it came from. A finding type with no genuinely matching control is
reported as unmapped rather than attached to an approximate requirement — an id
that does not hold up under review is worse than an empty column. `Permissions-Policy`
is the current example: ASVS 5.0 has no requirement for it, so it is reported
without one.

---

## Compliance Evidence

`--evidence report.md` (or `.json`) writes a report keyed by **requirement**
rather than by finding — the question an assessor actually asks:

| Status | Controls |
| --- | --- |
| Fail | 11 |
| Not assessed | 0 |
| Pass | 11 |

Each control is listed with its framework, the requirement text, a link to the
chapter it came from, and its evidence: the findings that failed it, or the
checks that assessed it and found nothing.

**A control is only reported as passing when a check that covers it actually
completed.** This is the part that decides whether the report is worth anything.
A scan of a host it could not reach produces no findings — reporting that as full
compliance would be worse than producing no report at all. So anything the scan
could not judge is listed as *not assessed*, with the reason:

```
### ASVS-5.0:4.2.1 — NOT ASSESSED
- **Not assessed because:**
  - HTTP Request Smuggling: a timing baseline could not be measured, so a delay
    would have had nothing to be compared against
```

Findings whose type maps to no catalogued requirement are listed at the end
rather than dropped, so nothing the scan found is left out of the report just
because there is no requirement to hang it on.

---

## Features

### Detection & accuracy

- **Response header posture**: one request establishes which browser security controls the response actually carries — HSTS (including `max-age` and `includeSubDomains`), CSP, frame protection, `nosniff`, `Referrer-Policy`, COOP, `Permissions-Policy` and version banners. Rules stay quiet when the control is genuinely in place, and HSTS is not reported over plaintext where a browser would ignore it anyway.
- **CSP analysed the way a browser reads it**, not by presence alone: `'unsafe-inline'` is *not* reported when a nonce or hash is also present, because a browser ignores it there; `'strict-dynamic'` suppresses host and scheme allowlist findings for the same reason; `object-src` accepts a `default-src` fallback while `base-uri`, which has none, must be explicit; and `*.example.com` is treated as an allowlist rather than an open door.
- **Per-cookie assessment**: every `Set-Cookie` field is parsed individually — including several folded into one header, without tearing apart the comma inside an `Expires` date — and checked for `Secure`, `SameSite`, name prefixes and size. `HttpOnly` is reported only for cookies whose name suggests a session or sensitive value (`sessionid`, `PHPSESSID`, `authtoken`, …), since an analytics cookie legitimately needs script access.

- **Unique-marker reflection**: injects a random per-request marker so a reflected Host is a high-confidence finding, not a guess — across `Host`, `X-Forwarded-Host`, `Forwarded` and 15+ other headers, checked in the body, the `Location` header and every response header.
- **Raw HTTP/1.1 client**: a purpose-built client (not `requests`) sends malformed requests verbatim — duplicate `Host` headers, absolute-URI request lines, line-folded headers — the building blocks of most Host validation bypasses.
- **Confirmed cache poisoning, not just reflection**: a cache-buster is planted, the poisoning request is sent through an unkeyed header, and the URL is re-requested *without* it; only a surviving marker (served from cache) is reported, with `X-Cache` / `Age` / `CF-Cache-Status` context.
- **Weighted SSRF scoring**: response-time deviation, internal-target indicators (`root:x:0:0:`, cloud-metadata markers, connection errors) and header anomalies are combined behind a threshold. Header anomalies are measured only against headers proven stable across baseline samples, so per-request identifiers (request ids, tracing, `CF-RAY`, nonces) are learned as volatile and ignored.
- **Confirmed virtual-host discovery**: the default vhost is sampled repeatedly to learn its natural page-to-page variance; a candidate is reported only when a status, length or title difference is confirmed on a second probe — dynamic content does not masquerade as a hidden host.
- **Request smuggling, detected without smuggling anything**: a probe whose body deliberately disagrees with its own `Content-Length` leaves whichever server loses the disagreement waiting for bytes that never arrive. A hang is only reported after two consecutive probes agree *and* a well-formed request in between still returns normally — which is what separates a desync from a target that merely became slow. Nothing is planted on the connection, so a scan does not tamper with other users' traffic.
- **Honest about what timing proves**: every smuggling finding carries a `Confirming this` note stating that a delay is evidence rather than proof, what to run for certainty, and what that costs. It is printed to the console and included in every report format.
- **Proven CORS findings**: a unique per-scan origin that cannot exist is sent as `Origin`; only the server echoing it back counts. Severity follows `Access-Control-Allow-Credentials`, since a permissive allowlist that also allows credentials means an attacker's page can read authenticated responses. A server that reflects *anything* is reported once as reflection rather than five times over as each narrower bypass, and a fixed allowlist — or a bare `*` without credentials, which is correct for a public endpoint — produces nothing.
- **Real out-of-band confirmation**: embeds a per-scan correlation id into OOB payloads and, given a listener export URL, polls it to confirm blind SSRF. Works with interactsh, webhook.site, RequestBin, Burp Collaborator exports and custom sinks.

### Engine, workflow & reporting

- **Evidence report by requirement**: `--evidence` answers *did this product meet each requirement, and how do you know?* — and never reports a requirement as met when the scan could not judge it. See [Compliance Evidence](#compliance-evidence).
- **Control-mapped findings**: each finding cites the OWASP ASVS 5.0 requirements it is evidence against, in every report format — see [Control Mapping](#control-mapping).
- **Severity-rated findings**: every finding carries a severity band (High / Medium / Low), shown in the summary and in every report format for quick triage.
- **Reports in JSON, Markdown or SARIF 2.1.0**: chosen by output extension. SARIF includes per-rule `security-severity` scores and stable fingerprints, dropping straight into GitHub code scanning or a security dashboard.
- **Findings split by class**: proven *vulnerabilities* and missing *posture* controls are counted separately, and `--fail-on` decides which of them gate the exit code — so posture reporting can be switched on without turning an existing pipeline red.
- **CI-friendly exit codes**: `0` = clean, `1` = findings, `2` = the scan could not run (bad input, interrupted, or the target was unreachable) — an unreachable host is never mistaken for a clean result.
- **Batch scanning**: `--list` scans a whole file of URLs in one run, aggregating findings into a single report, summary and exit code.
- **Copy-paste reproduction**: each finding ships a ready-to-run command — `curl` for header/parameter issues, a `printf | ncat` / `openssl s_client` wire-level command for raw bypasses.
- **Proxy-aware, end to end**: `--proxy` routes the whole scan through an upstream/intercepting proxy (e.g. Burp) — including the raw bypass traffic, tunnelled via `CONNECT` so the malformed requests stay intact. Supports `user:pass@` basic auth.
- **WAF-friendly rate limiting**: `--rate` caps the entire scan (all threads plus the raw client) at a fixed requests-per-second budget to stay under rate-based blocking.
- **Fast and configurable**: bounded `ThreadPoolExecutor` with connection pooling and automatic retries, configurable HTTP methods, timeout, custom headers and optional TLS-verification bypass.
- **Quiet / TTY-aware output**: `--quiet` (auto-enabled when stdout is not a TTY) strips progress bars and colours so piped and CI logs stay clean, while `Ctrl+C` stops the run gracefully without losing collected results.

---

## Installation

### Prerequisites

- **Python 3.6** or higher.

### Clone the Repository

```bash
git clone https://github.com/kabiri-labs/HeaderHawk.git
cd HeaderHawk
```

### Install Dependencies

Install the required Python packages using `pip`:

```bash
pip install -r requirements.txt
```

Alternatively, install them individually:

```bash
pip install requests tqdm colorama urllib3
```

---

## Usage

```bash
python headerhawk.py [options] <target_url>
```

### Basic Usage

```bash
python headerhawk.py http://example.com
```

### Options

- `<target_url>`: The target URL to scan. Required unless `--list` is given.
- `--list <file>` or `-l`: Scan every URL in a file (one per line; blank lines and `#` comments are ignored). Findings from all targets are aggregated into one report.
- `--oob <domain>`: Out-of-Band (OOB) domain embedded into payloads for SSRF correlation.
- `--oob-poll-url <url>`: Listener export URL polled after the scan to confirm OOB interactions.
- `--wordlist <file>` or `-w`: Custom virtual-host wordlist for discovery (one name per line).
- `--threads <number>`: Number of concurrent threads (default `5`). Must be between 1 and 20.
- `--rate N`: Cap the whole scan (all threads combined, including raw-HTTP bypass traffic) at `N` requests per second. Default `0` means unlimited; set a low value (e.g. `5`) to stay under WAF or rate-based blocking.
- `--timeout <seconds>`: Per-request timeout in seconds (default `10`).
- `--methods <list>`: Comma-separated HTTP methods to test (default `GET`, e.g. `GET,POST`).
- `--header <"Name: Value">` or `-H`: Add a custom request header. Repeatable.
- `--proxy <url>`: Route traffic through an upstream proxy (e.g. `http://127.0.0.1:8080`), including the raw-HTTP bypass tests, which are tunnelled via `CONNECT`. Supports optional `user:pass@` basic auth.
- `--insecure` or `-k`: Disable TLS certificate verification — needed for staging and lab hosts with a self-signed certificate. This genuinely disables verification even when the environment sets `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE`, which otherwise override it. Without it, a scan of an untrusted-certificate host fails every request and says so, pointing at this flag.
- `--verbose <level>`: Verbosity level (1 or 2). Level 2 also records non-findings for the report.
- `--enable-desync`: Confirm a suspected request-smuggling desync by planting a smuggled prefix and checking whether a following request comes back affected. **Intrusive** — see the warning below. Off by default; without it, smuggling is reported from timing alone.
- `--fail-on <vuln|posture|any|none>`: Which findings make the process exit `1`. Default `vuln` — only proven vulnerabilities. `posture` counts missing response-header controls, `any` counts both, `none` never fails on findings (report-only runs).
- `--quiet` or `-q`: Suppress progress bars, colours and status chatter (only findings and the final summary are printed). Auto-enabled when stdout is not a TTY, so piped/CI logs stay clean.
- `--evidence <file>`: Write a per-control compliance evidence report (`.md` or `.json`) — every catalogued requirement reported as Pass, Fail or Not assessed, with its evidence or the reason it could not be judged. See [Compliance Evidence](#compliance-evidence).
- `--output <file>` or `-o <file>`: Save results to a file. The format is chosen by extension: `.json`, `.sarif` (SARIF 2.1.0 for GitHub code scanning / security dashboards) or `.md`.

### Request Smuggling and `--enable-desync`

Smuggling detection is **timing-based by default and sends nothing that can affect
another user**. A probe is shaped so that the server which loses the
`Content-Length` / `Transfer-Encoding` disagreement waits for a body that never
arrives; the delay is the signal. CL.TE is always probed before TE.CL, because on
a CL.TE-vulnerable target the TE.CL probe would leave the front-end holding a
partial request and disrupt other users.

A delay is strong evidence but not proof — a slow upstream, a rate limiter or a
stalled connection pool produce the same symptom, and a target with no front-end
cannot desync at all. Findings say so in a `Confirming this` note rather than
overstating themselves.

`--enable-desync` buys certainty and costs restraint. It plants a smuggled prefix
and then issues a normal request to see whether the second comes back affected —
the prefix sits on the back-end connection and **can attach itself to another
user's request, corrupting or misrouting live traffic**. Use it only against a
system you are authorised to disrupt, and preferably outside peak hours. A
confirmed finding is reported as `Vulnerable` rather than `Potentially Vulnerable`.

### Exit Codes

The process exit code reflects the scan outcome, so it can gate a CI pipeline:

| Code | Meaning |
| ---- | ------- |
| `0`  | Scan completed and **no** findings were reported. |
| `1`  | Scan completed and **at least one** gating finding was reported (see `--fail-on`). |
| `2`  | The scan could not run meaningfully — invalid URL, interrupted, or the target was unreachable (every request failed). |

By default only vulnerability-class findings gate the build, so enabling the posture check does not change the exit code of an existing pipeline. Use `--fail-on any` to gate on posture too, or `--fail-on none` for a report-only run.

If every request failed because the certificate was not trusted, the summary says so explicitly and points at `--insecure` — a self-signed certificate should not look like an unreachable host.

An unreachable target is deliberately reported as code `2` (inconclusive), never as a clean `0`, so a host that never answered is not mistaken for a host with no vulnerabilities. The summary also prints a `Requests: <ok>/<total> succeeded` line so partial failures are visible.

#### CI Example

```bash
python headerhawk.py https://example.com --quiet -o report.json
if [ $? -eq 1 ]; then
  echo "Header vulnerabilities detected — failing the build."
  exit 1
fi
```

### Examples

#### Scan a List of Targets

```bash
python headerhawk.py --list targets.txt -o report.json
```

#### Export SARIF for Code Scanning

```bash
python headerhawk.py https://example.com -o findings.sarif
```

#### Throttle to Avoid a WAF

```bash
python headerhawk.py http://example.com --threads 10 --rate 5
```

#### Route Everything Through Burp (raw bypasses included)

```bash
python headerhawk.py https://example.com --proxy http://127.0.0.1:8080 -k
```

#### Test Additional Methods

```bash
python headerhawk.py http://example.com --methods GET,POST
```

#### Send Custom Headers (e.g. Authentication)

```bash
python headerhawk.py http://example.com -H "Authorization: Bearer <token>" -H "Cookie: session=abc"
```

#### Confirm Blind SSRF via an OOB Listener

```bash
python headerhawk.py http://example.com --oob xxxx.oast.fun --oob-poll-url https://api.listener.example/export
```

#### Virtual Host Discovery with a Custom Wordlist

```bash
python headerhawk.py http://example.com -w internal-vhosts.txt
```

#### Full Command

```bash
python headerhawk.py http://example.com --threads 10 --timeout 8 --rate 20 --verbose 2 --output results.sarif --oob oob.example.com
```

### Interrupting the Program

- Press `Ctrl+C` at any time to stop the execution gracefully; results collected so far are still written to `--output`.

---

## Output

The scan ends with a summary of every finding. Each finding reports:

- **Test Type** — one of Host Header Injection, Host Header Bypass, Web Cache Poisoning, Auth Bypass, Virtual Host Discovery, SSRF, URL Parameter SSRF, Open Redirect or Blind SSRF (OOB).
- **Severity** — High / Medium / Low.
- **URL & HTTP Method** — the request that triggered the finding.
- **Header / Parameter & Payload** — the manipulated header (or URL parameter) and the value used.
- **Status Code & Response Time** — the observed response.
- **Controls** — the security requirements the finding is evidence against.
- **Analysis** — why it was flagged (reflection location, weighted SSRF signals, header anomalies, confirmed poisoning, OOB interaction, …).
- **Reproduce** — a copy-paste command that reproduces the finding.

A `Requests: <ok>/<total> succeeded` line and a `Targets scanned` count are always printed so coverage and reachability are visible.

### Sample Output

```
HeaderHawk 2.6.0
GitHub: https://github.com/kabiri-labs/HeaderHawk

Targets: 1
Methods: GET
Using 5 threads (timeout 10.0s, rate unlimited).
Verbosity level set to 1.

Target URL: http://example.com
Original Host: example.com

Starting Host Header Injection Testing...
Host Header Injection Testing: 100%|████████████████████████| 76/76 [00:06<00:00, 12.1test/s]

[!] Host Header Injection Finding! [Medium]
URL: http://example.com/
Method: GET
Header: X-Forwarded-Host
Payload: 834503a3f66d.example-collab.com
Status Code: 302
Response Time: 0.01s
Analysis: Injected host reflected in 'Location' header: https://834503a3f66d.example-collab.com/login Injected host reflected in response body (cache/link poisoning).
Reproduce: curl -s -i -H 'X-Forwarded-Host: 834503a3f66d.example-collab.com' 'http://example.com/'
--------------------------------------------------------------------------------

========== Test Summary ==========
Targets scanned: 1/1
Requests: 512/512 succeeded (0 failed).
Total findings: 1

--- Host Header Injection ---
- [Medium] GET http://example.com/
  Header/Parameter: X-Forwarded-Host
  Payload: 834503a3f66d.example-collab.com
  Analysis: Injected host reflected in 'Location' header: https://834503a3f66d.example-collab.com/login Injected host reflected in response body (cache/link poisoning).
--------------------------------------------------------------------------------
===================================
```

---

## Contributing

### Project layout

The scanner is a package; `headerhawk.py` at the repository root is only a thin
entry point so `python headerhawk.py <target>` keeps working from a checkout.

```
headerhawk/
├── cli.py                 # argument parsing and scan orchestration
├── _meta.py               # tool name, version, project URL
├── compliance/            # control catalogue and finding -> control mapping
├── core/                  # engine: session, pacing, stats, severity, OOB, output
├── net/raw.py             # raw HTTP/1.1 client, with timed byte-exact sends
├── posture/               # response-side assessment
│   ├── facts.py           # the response view a rule is given
│   ├── rules.py           # header and CSP rules
│   └── cookies.py         # Set-Cookie parsing and cookie rules
├── checks/                # one module per class of weakness
│   ├── base.py            # shared scaffolding (requests, thread pool, findings)
│   ├── wordlists.py       # header and virtual-host name lists
│   └── registry.py        # ordered list of checks the CLI runs
└── report/                # JSON, SARIF and Markdown rendering
```

To add a detection module, subclass `BaseTest` in a new `checks/` module, give it
a `test_type`, add that type to `SEVERITY_BY_TEST` in `core/severity.py`, and
register the class in `checks/registry.py` — the CLI picks it up from there.
Also give it an entry in `compliance/mapping.py` — an empty tuple is a valid
answer, but the decision may not be skipped; a test enforces it.

### Workflow

Contributions are welcome! Please follow these steps:

1. **Fork the Repository**: Click the "Fork" button at the top-right corner of this page.
2. **Clone Your Fork**: Clone your forked repository to your local machine.

   ```bash
   git clone https://github.com/your-username/HeaderHawk.git
   ```

3. **Create a Branch**: Create a new branch for your feature or bug fix.

   ```bash
   git checkout -b feat/YourFeature
   ```

4. **Make Changes**: Add your improvements or fixes, together with matching tests.

5. **Run the Tests**: The unit tests are fully offline (no network access required).

   ```bash
   python -m unittest discover -s tests
   ```

6. **Commit Changes**: Commit your changes with a descriptive message.

   ```bash
   git commit -m "Add new detection module for X"
   ```

7. **Push to GitHub**: Push your changes to your forked repository.

   ```bash
   git push origin feat/YourFeature
   ```

8. **Open a Pull Request**: Navigate to the original repository and click on "New Pull Request".

Please ensure your code adheres to the existing style, includes appropriate error handling, and keeps the test suite green.

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

**HeaderHawk** is intended for educational and authorized testing purposes only. Unauthorized use of this tool against systems without explicit permission is illegal and unethical. The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

---

## Contact

For support or inquiries:

- **Email**: [certification.kabiri@gmail.com](mailto:certification.kabiri@gmail.com)
- **GitHub Issues**: [Create an Issue](https://github.com/kabiri-labs/HeaderHawk/issues)

Feel free to open an issue or pull request for any bugs, feature requests, or questions.

---

**Star this project** ⭐ if you find it useful!
