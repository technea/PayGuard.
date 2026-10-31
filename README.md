# PayGuard

**A read-only payment-intent security checker for AI agents.**

PayGuard evaluates an x402-style payment request against a separate, explicit policy describing what the user intended to pay for. It returns **PASS**, **REVIEW**, or **BLOCK** with check-by-check explanations.

## Security boundary

PayGuard does not sign, authorize, or execute payments, and it does not independently enforce a block. A `PASS` means only that the supplied request fields match the supplied policy. It does **not** authenticate the merchant, prove request origin, inspect chain state or token contract safety, or guarantee a payment is safe.

Never put private keys, seed phrases, API tokens, or user credentials into this repository.

## MVP checks

- HTTPS resource URL matches the user's expected resource.
- Payment scheme, network, asset identifier, recipient, atomic-unit amount, and validity timeout match explicit policy.
- Conflicting current and legacy amount fields fail closed.
- Mixed acceptable and unacceptable payment alternatives do not receive an overall `PASS`.
- Incomplete policy returns `REVIEW`.

## Local development

Requires Node.js 20+.

```bash
npm test
npm run build
```

## Example

See the tests for complete request and policy examples. Amounts are integer strings in the asset's smallest units; do not use floating-point values for payment amounts.

## Flow

```mermaid
flowchart TD
    A["User / AI agent supplies URL"] --> B["URL Sentinel parses locally"]
    B --> C["Check hostname, URL syntax, lookalikes and wallet-secret signals"]
    C --> D{"Explicit reputation lookup requested?"}
    D -->|No| E["Return heuristic assessment"]
    D -->|Yes| F["Optional Google Web Risk lookup"]
    F --> G["Known threat / no match / unavailable"]
    G --> H["Explain findings and limitations"]
    E --> H
    H --> I["Prepare redacted report draft"]
    I --> J["User reviews report"]
    J --> K["Submit only via a verified reporting channel"]
```

URL Sentinel does not open or fetch the submitted URL, read the user's computer, request wallet secrets, or automatically notify PayBox. Reputation lookup is opt-in and sends the normalized origin/path without query parameters to Google Web Risk. The URL path may still contain identifiers, so only enable reputation lookup when it is appropriate to share that URL with the provider.

## URL Sentinel

PayGuard includes a URL Sentinel tool for checking a user-supplied URL for common phishing and impersonation indicators. It parses the supplied address but never opens the submitted URL. Checks include embedded credentials, non-HTTPS URLs, IP-literal hosts, punycode/IDN labels, URL shorteners, likely lookalikes compared with a separately supplied trusted domain, suspicious PayBox-branded hostnames, wallet-recovery terminology, and a resource/expected-domain mismatch.

Verdicts are evidence-oriented:
- `KNOWN_MALICIOUS`: an enabled Google Web Risk lookup returned a threat match.
- `SUSPICIOUS` / `CAUTION`: heuristic signals need independent verification.
- `EXPECTED_DOMAIN_MATCH`: a hostname matches a user-supplied trusted domain; this does not guarantee the page is safe.
- `NO_KNOWN_THREAT`: the configured reputation lookup found no match; absence of a match is not proof of legitimacy.
- `UNVERIFIED`: the available information is insufficient to call the website legitimate.

### Optional Google Web Risk lookup

Set `GOOGLE_WEB_RISK_API_KEY` in the **server-side environment only**. The tool performs a lookup only when `checkReputation: true` is explicitly supplied. To reduce accidental disclosure, the reputation query removes all URL query parameters, credentials and fragments; this may miss threat records scoped to those parts of a URL. The API key is sent in the request header and is never expected as tool input.

Google lists the Web Risk Lookup API's first 100,000 calls per month as free at the time of writing; confirm current pricing and terms before deployment: https://cloud.google.com/web-risk/pricing

## Passive Website Snapshot Scanner

PayGuard now includes a first, deliberately limited website-analysis module. It analyzes caller-supplied HTML, response headers and URL metadata without contacting the target website.

The module is exposed through `POST /api/scan-website-snapshot`. It reports selected HTTP security-header gaps, password fields on HTTP pages, HTTPS forms targeting HTTP, cross-origin form destinations, mixed-content references, inline-script inventory and a supplied cross-origin final URL.

**Important:** this endpoint does not fetch the submitted URL. It makes zero network requests and does not independently verify the supplied snapshot. A report with no findings is labelled `NO_OBVIOUS_ISSUES_IN_SUPPLIED_SNAPSHOT`, not `SAFE`. The caller must obtain any HTML and headers through an independently authorized and SSRF-safe collection process.

See [docs/website-scanner.md](docs/website-scanner.md) for input limits, checks, report fields and limitations. Automated tests live in `test/website-scanner.test.mjs`.

## Threat Intelligence Feed Foundation

PayGuard includes bounded parsers and exact-URL matching for OpenPhish URL lists and URLhaus CSV, plus provider freshness/provenance snapshots. This foundation does not download feeds or automatically classify URLs; production refresh workers, storage and provider terms review are still required. See [docs/threat-intelligence.md](docs/threat-intelligence.md).

## TLS and Certificate Intelligence

For HTTPS collection, PayGuard records the negotiated TLS protocol, cipher name and a limited peer-certificate summary from Node's TLS socket, including available diagnostics when certificate verification fails. Deterministic analysis flags deprecated TLS versions and certificates approaching expiry. Certificate validation remains enabled; PayGuard does not disable TLS verification. See [docs/tls-intelligence.md](docs/tls-intelligence.md) for exact coverage and limitations. HTTP scans correctly report TLS as not observed.

## Safe Passive Website Collection

The `POST /api/scan-website` endpoint performs a bounded GET of one public HTML document and analyzes the returned snapshot. It is separate from the no-network `POST /api/scan-website-snapshot` endpoint.

Network collection is disabled by default. Set `PAYGUARD_ENABLE_PASSIVE_COLLECTION=true` only behind authentication or a trusted API gateway, with quotas and outbound egress restrictions. Do not expose it as an unauthenticated public fetch proxy.

The initial collector accepts only HTTP(S) on standard ports, public IPv4 addresses, HTML responses, and a small response-size limit. DNS is checked before every request, the selected IPv4 address is pinned for that request, redirects are manual and bounded, and HTTPS-to-HTTP downgrade redirects are rejected. It does not execute JavaScript, crawl links, submit forms, send cookies or credentials, or run active vulnerability tests.

IPv6 is intentionally unsupported in this first collector. Production deployments should additionally enforce outbound network egress rules blocking private, link-local, metadata-service and internal destinations. See [docs/website-scanner.md](docs/website-scanner.md) for the full security boundary and [docs/tls-intelligence.md](docs/tls-intelligence.md) for TLS evidence semantics. The implementation handoff and remaining engineering tasks are in [docs/cloud-handoff.md](docs/cloud-handoff.md).

## Threat reports

`payguard_prepare_threat_report` creates a redacted JSON draft. It does not submit the report or notify PayBox because no verified official reporting endpoint is configured in this project. Review and submit it only through a route confirmed by PayBox. Reports are allegations for investigation, not proof of malicious intent. The draft does not include free-form user notes because automated secret redaction cannot reliably identify every seed phrase or credential format.

## Local API, k6 and Grafana testing

This repository includes a read-only HTTP wrapper for local testing, k6 scenarios, Prometheus metrics, and a provisioned Grafana dashboard. These are development tools; they do not execute payments or prove transaction blocking.

### Requirements

- Node.js 20+ for the API and automated tests.
- Docker Desktop with Docker Compose v2 for Grafana, Prometheus, and k6 containers.

### Run automated tests

```bash
npm test
npm run build
node --check server.mjs
node --check dist/plugin.mjs
```

### Start the API directly

```bash
npm start
```

The local API defaults to `http://127.0.0.1:8080` and provides `GET /health`, `GET /metrics`, and these JSON POST endpoints:

- `/api/analyze-url`
- `/api/check-payment`
- `/api/threat-report`
- `/api/scan-website-snapshot`
- `/api/scan-website`

For `/api/analyze-url`, the submitted URL is parsed but never visited. The separate `/api/scan-website` endpoint performs the restricted passive GET described above. Reputation lookup in URL Sentinel is disabled unless a request explicitly sets `checkReputation: true` and the server-side `GOOGLE_WEB_RISK_API_KEY` is configured.

### Interactive Web Dashboard

Open `http://127.0.0.1:8080/dashboard` (or simply visit the root URL `http://127.0.0.1:8080` in any web browser) to access the interactive PayGuard UI:
- **Telemetry & Service Health**: Real-time health check, uptime, total request counter, and in-flight request status.
- **URL Sentinel Scanner**: Interactive sandbox with preset attack simulations (Unicode homoglyphs, brand spoofing, subdomain/suffix bypasses, credential leak detection) and instant verdict rationale.
- **Payment Guard Policy Studio**: Test autonomous agent payment criteria against custom policies (`PASS`, `REVIEW`, `BLOCK`).
- **Threat Report Studio**: Produce sanitized incident report drafts with client-side credential redaction and JSON export.
- **x402 Bazaar Discovery & Simulator**: View registered payment-gated capabilities and inspect simulated HTTP 402 challenge payloads.

### Start Grafana and Prometheus

Copy `.env.example` to `.env`, then set a long, unique value for `GRAFANA_ADMIN_PASSWORD`. Keep `.env` private.

```bash
docker compose up --build -d payguard-api prometheus grafana
docker compose ps
```

Open Grafana at http://127.0.0.1:3000 (username `admin`, password from `.env`). Prometheus is at http://127.0.0.1:9090. Ports bind to loopback only.

### Run k6

With the services above running, execute:

```bash
docker compose --profile loadtest run --rm k6 run -o experimental-prometheus-rw /scripts/smoke.js
docker compose --profile loadtest run --rm k6 run -o experimental-prometheus-rw /scripts/load.js
```

The load scenario ramps up to 25 virtual users for about 90 seconds. Initial thresholds are development targets (less than 1% failed requests, p95 below 500 ms, p99 below 1 second), not production capacity guarantees. k6 sends metrics to the enabled Prometheus remote-write receiver; Grafana's `PayGuard API & k6 Load Test` dashboard displays request rate, latency, HTTP errors, verdicts, and in-flight API requests.

Stop the stack with `docker compose down`. Use `docker compose down -v` only if you intend to delete persisted metrics and Grafana data.

Metrics use low-cardinality route/status/verdict labels and deliberately omit the submitted URL and domain. Concurrency limits and sliding window rate limits are implemented in `server.mjs`.

## x402 Protocol & Bazaar Discovery

PayGuard implements the x402 HTTP 402 Payment Required flow and provides standard Bazaar discovery metadata for autonomous AI agents in `paybox.mjs`:
- Unpaid requests can receive an HTTP 402 challenge with payment requirement fields and Bazaar discovery catalog information.
- Supports Base Sepolia testnet (`eip155:84532`) and test USDC asset configuration.
- Verifies payment proofs (`Payment-Signature` / CDP transaction proof) to settle security report requests.

## PayBox Marketplace Integration

PayGuard exports an MCP/x402 compliant plugin manifest in `paybox.mjs` exposing:
- `payguard_analyze_url`: URL phishing and impersonation sentinel
- `payguard_check_payment_intent`: x402 payment requirements policy verifier
- `payguard_prepare_threat_report`: privacy-redacted threat report generator

Integration verification status: Local unit and end-to-end simulated flows verified; distribution artifacts are bundled into standalone ESM and CommonJS modules (`dist/index.js`, `dist/index.mjs`, `dist/index.cjs`, `dist/plugin.mjs`) with zero external runtime dependencies and integrated Model Context Protocol (MCP) stdio discovery (`initialize`, `tools/list`, and `tools/call`) so marketplace checkers can discover tools without executing them. See [PAYBOX_SUBMISSION.md](file:///e:/PayGuard.-main/PAYBOX_SUBMISSION.md) for complete checklist.

## License

MIT
