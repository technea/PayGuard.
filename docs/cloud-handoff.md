# PayGuard Cloud Handoff

This document is the implementation handoff for continuing PayGuard work with another coding agent or cloud development environment.

## Current branch and review state

- Repository: `technea/PayGuard.`
- Branch: `feat/passive-website-scanner-foundation`
- Pull request: https://github.com/technea/PayGuard./pull/5
- PR state: draft, open, not merged.
- Do not merge without the owner's explicit approval.
- The existing landing page is intentionally unchanged.

## Implemented modules

### Passive website snapshot analysis

- `src/website-scanner/input-validation.mjs`: strict input and size validation.
- `src/website-scanner/header-analysis.mjs`: HTTP security-header checks.
- `src/website-scanner/html-analysis.mjs`: passive HTML checks.
- `src/website-scanner/index.mjs`: evidence report composition.

Endpoint: `POST /api/scan-website-snapshot`

This endpoint performs no network requests and analyzes only caller-supplied metadata.

### Restricted passive collector

- `src/website-scanner/network-policy.mjs`: public IPv4 policy and DNS validation.
- `src/website-scanner/safe-http-client.mjs`: pinned-IP HTTP(S) GET, bounded HTML response, timeout and TLS metadata.
- `src/website-scanner/collection.mjs`: redirect policy, per-hop DNS checks and report composition.

Endpoint: `POST /api/scan-website`

The collector is disabled by default. It requires `PAYGUARD_ENABLE_PASSIVE_COLLECTION=true`. Do not enable it on a public deployment until authentication, quotas, monitoring and outbound egress restrictions are independently enforced.

Current constraints:
- HTTP(S), standard ports only.
- Public IPv4 only; IPv6 intentionally unsupported.
- DNS checked before every request; mixed public/private answers rejected; chosen address pinned.
- Maximum three redirects; every destination revalidated; HTTPS downgrade blocked.
- GET only; HTML only; identity encoding; response size and timeout limits.
- No cookies, authorization forwarding, JavaScript execution, crawling, form submission or active testing.

### TLS intelligence

- `src/website-scanner/tls-analysis.mjs`
- Captures negotiated protocol, cipher, limited leaf-certificate summary and available handshake-failure diagnostics.
- Flags deprecated TLS 1.0/1.1, failed certificate verification, expired, not-yet-valid and soon-to-expire certificates.
- Standard TLS verification remains enabled.
- Does not enumerate every supported protocol/cipher, query certificate transparency, or check revocation.

## Safety and reporting contract

- Deterministic checks and observed evidence drive findings.
- Every finding has severity, confidence, evidence and remediation.
- A no-finding report is never described as proof of safety.
- Snapshot reports and live passive collection reports must remain distinguishable.
- AI may explain and prioritize findings but must not override deterministic evidence or mark an unverified site safe.
- Active scanners (ZAP, Nuclei, etc.) must be a separate workflow requiring verified domain ownership or explicit authorization, isolated workers, strict quotas and egress controls.
- Do not add wallet signing, private-key handling, or payment execution to PayGuard.

## Verification

Latest GitHub Actions run for this branch passed:
- 90 tests passed, 0 failed.
- API server syntax, distributable syntax and plugin export checks passed.
- Vercel preview deployment status: Ready.

Run locally:
```bash
npm test
node --check server.mjs
node --check dist/plugin.mjs
```

### Threat intelligence feed foundation (implemented on this branch)

- Added bounded OpenPhish URL-list and URLhaus CSV parsers.
- Added URL indicator normalization, exact URL matching, freshness labels and source provenance snapshots.
- Added parser and snapshot tests.
- See `docs/threat-intelligence.md`.
- Live feed downloads, scheduled refresh, persistence and automatic URL Sentinel integration are intentionally not implemented yet.

## Remaining work for the next implementation phase

1. Add authentication and per-account quotas before enabling network collection.
2. Enforce outbound firewall/egress restrictions at deployment level; application checks alone are not enough.
3. Add DNS/TLS edge cases and a safe IPv6 policy only after thorough tests.
4. Add threat-intelligence providers behind independent adapters with source attribution, timestamps, cache TTLs, feed-health checks, licensing review and false-positive handling. Do not hardcode stale blocklists.
5. Build deterministic evidence normalization and correlation across URL, TLS, headers, HTML and threat feeds.
6. Add an authorization-proof workflow before integrating active scanners such as ZAP or Nuclei.
7. Add Base and NEAR security adapters as separate modules, beginning with read-only contract/token/transaction risk checks.
8. Add a dashboard that presents evidence, uncertainty, scan scope and remediation without claiming certification.
9. Perform independent code review, dependency/license review, SSRF testing and deployment security review before production enablement.

## Instructions for continuing agents

- Inspect the current branch and tests before changing anything.
- Preserve the modular folder structure and avoid monolithic files.
- Do not rewrite the existing landing page.
- Do not merge this PR or other PRs without explicit owner approval.
- Do not enable the passive collection flag on a public deployment as a shortcut.
- Never claim a live scan or security control is working unless it has been tested in the actual deployment environment.
