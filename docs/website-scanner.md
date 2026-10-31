# Passive Website Snapshot Scanner

## Purpose

The first PayGuard website-scanning component analyzes a response snapshot supplied by a trusted caller. It checks selected HTTP security headers, form destinations, mixed-content references, inline-script inventory, and a supplied final URL.

## Important boundary

This module performs **zero network requests**. It does not fetch a URL, resolve DNS, perform a TLS handshake, crawl pages, execute JavaScript, or launch active vulnerability tests. The caller must obtain the HTML and response headers through an independently authorized and SSRF-safe collection process.

A result describes only the supplied snapshot. It is not a certificate that a website is safe, and it does not establish that a domain is malicious.

## Input

```json
{
  "targetUrl": "https://example.com/login",
  "finalUrl": "https://example.com/login",
  "redirects": [],
  "responseHeaders": {
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff"
  },
  "html": "<html><body>...</body></html>"
}
```

- `targetUrl` is required.
- `finalUrl`, `redirects`, `responseHeaders`, and `html` are optional.
- Only HTTP and HTTPS URLs are accepted; embedded URL credentials are rejected.
- HTML is limited to 48 KiB (the API request body is capped at 64 KiB), redirects to 10, and response headers to 100.

## Output

The report includes a scan mode, zero network-request count, observed findings, severity, confidence, evidence, remediation, and explicit limitations.

A report with no findings uses `NO_OBVIOUS_ISSUES_IN_SUPPLIED_SNAPSHOT`, never `SAFE` or `TRUSTED`.

## Current checks

- Missing HSTS, CSP, X-Content-Type-Options, Referrer-Policy and Permissions-Policy.
- Missing both CSP frame-ancestors and X-Frame-Options.
- Password inputs on HTTP pages.
- HTTPS forms targeting HTTP.
- Cross-origin form destinations.
- HTTP resource references on HTTPS pages.
- Inline-script inventory.
- Supplied final URL on a different origin.

## Not included yet

- Safe HTTP collection / SSRF-resistant fetcher.
- DNS, TLS and certificate intelligence.
- Reputation-feed ingestion.
- Authenticated scanning or active DAST.
- ZAP and Nuclei orchestration.

These will be separate modules. Active testing must require verified ownership or explicit authorization, strict scope enforcement, isolated workers, and resource limits.
