# Passive Website Scanner

## Snapshot analysis

`POST /api/scan-website-snapshot` analyzes caller-supplied HTML, headers and URL metadata. It makes zero network requests. See the source and tests for exact findings and limits.

## Safe passive collection

`POST /api/scan-website` retrieves one public HTML document using a restricted GET request, then passes the collected snapshot to the analyzer.

### Network safety controls

- HTTP and HTTPS only; standard ports 80 and 443 only.
- Public IPv4 targets only. IPv6 is intentionally unsupported in this first version.
- Rejects loopback, private, link-local, carrier-grade NAT, documentation, benchmarking, multicast and reserved IPv4 ranges.
- Rejects localhost and reserved hostname suffixes.
- Resolves DNS immediately before each request, rejects a hostname if any returned IPv4 address is non-public, and pins the request's DNS lookup to the validated address.
- Redirects are manual, limited to three, and revalidated independently. HTTPS-to-HTTP downgrade redirects are blocked.
- GET only. No cookies, authorization headers, form submissions, JavaScript execution, crawling, or active vulnerability tests.
- HTML-only responses, identity content encoding, bounded response size, bounded headers, and request timeout.

### Limitations

This is a best-effort SSRF-resistant public-web collector, not a substitute for network-level egress controls. Production deployment should additionally enforce outbound firewall rules that deny private, link-local, metadata-service and internal network ranges. The first version does not fetch linked resources, inspect APIs, authenticate, or perform active testing.

A report is based on one retrieved HTML response and is not a certification that a site is safe. Active scanners such as ZAP and Nuclei must remain a separate, authorization-gated workflow.
