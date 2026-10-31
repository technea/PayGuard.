# Threat Intelligence Feed Foundation

PayGuard now has a provider-neutral, deterministic foundation for importing and matching URL indicators from two feed formats:

- OpenPhish URL-list format: one HTTP(S) URL per line, with blank lines and comment lines ignored.
- URLhaus CSV export format: parses the documented CSV columns for URL, threat type, date added and reference.

## Modules

- `indicator-normalization.mjs`: validates HTTP(S) URLs, strips fragments/default ports and normalizes provider identifiers.
- `feed-parsers.mjs`: bounded parsers for OpenPhish and URLhaus. Maximum input is 5 MiB and maximum accepted/rejected records per feed is 50,000.
- `match-indicators.mjs`: exact normalized URL matching only. It does not infer that every URL on a hostname is malicious.
- `feed-snapshot.mjs`: records provider fetch time, freshness, indicator counts and source provenance; deduplicates indicators by provider and URL.
- `index.mjs`: public module exports.

## Security and trust boundaries

This is a parser, normalizer and matching foundation, not an autonomous feed downloader. It does not fetch third-party feeds, persist data, schedule refreshes or claim a match is independently verified. A trusted backend feed-refresh worker must retrieve feeds from fixed provider endpoints, enforce HTTPS/timeouts/size limits, validate provider responses, record successful fetch timestamps and pass the parsed results into the snapshot builder.

Never accept user-submitted feed contents as trusted threat intelligence. Do not let an untrusted request choose arbitrary feed URLs; that would create an SSRF-capable proxy. Do not treat stale or undated indicators as current. A match means a source listed that exact URL; it is a strong lead for investigation, not proof of current malicious behaviour.

## Matching semantics

- Exact normalized URL matching; hostname-wide wildcard matching is intentionally not implemented.
- Query strings are retained because path/query may identify the exact malicious resource. Callers should avoid logging raw URLs because they may contain sensitive tokens.
- URL fragments are removed because they are not sent to web servers.
- Default ports are removed and hostnames are lowercased.
- Provider, threat label, observed time and source reference are retained as evidence.
- Stale or undated indicators remain visible but are explicitly marked `stale_or_undated`.

## Provider operations still required

Before production use, independently review each provider's current terms, attribution requirements, redistribution restrictions, rate limits and feed freshness guarantees. Implement a server-side scheduled refresh worker, authenticated administrative controls, durable storage, last-successful-fetch monitoring, cache expiry and rollback to the last known-good snapshot. A failed or empty refresh must not silently replace a healthy snapshot.

## Not implemented yet

- No live feed download or scheduled refresh.
- No persistence/database.
- No automatic reputation verdict in URL Sentinel.
- No wildcard/domain-level or fuzzy matching.
- No feed signing or cryptographic provenance verification.
- No Base/NEAR contract threat feeds.
