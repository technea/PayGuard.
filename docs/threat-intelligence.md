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

## Feed refresh and storage (implemented, unit-tested, not yet verified live)

- `feed-refresh.mjs`: `refreshThreatFeeds(providerConfig, kv, options)` performs one refresh cycle. Provider endpoints come only from operator configuration (`providerConfigFromEnv`: `PAYGUARD_OPENPHISH_FEED_URL`, `PAYGUARD_URLHAUS_FEED_URL`, optional `PAYGUARD_URLHAUS_AUTH_KEY`). They must be HTTPS without embedded credentials, and requests never follow redirects. No request input can select a feed URL.
- Downloads are bounded (5 MiB, streamed and aborted on overrun, 15 s timeout). A failed, empty, below-minimum or sharply shrunken (<50% of previous) download keeps that provider's previous indicators with their original fetch time, so freshness stays truthful. A cycle in which no provider is accepted writes nothing.
- `kv-store.mjs`: key-value contract with an in-memory adapter and a Redis-REST adapter (`KV_REST_API_URL` / `KV_REST_API_TOKEN`, or `UPSTASH_REDIS_REST_*`). HTTPS is required and the token is never included in error messages.
- `snapshot-store.mjs`: each snapshot is written as an immutable generation (chunked indicators plus a manifest signed with HMAC-SHA256 using `PAYGUARD_FEED_HMAC_KEY`, 32+ characters). The active pointer moves only after all writes succeed. Loading verifies the manifest signature and every chunk hash; a failed generation falls back to the previous one and reports `rolledBack`. This detects tampering with stored data by anyone without the HMAC key. It does not prove that the provider's data was genuine, and an attacker with KV write access could still point to an older valid generation, which freshness labels will show.
- Per-provider staleness (`providerStaleAfterMs`): the OpenPhish community feed is documented as updated every 12 hours, so the global 6-hour default would mark a healthy feed stale.

**What is verified:** unit tests with a fake `fetch`, an in-memory store and a local fake Redis-REST server, including tamper, rollback and mutation checks. **What is not verified:** behaviour against the real OpenPhish/URLhaus endpoints, a real Upstash/Vercel KV instance, and serverless cold-start cost of loading a multi-MB snapshot. The REST adapter follows the Upstash-style command protocol; confirm it against your actual KV before relying on it. The `auth-key` header name for URLhaus is an assumption to confirm in abuse.ch documentation.

**Licensing flag:** the OpenPhish public feed page lists it as non-commercial use only. Confirm that matches how PayGuard will be used before enabling it.

## Not implemented yet

- No scheduler or trigger that calls `refreshThreatFeeds` (it needs a cron or worker deployment).
- No automatic reputation verdict in URL Sentinel.
- No wildcard/domain-level or fuzzy matching.
- No cryptographic verification of provider-side provenance (the HMAC covers PayGuard's own storage only).
- No Base/NEAR contract threat feeds.
