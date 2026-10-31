import { parseOpenPhishFeed, parseUrlhausCsvFeed } from "./feed-parsers.mjs";
import { buildThreatIntelSnapshot } from "./feed-snapshot.mjs";
import { loadActiveThreatSnapshot, saveThreatSnapshot } from "./snapshot-store.mjs";

const MAX_FEED_BYTES = 5 * 1024 * 1024;
const PARSERS = { openphish: parseOpenPhishFeed, urlhaus: parseUrlhausCsvFeed };

// Provider endpoints are OPERATOR configuration, never request input. Refreshing must not
// become an SSRF-capable proxy, so the refresher accepts only a fixed, validated provider list.
export function validateProviderConfig(config) {
  if (!Array.isArray(config) || !config.length) throw new TypeError("At least one provider must be configured.");
  const seen = new Set();
  return config.map((entry) => {
    if (!entry || !PARSERS[entry.provider]) throw new TypeError("Unsupported threat feed provider.");
    if (seen.has(entry.provider)) throw new TypeError("Duplicate provider: " + entry.provider);
    seen.add(entry.provider);
    let url;
    try {
      url = new URL(entry.url);
    } catch {
      throw new TypeError("Invalid feed URL for " + entry.provider + ".");
    }
    if (url.protocol !== "https:" || url.username || url.password) {
      throw new TypeError("Feed URL for " + entry.provider + " must be HTTPS without embedded credentials.");
    }
    const headers = {};
    for (const [name, value] of Object.entries(entry.headers ?? {})) {
      if (typeof value !== "string" || /[\r\n]/.test(name + value)) throw new TypeError("Invalid feed header.");
      headers[name.toLowerCase()] = value;
    }
    return {
      provider: entry.provider,
      url: url.toString(),
      headers,
      staleAfterMs: Number.isFinite(entry.staleAfterMs) && entry.staleAfterMs > 0 ? entry.staleAfterMs : 24 * 60 * 60 * 1000,
      minIndicators: Number.isSafeInteger(entry.minIndicators) && entry.minIndicators >= 0 ? entry.minIndicators : 1
    };
  });
}

async function readBounded(response, limit) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) throw new RangeError("Feed exceeds the 5 MiB limit.");
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Feed response had no body.");
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      throw new RangeError("Feed exceeds the 5 MiB limit.");
    }
    chunks.push(value);
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(Buffer.concat(chunks));
}

async function fetchOneProvider(config, { fetchImpl, timeoutMs, now }) {
  const response = await fetchImpl(config.url, {
    method: "GET",
    headers: { accept: "text/plain, text/csv", "user-agent": "PayGuard-feed-refresh/1", ...config.headers },
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!response.ok) throw new Error("Provider responded with HTTP " + response.status + ".");
  const text = await readBounded(response, MAX_FEED_BYTES);
  const fetchedAt = new Date(now).toISOString();
  const parsed = PARSERS[config.provider](text, { observedAt: fetchedAt });
  return { provider: config.provider, indicators: parsed.indicators, rejected: parsed.rejected, fetchedAt };
}

// One refresh cycle. Per provider: a failed, empty, implausibly small, or sharply shrunken
// download keeps that provider's previous indicators (with their OLD fetchedAt, so freshness
// tells the truth). A cycle where nothing was accepted never writes a new snapshot.
export async function refreshThreatFeeds(providerConfig, kv, {
  hmacKey,
  fetchImpl = globalThis.fetch,
  timeoutMs = 15_000,
  now = Date.now(),
  minRetainedRatio = 0.5
} = {}) {
  const configs = validateProviderConfig(providerConfig);
  const previousLoad = await loadActiveThreatSnapshot(kv, { hmacKey });
  const previous = previousLoad.ok ? previousLoad.snapshot : null;

  const feedResults = [];
  const outcomes = [];
  let accepted = 0;

  for (const config of configs) {
    const prevProvider = previous?.providers.find((p) => p.provider === config.provider) ?? null;
    const prevIndicators = previous?.indicators.filter((i) => i.source === config.provider) ?? [];
    const carryOver = (reason) => {
      outcomes.push({ provider: config.provider, status: "kept_previous", reason });
      if (prevProvider) {
        feedResults.push({
          provider: config.provider,
          indicators: prevIndicators,
          rejected: prevProvider.rejectedCount,
          fetchedAt: prevProvider.fetchedAt
        });
      }
    };
    try {
      const fresh = await fetchOneProvider(config, { fetchImpl, timeoutMs, now });
      if (fresh.indicators.length < config.minIndicators) {
        carryOver("below_minimum_indicators");
      } else if (prevIndicators.length && fresh.indicators.length < prevIndicators.length * minRetainedRatio) {
        carryOver("indicator_count_dropped_sharply");
      } else {
        feedResults.push(fresh);
        accepted++;
        outcomes.push({ provider: config.provider, status: "updated", indicatorCount: fresh.indicators.length, rejected: fresh.rejected });
      }
    } catch (error) {
      carryOver(error instanceof RangeError ? "feed_too_large_or_limit_exceeded" : "fetch_or_parse_failed");
    }
  }

  if (!accepted) return { stored: false, reason: "no_provider_accepted", outcomes };

  const snapshot = buildThreatIntelSnapshot(feedResults, {
    now,
    providerStaleAfterMs: Object.fromEntries(configs.map((c) => [c.provider, c.staleAfterMs]))
  });
  const saved = await saveThreatSnapshot(kv, snapshot, { hmacKey });
  return { stored: true, generation: saved.generation, indicatorCount: saved.indicatorCount, outcomes };
}

export function providerConfigFromEnv(env = process.env) {
  const configs = [];
  if (env.PAYGUARD_OPENPHISH_FEED_URL) {
    configs.push({ provider: "openphish", url: env.PAYGUARD_OPENPHISH_FEED_URL, staleAfterMs: 24 * 60 * 60 * 1000 });
  }
  if (env.PAYGUARD_URLHAUS_FEED_URL) {
    const headers = env.PAYGUARD_URLHAUS_AUTH_KEY ? { "auth-key": env.PAYGUARD_URLHAUS_AUTH_KEY } : {};
    configs.push({ provider: "urlhaus", url: env.PAYGUARD_URLHAUS_FEED_URL, headers, staleAfterMs: 12 * 60 * 60 * 1000 });
  }
  return configs;
}
