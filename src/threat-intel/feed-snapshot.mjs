const SUPPORTED_PROVIDERS = new Set(["openphish", "urlhaus"]);
const DEFAULT_FEED_STALE_MS = 6 * 60 * 60 * 1000;

export function buildThreatIntelSnapshot(feedResults, {
  now = Date.now(),
  staleAfterMs = DEFAULT_FEED_STALE_MS,
  providerStaleAfterMs = {}
} = {}) {
  if (!Array.isArray(feedResults)) throw new TypeError("feedResults must be an array.");
  if (!Number.isFinite(now) || !Number.isFinite(staleAfterMs) || staleAfterMs < 0) {
    throw new TypeError("now and staleAfterMs must be valid non-negative timestamps.");
  }

  const providers = [];
  const indicatorsByKey = new Map();

  for (const feed of feedResults) {
    if (!feed || !SUPPORTED_PROVIDERS.has(feed.provider) || !Array.isArray(feed.indicators)) continue;
    const fetchedAtMs = typeof feed.fetchedAt === "string" ? Date.parse(feed.fetchedAt) : NaN;
    const fetchedAt = Number.isFinite(fetchedAtMs) ? new Date(fetchedAtMs).toISOString() : null;
    const ageMs = Number.isFinite(fetchedAtMs) ? Math.max(0, now - fetchedAtMs) : null;
    const providerLimit = Number.isFinite(providerStaleAfterMs?.[feed.provider]) && providerStaleAfterMs[feed.provider] >= 0
      ? providerStaleAfterMs[feed.provider]
      : staleAfterMs;
    const freshness = ageMs === null ? "unknown" : ageMs > providerLimit ? "stale" : "current";

    providers.push({
      provider: feed.provider,
      status: freshness === "current" ? "available" : freshness === "stale" ? "stale" : "unknown",
      fetchedAt,
      ageMs,
      freshness,
      indicatorCount: feed.indicators.length,
      rejectedCount: Number.isSafeInteger(feed.rejected) && feed.rejected >= 0 ? feed.rejected : 0
    });

    for (const indicator of feed.indicators) {
      if (!indicator || indicator.source !== feed.provider || typeof indicator.value !== "string") continue;
      const key = feed.provider + "|" + indicator.value;
      if (!indicatorsByKey.has(key)) indicatorsByKey.set(key, indicator);
    }
  }

  return {
    schemaVersion: 1,
    generatedAt: new Date(now).toISOString(),
    providers,
    indicatorCount: indicatorsByKey.size,
    indicators: [...indicatorsByKey.values()]
  };
}
