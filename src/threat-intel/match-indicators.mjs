import { normalizeThreatUrl } from "./indicator-normalization.mjs";

export function matchThreatIndicators(target, indicators, { now = Date.now(), maxAgeMs = 7 * 24 * 60 * 60 * 1000 } = {}) {
  const normalizedTarget = normalizeThreatUrl(target);
  if (!normalizedTarget || !Array.isArray(indicators)) {
    return { status: "INVALID_INPUT", matches: [], checked: 0 };
  }
  const targetUrl = new URL(normalizedTarget);
  const matches = [];
  let checked = 0;
  for (const indicator of indicators) {
    if (!indicator || indicator.indicatorType !== "url" || typeof indicator.value !== "string") continue;
    checked++;
    const normalizedIndicator = normalizeThreatUrl(indicator.value);
    if (!normalizedIndicator || normalizedIndicator !== normalizedTarget) continue;
    const timestamp = typeof indicator.observedAt === "string" ? Date.parse(indicator.observedAt) : NaN;
    const ageMs = Number.isFinite(timestamp) ? Math.max(0, now - timestamp) : null;
    const stale = ageMs === null || ageMs > maxAgeMs;
    matches.push({
      source: indicator.source,
      threat: indicator.threat || "unspecified",
      observedAt: Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null,
      ageMs,
      freshness: stale ? "stale_or_undated" : "current",
      reference: indicator.reference || null
    });
  }
  return {
    status: matches.length ? "MATCH" : "NO_MATCH",
    target: targetUrl.toString(),
    checked,
    matches
  };
}
