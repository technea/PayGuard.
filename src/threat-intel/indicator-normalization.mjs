const MAX_URL_LENGTH = 4096;
const MAX_HOST_LENGTH = 253;
// Timestamps without an explicit zone (e.g. URLhaus "2026-10-31 09:00:00") are UTC.
// Date.parse would otherwise interpret them in the host's local timezone.
const ZONELESS_DATETIME = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?)$/;

export function parseThreatTimestamp(value) {
  if (typeof value !== "string") return NaN;
  const trimmed = value.trim();
  const zoneless = ZONELESS_DATETIME.exec(trimmed);
  return Date.parse(zoneless ? zoneless[1] + "T" + zoneless[2] + "Z" : trimmed);
}

export function normalizeThreatUrl(value) {
  if (typeof value !== "string" || !value || value.length > MAX_URL_LENGTH || value.trim() !== value) return null;
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return null;
    url.hash = "";
    url.hostname = url.hostname.toLowerCase().replace(/\.$/, "");
    if (!url.hostname || url.hostname.length > MAX_HOST_LENGTH) return null;
    if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) url.port = "";
    return url.toString();
  } catch {
    return null;
  }
}

export function normalizeThreatIndicator(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const url = normalizeThreatUrl(input.url);
  if (!url) return null;
  const source = typeof input.source === "string" && /^[a-z0-9_-]{2,40}$/i.test(input.source)
    ? input.source.toLowerCase()
    : null;
  if (!source) return null;
  const observedAtMs = parseThreatTimestamp(input.observedAt);
  const observedAt = Number.isFinite(observedAtMs) ? new Date(observedAtMs).toISOString() : null;
  const threat = typeof input.threat === "string" ? input.threat.slice(0, 80) : "unspecified";
  const reference = typeof input.reference === "string" && /^https:\/\//i.test(input.reference)
    ? input.reference.slice(0, 500)
    : null;
  return {
    indicatorType: "url",
    value: url,
    hostname: new URL(url).hostname,
    source,
    threat,
    observedAt,
    reference
  };
}
