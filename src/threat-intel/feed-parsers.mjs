import { normalizeThreatIndicator } from "./indicator-normalization.mjs";

const MAX_FEED_BYTES = 5 * 1024 * 1024;
const MAX_INDICATORS = 50_000;

function boundedText(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_FEED_BYTES) {
    throw new TypeError("Threat feed must be a string no larger than 5 MiB.");
  }
  return value;
}

function parseCsvLine(line) {
  const fields = [];
  let value = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"' && quoted && line[i + 1] === '"') {
      value += '"';
      i++;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      fields.push(value);
      value = "";
    } else {
      value += char;
    }
  }
  if (quoted) return null;
  fields.push(value);
  return fields;
}

export function parseOpenPhishFeed(text, { observedAt = new Date().toISOString() } = {}) {
  const lines = boundedText(text).split(/\r?\n/);
  const indicators = [];
  let rejected = 0;
  for (const raw of lines) {
    const value = raw.trim();
    if (!value || value.startsWith("#")) continue;
    const indicator = normalizeThreatIndicator({ url: value, source: "openphish", threat: "phishing", observedAt });
    if (indicator) indicators.push(indicator);
    else rejected++;
    if (indicators.length + rejected > MAX_INDICATORS) throw new RangeError("Threat feed exceeds the 50,000-record limit.");
  }
  return { provider: "openphish", indicators, rejected, parsedAt: new Date().toISOString() };
}

export function parseUrlhausCsvFeed(text, { observedAt = new Date().toISOString() } = {}) {
  const lines = boundedText(text).split(/\r?\n/);
  const indicators = [];
  let rejected = 0;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const fields = parseCsvLine(line);
    if (!fields || fields.length < 5) {
      rejected++;
      continue;
    }
    // URLhaus CSV columns: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter.
    const [id, dateadded, url, , threat, , reference] = fields;
    const indicator = normalizeThreatIndicator({
      url,
      source: "urlhaus",
      threat: threat || "malware",
      observedAt: dateadded || observedAt,
      reference: reference || (id ? `https://urlhaus.abuse.ch/url/${encodeURIComponent(id)}/` : null)
    });
    if (indicator) indicators.push(indicator);
    else rejected++;
    if (indicators.length + rejected > MAX_INDICATORS) throw new RangeError("Threat feed exceeds the 50,000-record limit.");
  }
  return { provider: "urlhaus", indicators, rejected, parsedAt: new Date().toISOString() };
}
