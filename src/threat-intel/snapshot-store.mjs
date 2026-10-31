import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";

const PREFIX = "payguard:ti:";
const ACTIVE_KEY = PREFIX + "active";
const DEFAULT_CHUNK_BYTES = 200_000;
const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const MIN_HMAC_KEY_LENGTH = 32;

function requireHmacKey(hmacKey) {
  if (typeof hmacKey !== "string" || hmacKey.length < MIN_HMAC_KEY_LENGTH) {
    throw new TypeError("An HMAC key of at least " + MIN_HMAC_KEY_LENGTH + " characters is required to store or load snapshots.");
  }
}

const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const sign = (hmacKey, text) => createHmac("sha256", hmacKey).update(text).digest("hex");

function safeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function chunkIndicators(indicators, chunkBytes) {
  const chunks = [];
  let current = [];
  let size = 2;
  for (const indicator of indicators) {
    const encoded = JSON.stringify(indicator);
    const bytes = Buffer.byteLength(encoded) + 1;
    if (current.length && size + bytes > chunkBytes) {
      chunks.push(current);
      current = [];
      size = 2;
    }
    current.push(indicator);
    size += bytes;
  }
  if (current.length || !chunks.length) chunks.push(current);
  return chunks;
}

// Writes a new immutable generation (chunks + signed manifest) and only then moves the
// active pointer, so a failed or partial write can never replace a healthy snapshot.
export async function saveThreatSnapshot(kv, snapshot, {
  hmacKey,
  chunkBytes = DEFAULT_CHUNK_BYTES,
  ttlSeconds = DEFAULT_TTL_SECONDS
} = {}) {
  requireHmacKey(hmacKey);
  if (!snapshot || !Array.isArray(snapshot.indicators) || !Array.isArray(snapshot.providers)) {
    throw new TypeError("snapshot must come from buildThreatIntelSnapshot.");
  }
  const generation = randomUUID();
  const chunkEntries = [];
  for (const [index, chunk] of chunkIndicators(snapshot.indicators, chunkBytes).entries()) {
    const key = PREFIX + "gen:" + generation + ":chunk:" + index;
    const body = JSON.stringify(chunk);
    await kv.set(key, body, { ttlSeconds });
    chunkEntries.push({ key, sha256: sha256(body), count: chunk.length });
  }
  const manifest = JSON.stringify({
    schemaVersion: 1,
    generation,
    generatedAt: snapshot.generatedAt,
    providers: snapshot.providers,
    indicatorCount: snapshot.indicators.length,
    chunks: chunkEntries
  });
  await kv.set(PREFIX + "gen:" + generation + ":manifest", JSON.stringify({ manifest, sig: sign(hmacKey, manifest) }), { ttlSeconds });

  let previous = null;
  const activeRaw = await kv.get(ACTIVE_KEY);
  if (activeRaw) {
    try {
      previous = JSON.parse(activeRaw).generation ?? null;
    } catch {
      previous = null;
    }
  }
  await kv.set(ACTIVE_KEY, JSON.stringify({ generation, previous }));
  return { generation, previous, indicatorCount: snapshot.indicators.length, chunkCount: chunkEntries.length };
}

async function loadGeneration(kv, generation, hmacKey) {
  if (typeof generation !== "string" || !/^[0-9a-f-]{36}$/.test(generation)) return { ok: false, reason: "invalid_generation_id" };
  const raw = await kv.get(PREFIX + "gen:" + generation + ":manifest");
  if (!raw) return { ok: false, reason: "manifest_missing" };
  let envelope;
  try {
    envelope = JSON.parse(raw);
  } catch {
    return { ok: false, reason: "manifest_corrupt" };
  }
  if (!envelope || typeof envelope.manifest !== "string" || !safeEqualHex(envelope.sig, sign(hmacKey, envelope.manifest))) {
    return { ok: false, reason: "manifest_signature_invalid" };
  }
  const manifest = JSON.parse(envelope.manifest);
  if (manifest.generation !== generation || !Array.isArray(manifest.chunks)) return { ok: false, reason: "manifest_mismatch" };
  const indicators = [];
  for (const entry of manifest.chunks) {
    if (typeof entry.key !== "string" || !entry.key.startsWith(PREFIX + "gen:" + generation + ":chunk:")) {
      return { ok: false, reason: "chunk_key_invalid" };
    }
    const body = await kv.get(entry.key);
    if (body === null) return { ok: false, reason: "chunk_missing" };
    if (!safeEqualHex(sha256(body), entry.sha256)) return { ok: false, reason: "chunk_hash_mismatch" };
    const parsed = JSON.parse(body);
    if (!Array.isArray(parsed) || parsed.length !== entry.count) return { ok: false, reason: "chunk_count_mismatch" };
    indicators.push(...parsed);
  }
  if (indicators.length !== manifest.indicatorCount) return { ok: false, reason: "indicator_count_mismatch" };
  return {
    ok: true,
    generation,
    snapshot: {
      schemaVersion: manifest.schemaVersion,
      generatedAt: manifest.generatedAt,
      providers: manifest.providers,
      indicatorCount: manifest.indicatorCount,
      indicators
    }
  };
}

// Verifies the manifest signature and every chunk hash. If the active generation fails
// verification, falls back to the previous generation and reports that it did.
export async function loadActiveThreatSnapshot(kv, { hmacKey } = {}) {
  requireHmacKey(hmacKey);
  const activeRaw = await kv.get(ACTIVE_KEY);
  if (!activeRaw) return { ok: false, reason: "no_snapshot" };
  let active;
  try {
    active = JSON.parse(activeRaw);
  } catch {
    return { ok: false, reason: "active_pointer_corrupt" };
  }
  const primary = await loadGeneration(kv, active.generation, hmacKey);
  if (primary.ok) return { ...primary, rolledBack: false };
  if (active.previous) {
    const fallback = await loadGeneration(kv, active.previous, hmacKey);
    if (fallback.ok) return { ...fallback, rolledBack: true, rollbackReason: primary.reason };
  }
  return { ok: false, reason: primary.reason };
}
