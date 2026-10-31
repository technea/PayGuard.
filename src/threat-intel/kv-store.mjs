// Minimal key-value contract used by threat-intel storage (and later quotas):
//   get(key) -> string | null
//   set(key, value, { ttlSeconds? }) -> void
//   del(key) -> void
//   incr(key) -> number
//   expire(key, ttlSeconds) -> void
// Two adapters: in-memory (tests / local) and a Redis-REST adapter (Upstash / Vercel KV style).

export function createMemoryKvStore({ now = () => Date.now() } = {}) {
  const data = new Map();
  const live = (key) => {
    const entry = data.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt <= now()) {
      data.delete(key);
      return null;
    }
    return entry;
  };
  return {
    kind: "memory",
    async get(key) {
      return live(key)?.value ?? null;
    },
    async set(key, value, { ttlSeconds } = {}) {
      data.set(key, { value: String(value), expiresAt: ttlSeconds ? now() + ttlSeconds * 1000 : null });
    },
    async del(key) {
      data.delete(key);
    },
    async incr(key) {
      const entry = live(key);
      const next = (entry ? Number.parseInt(entry.value, 10) || 0 : 0) + 1;
      data.set(key, { value: String(next), expiresAt: entry ? entry.expiresAt : null });
      return next;
    },
    async expire(key, ttlSeconds) {
      const entry = live(key);
      if (entry) entry.expiresAt = now() + ttlSeconds * 1000;
    }
  };
}

export function createRestKvStore({
  baseUrl,
  token,
  fetchImpl = globalThis.fetch,
  timeoutMs = 5000,
  allowInsecure = false
} = {}) {
  if (typeof baseUrl !== "string" || typeof token !== "string" || !token) {
    throw new TypeError("REST KV store requires baseUrl and token.");
  }
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new TypeError("REST KV baseUrl is not a valid URL.");
  }
  if (parsed.username || parsed.password) throw new TypeError("REST KV baseUrl must not embed credentials.");
  if (parsed.protocol !== "https:" && !(allowInsecure && parsed.protocol === "http:")) {
    throw new TypeError("REST KV baseUrl must use HTTPS.");
  }
  if (typeof fetchImpl !== "function") throw new TypeError("A fetch implementation is required.");

  // The token is never included in thrown errors.
  async function command(args) {
    let response;
    try {
      response = await fetchImpl(parsed.toString(), {
        method: "POST",
        headers: { authorization: "Bearer " + token, "content-type": "application/json" },
        body: JSON.stringify(args),
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs)
      });
    } catch {
      throw new Error("KV request failed (network, timeout or redirect).");
    }
    if (!response.ok) throw new Error("KV request rejected with HTTP " + response.status + ".");
    let body;
    try {
      body = await response.json();
    } catch {
      throw new Error("KV response was not valid JSON.");
    }
    if (!body || typeof body !== "object" || body.error) throw new Error("KV command returned an error.");
    return body.result;
  }

  return {
    kind: "rest",
    async get(key) {
      const result = await command(["GET", key]);
      return typeof result === "string" ? result : null;
    },
    async set(key, value, { ttlSeconds } = {}) {
      const args = ["SET", key, String(value)];
      if (ttlSeconds) args.push("EX", String(Math.floor(ttlSeconds)));
      await command(args);
    },
    async del(key) {
      await command(["DEL", key]);
    },
    async incr(key) {
      const result = await command(["INCR", key]);
      if (!Number.isSafeInteger(result)) throw new Error("KV INCR returned a non-integer.");
      return result;
    },
    async expire(key, ttlSeconds) {
      await command(["EXPIRE", key, String(Math.floor(ttlSeconds))]);
    }
  };
}

// Vercel KV / Upstash expose KV_REST_API_URL + KV_REST_API_TOKEN (or UPSTASH_REDIS_REST_*).
export function createKvStoreFromEnv(env = process.env, options = {}) {
  const baseUrl = env.KV_REST_API_URL || env.UPSTASH_REDIS_REST_URL;
  const token = env.KV_REST_API_TOKEN || env.UPSTASH_REDIS_REST_TOKEN;
  if (!baseUrl || !token) return null;
  return createRestKvStore({ baseUrl, token, ...options });
}
