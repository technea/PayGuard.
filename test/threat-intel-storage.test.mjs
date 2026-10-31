import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  createMemoryKvStore,
  createRestKvStore,
  saveThreatSnapshot,
  loadActiveThreatSnapshot,
  refreshThreatFeeds,
  validateProviderConfig,
  buildThreatIntelSnapshot,
  normalizeThreatIndicator
} from "../src/threat-intel/index.mjs";

const KEY = "k".repeat(40);
const NOW = Date.parse("2026-10-31T12:00:00Z");

const indicator = (n, source = "openphish") =>
  normalizeThreatIndicator({ url: "https://bad" + n + ".example/login", source, threat: "phishing", observedAt: "2026-10-31T10:00:00Z" });

function snapshotOf(count, source = "openphish") {
  return buildThreatIntelSnapshot(
    [{ provider: source, indicators: Array.from({ length: count }, (_, i) => indicator(i, source)), rejected: 0, fetchedAt: "2026-10-31T11:00:00Z" }],
    { now: NOW }
  );
}

test("memory KV honours TTL and counters", async () => {
  let t = 1000;
  const kv = createMemoryKvStore({ now: () => t });
  await kv.set("a", "1", { ttlSeconds: 10 });
  assert.equal(await kv.get("a"), "1");
  t += 11_000;
  assert.equal(await kv.get("a"), null);
  assert.equal(await kv.incr("c"), 1);
  assert.equal(await kv.incr("c"), 2);
});

test("REST KV adapter speaks the Redis-REST command protocol against a local fake and never leaks the token in errors", async () => {
  const store = new Map();
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ auth: req.headers.authorization, cmd: JSON.parse(body) });
      const [op, key, value] = JSON.parse(body);
      if (req.headers.authorization !== "Bearer sekret-token") { res.statusCode = 401; return res.end("{}"); }
      let result = null;
      if (op === "SET") { store.set(key, value); result = "OK"; }
      else if (op === "GET") result = store.get(key) ?? null;
      else if (op === "DEL") { store.delete(key); result = 1; }
      else if (op === "INCR") { const n = Number(store.get(key) ?? 0) + 1; store.set(key, String(n)); result = n; }
      else if (op === "EXPIRE") result = 1;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ result }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = "http://127.0.0.1:" + server.address().port;
  try {
    const kv = createRestKvStore({ baseUrl: url, token: "sekret-token", allowInsecure: true });
    await kv.set("x", "hello", { ttlSeconds: 60 });
    assert.equal(await kv.get("x"), "hello");
    assert.deepEqual(seen[0].cmd, ["SET", "x", "hello", "EX", "60"]);
    assert.equal(await kv.incr("n"), 1);
    await kv.del("x");
    assert.equal(await kv.get("x"), null);
    const bad = createRestKvStore({ baseUrl: url, token: "wrong-token", allowInsecure: true });
    await assert.rejects(() => bad.get("x"), (e) => /HTTP 401/.test(e.message) && !e.message.includes("wrong-token"));
  } finally {
    server.close();
  }
  assert.throws(() => createRestKvStore({ baseUrl: "http://example.com", token: "t" }), /HTTPS/);
  assert.throws(() => createRestKvStore({ baseUrl: "https://u:p@example.com", token: "t" }), /credentials/);
});

test("snapshot round-trips across multiple chunks with signature and hash verification", async () => {
  const kv = createMemoryKvStore();
  const snap = snapshotOf(300);
  const saved = await saveThreatSnapshot(kv, snap, { hmacKey: KEY, chunkBytes: 4000 });
  assert.ok(saved.chunkCount > 1);
  const loaded = await loadActiveThreatSnapshot(kv, { hmacKey: KEY });
  assert.equal(loaded.ok, true);
  assert.equal(loaded.rolledBack, false);
  assert.equal(loaded.snapshot.indicators.length, 300);
  assert.deepEqual(loaded.snapshot.indicators[7], snap.indicators[7]);
});

test("storage refuses to operate without a strong HMAC key", async () => {
  const kv = createMemoryKvStore();
  await assert.rejects(() => saveThreatSnapshot(kv, snapshotOf(1), { hmacKey: "short" }), /HMAC key/);
  await assert.rejects(() => loadActiveThreatSnapshot(kv, {}), /HMAC key/);
});

test("tampered chunk is rejected and the previous generation is used instead", async () => {
  const kv = createMemoryKvStore();
  await saveThreatSnapshot(kv, snapshotOf(5), { hmacKey: KEY });
  const second = await saveThreatSnapshot(kv, snapshotOf(8), { hmacKey: KEY });
  const chunkKey = "payguard:ti:gen:" + second.generation + ":chunk:0";
  const original = await kv.get(chunkKey);
  await kv.set(chunkKey, original.replace("bad0.example", "evil.example"));
  const loaded = await loadActiveThreatSnapshot(kv, { hmacKey: KEY });
  assert.equal(loaded.ok, true);
  assert.equal(loaded.rolledBack, true);
  assert.equal(loaded.rollbackReason, "chunk_hash_mismatch");
  assert.equal(loaded.snapshot.indicators.length, 5);
});

test("forged manifest (wrong HMAC key) is rejected with no fallback available", async () => {
  const kv = createMemoryKvStore();
  await saveThreatSnapshot(kv, snapshotOf(3), { hmacKey: KEY });
  const loaded = await loadActiveThreatSnapshot(kv, { hmacKey: "z".repeat(40) });
  assert.equal(loaded.ok, false);
  assert.equal(loaded.reason, "manifest_signature_invalid");
});

const feedText = (n, prefix = "bad") => Array.from({ length: n }, (_, i) => "https://" + prefix + i + ".example/p").join("\n");
const okFetch = (map) => async (url, init) => {
  assert.equal(init.redirect, "error", "refresher must never follow redirects");
  const v = map[url];
  if (v instanceof Error) throw v;
  return new Response(v.body, { status: v.status ?? 200, headers: v.headers });
};
const OP = [{ provider: "openphish", url: "https://feeds.example/op.txt" }];

test("refresh stores a verified snapshot and reports per-provider outcome", async () => {
  const kv = createMemoryKvStore();
  const res = await refreshThreatFeeds(OP, kv, { hmacKey: KEY, now: NOW, fetchImpl: okFetch({ "https://feeds.example/op.txt": { body: feedText(10) } }) });
  assert.equal(res.stored, true);
  assert.deepEqual(res.outcomes, [{ provider: "openphish", status: "updated", indicatorCount: 10, rejected: 0 }]);
  const loaded = await loadActiveThreatSnapshot(kv, { hmacKey: KEY });
  assert.equal(loaded.snapshot.indicatorCount, 10);
  assert.equal(loaded.snapshot.providers[0].fetchedAt, new Date(NOW).toISOString());
});

test("failed, empty or sharply shrunken refresh never replaces a healthy snapshot", async () => {
  const kv = createMemoryKvStore();
  await refreshThreatFeeds(OP, kv, { hmacKey: KEY, now: NOW, fetchImpl: okFetch({ "https://feeds.example/op.txt": { body: feedText(10) } }) });
  const before = (await loadActiveThreatSnapshot(kv, { hmacKey: KEY })).generation;
  const cases = {
    "http 500": { body: "oops", status: 500 },
    "network error": new Error("down"),
    "empty feed": { body: "" },
    "sharp drop": { body: feedText(2) }
  };
  for (const [name, response] of Object.entries(cases)) {
    const res = await refreshThreatFeeds(OP, kv, { hmacKey: KEY, now: NOW + 3600_000, fetchImpl: okFetch({ "https://feeds.example/op.txt": response }) });
    assert.equal(res.stored, false, name);
    assert.equal(res.reason, "no_provider_accepted", name);
    assert.equal((await loadActiveThreatSnapshot(kv, { hmacKey: KEY })).generation, before, name);
  }
});

test("when one provider fails, its previous indicators are kept with their ORIGINAL fetch time", async () => {
  const kv = createMemoryKvStore();
  const both = [
    { provider: "openphish", url: "https://feeds.example/op.txt", staleAfterMs: 12 * 3600_000 },
    { provider: "urlhaus", url: "https://feeds.example/uh.csv", staleAfterMs: 12 * 3600_000 }
  ];
  const csv = (n) => Array.from({ length: n }, (_, i) => i + ',"2026-10-31 09:00:00","https://mal' + i + '.example/x","online","malware_download","","https://urlhaus.abuse.ch/url/' + i + '/","r"').join("\n");
  await refreshThreatFeeds(both, kv, { hmacKey: KEY, now: NOW, fetchImpl: okFetch({ "https://feeds.example/op.txt": { body: feedText(4) }, "https://feeds.example/uh.csv": { body: csv(3) } }) });
  const later = NOW + 14 * 3600_000;
  const res = await refreshThreatFeeds(both, kv, { hmacKey: KEY, now: later, fetchImpl: okFetch({ "https://feeds.example/op.txt": { body: feedText(4, "new") }, "https://feeds.example/uh.csv": new Error("down") }) });
  assert.equal(res.stored, true);
  assert.equal(res.outcomes.find((o) => o.provider === "urlhaus").status, "kept_previous");
  const snap = (await loadActiveThreatSnapshot(kv, { hmacKey: KEY })).snapshot;
  const uh = snap.providers.find((p) => p.provider === "urlhaus");
  assert.equal(uh.fetchedAt, new Date(NOW).toISOString());
  assert.equal(uh.freshness, "stale");
  assert.equal(uh.indicatorCount, 3);
  assert.equal(snap.providers.find((p) => p.provider === "openphish").freshness, "current");
});

test("per-provider staleness: a 12-hourly feed is not 'stale' at 8 hours old", () => {
  const feed = [{ provider: "openphish", indicators: [], rejected: 0, fetchedAt: new Date(NOW - 8 * 3600_000).toISOString() }];
  assert.equal(buildThreatIntelSnapshot(feed, { now: NOW }).providers[0].freshness, "stale");
  assert.equal(buildThreatIntelSnapshot(feed, { now: NOW, providerStaleAfterMs: { openphish: 24 * 3600_000 } }).providers[0].freshness, "current");
});

test("oversized feed bodies are aborted and rejected", async () => {
  const kv = createMemoryKvStore();
  const big = "https://a.example/\n".repeat(400_000);
  const res = await refreshThreatFeeds(OP, kv, { hmacKey: KEY, now: NOW, fetchImpl: okFetch({ "https://feeds.example/op.txt": { body: big } }) });
  assert.equal(res.stored, false);
  assert.equal(res.outcomes[0].reason, "feed_too_large_or_limit_exceeded");
});

test("provider config rejects non-HTTPS, credentials, duplicates, unknown providers and header injection", () => {
  assert.throws(() => validateProviderConfig([{ provider: "openphish", url: "http://x.example/f" }]), /HTTPS/);
  assert.throws(() => validateProviderConfig([{ provider: "openphish", url: "https://u:p@x.example/f" }]), /HTTPS/);
  assert.throws(() => validateProviderConfig([{ provider: "evil", url: "https://x.example/f" }]), /Unsupported/);
  assert.throws(() => validateProviderConfig([{ provider: "openphish", url: "https://x.example/a" }, { provider: "openphish", url: "https://x.example/b" }]), /Duplicate/);
  assert.throws(() => validateProviderConfig([{ provider: "openphish", url: "https://x.example/a", headers: { a: "b\r\nx: y" } }]), /header/);
  assert.throws(() => validateProviderConfig([]), /At least one/);
});
