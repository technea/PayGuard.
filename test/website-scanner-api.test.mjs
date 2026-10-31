import test from "node:test";
import assert from "node:assert/strict";
import { routes } from "../server.mjs";

test("HTTP route registry exposes passive website snapshot analysis", async () => {
  const handler = routes.get("/api/scan-website-snapshot");
  assert.equal(typeof handler, "function");
  const report = await handler({
    targetUrl: "https://example.com",
    responseHeaders: {
      "strict-transport-security": "max-age=31536000",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=()"
    }
  });
  assert.equal(report.scanner, "payguard-passive-website-snapshot");
  assert.equal(report.networkRequestsMade, 0);
  assert.equal(report.assessment, "NO_OBVIOUS_ISSUES_IN_SUPPLIED_SNAPSHOT");
});

test("HTTP route rejects malformed website snapshot input", async () => {
  const handler = routes.get("/api/scan-website-snapshot");
  await assert.rejects(handler({ targetUrl: "javascript:alert(1)" }), /HTTP\(S\)/);
});

test("network collection endpoint is disabled unless explicitly enabled by the server", async () => {
  const handler = routes.get("/api/scan-website");
  assert.equal(typeof handler, "function");
  const previous = process.env.PAYGUARD_ENABLE_PASSIVE_COLLECTION;
  delete process.env.PAYGUARD_ENABLE_PASSIVE_COLLECTION;
  try {
    await assert.rejects(
      handler({ targetUrl: "https://example.com/" }),
      error => error.statusCode === 503 && /disabled/.test(error.message)
    );
  } finally {
    if (previous === undefined) delete process.env.PAYGUARD_ENABLE_PASSIVE_COLLECTION;
    else process.env.PAYGUARD_ENABLE_PASSIVE_COLLECTION = previous;
  }
});

test("network collection endpoint rejects unsupported ports", async () => {
  const handler = routes.get("/api/scan-website");
  await assert.rejects(handler({ targetUrl: "https://example.com:8443/" }), /standard HTTP and HTTPS ports/);
});
