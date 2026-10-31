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
