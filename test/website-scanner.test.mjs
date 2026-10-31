import test from "node:test";
import assert from "node:assert/strict";
import { analyzeWebsiteSnapshot } from "../src/website-scanner/index.mjs";

const safeHeaders = {
  "strict-transport-security": "max-age=31536000",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=()"
};

test("returns a passive snapshot report and never makes network requests", () => {
  const report = analyzeWebsiteSnapshot({
    targetUrl: "https://example.com",
    responseHeaders: safeHeaders,
    html: "<!doctype html><html><body><h1>Hello</h1></body></html>"
  });

  assert.equal(report.scanMode, "passive_snapshot");
  assert.equal(report.networkRequestsMade, 0);
  assert.equal(report.assessment, "NO_OBVIOUS_ISSUES_IN_SUPPLIED_SNAPSHOT");
  assert.equal(report.findingCount, 0);
  assert.ok(report.limitations.length >= 3);
});

test("detects missing security headers with evidence and remediation", () => {
  const report = analyzeWebsiteSnapshot({
    targetUrl: "https://example.com",
    responseHeaders: {},
    html: ""
  });

  assert.ok(report.findings.some(finding => finding.id === "missing_hsts"));
  assert.ok(report.findings.some(finding => finding.id === "missing_csp"));
  assert.ok(report.findings.some(finding => finding.id === "missing_clickjacking_protection"));
  assert.ok(report.findings.every(finding => finding.evidence && finding.remediation));
});

test("detects password input on HTTP pages", () => {
  const report = analyzeWebsiteSnapshot({
    targetUrl: "http://example.com/login",
    html: '<form><input type="password" name="password"></form>'
  });

  assert.ok(report.findings.some(finding => finding.id === "password_input_on_http" && finding.severity === "high"));
});

test("detects HTTPS form submission to HTTP", () => {
  const report = analyzeWebsiteSnapshot({
    targetUrl: "https://example.com/login",
    html: '<form action="http://collector.example/submit"><input name="email"></form>'
  });

  assert.ok(report.findings.some(finding => finding.id === "https_page_posts_to_http"));
});

test("detects mixed content references on HTTPS pages", () => {
  const report = analyzeWebsiteSnapshot({
    targetUrl: "https://example.com",
    html: '<img src="http://cdn.example/image.png"><script src="http://cdn.example/app.js"></script>'
  });

  assert.ok(report.findings.some(finding => finding.id === "mixed_content_references"));
});

test("reports cross-origin final URL as a review signal, not proof of phishing", () => {
  const report = analyzeWebsiteSnapshot({
    targetUrl: "https://example.com",
    finalUrl: "https://login.example.net/session",
    responseHeaders: safeHeaders
  });

  assert.ok(report.findings.some(finding => finding.id === "cross_origin_redirect"));
  assert.equal(report.assessment, "FINDINGS_OBSERVED");
});

test("rejects unsupported protocols and embedded URL credentials", () => {
  assert.throws(() => analyzeWebsiteSnapshot({ targetUrl: "file:///etc/passwd" }), /HTTP\(S\)/);
  assert.throws(() => analyzeWebsiteSnapshot({ targetUrl: "https://user:pass@example.com" }), /credentials/);
});

test("rejects oversized HTML and malformed headers", () => {
  assert.throws(() => analyzeWebsiteSnapshot({
    targetUrl: "https://example.com",
    html: "x".repeat(256 * 1024 + 1)
  }), /analysis limit/);

  assert.throws(() => analyzeWebsiteSnapshot({
    targetUrl: "https://example.com",
    responseHeaders: { "bad header": "value" }
  }), /invalid header name/);
});

test("does not claim that a snapshot with no findings is safe", () => {
  const report = analyzeWebsiteSnapshot({
    targetUrl: "https://example.com",
    responseHeaders: safeHeaders
  });

  assert.equal(report.assessment, "NO_OBVIOUS_ISSUES_IN_SUPPLIED_SNAPSHOT");
  assert.ok(report.limitations.some(item => item.includes("not proof") || item.includes("did not retrieve")));
});
