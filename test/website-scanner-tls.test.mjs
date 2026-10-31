import test from "node:test";
import assert from "node:assert/strict";
import { analyzeTlsConnection } from "../src/website-scanner/tls-analysis.mjs";

const now = Date.parse("2026-10-31T12:00:00.000Z");

test("TLS 1.3 with a verified certificate produces no TLS findings", () => {
  const result = analyzeTlsConnection({
    authorized: true,
    protocol: "TLSv1.3",
    cipher: { name: "TLS_AES_128_GCM_SHA256" },
    certificate: {
      subject: { CN: "example.com" },
      issuer: { CN: "Example CA" },
      valid_from: "Oct 01 00:00:00 2026 GMT",
      valid_to: "Oct 01 00:00:00 2027 GMT",
      fingerprint256: "AA:BB:CC"
    }
  }, now);
  assert.equal(result.status, "verified");
  assert.equal(result.protocol, "TLSv1.3");
  assert.equal(result.findings.length, 0);
  assert.equal(result.certificate.subject, "example.com");
});

test("TLS verification failure creates a high-confidence finding", () => {
  const result = analyzeTlsConnection({
    authorized: false,
    authorizationError: "CERT_HAS_EXPIRED",
    protocol: "TLSv1.2"
  }, now);
  assert.equal(result.status, "verification_failed");
  assert.equal(result.findings[0].id, "tls_certificate_validation_failed");
  assert.equal(result.findings[0].severity, "high");
});

test("deprecated TLS versions are reported with observed protocol evidence", () => {
  const result = analyzeTlsConnection({ authorized: true, protocol: "TLSv1.1" }, now);
  assert.equal(result.findings[0].id, "deprecated_tls_protocol");
  assert.equal(result.findings[0].severity, "high");
  assert.match(result.findings[0].evidence, /TLSv1.1/);
});

test("expired and soon-to-expire certificates are distinguished", () => {
  const expired = analyzeTlsConnection({
    authorized: true,
    protocol: "TLSv1.2",
    certificate: { valid_to: "Oct 01 00:00:00 2026 GMT" }
  }, now);
  assert.ok(expired.findings.some(item => item.id === "tls_certificate_expired"));

  const expiring = analyzeTlsConnection({
    authorized: true,
    protocol: "TLSv1.2",
    certificate: { valid_to: "Nov 10 00:00:00 2026 GMT" }
  }, now);
  assert.ok(expiring.findings.some(item => item.id === "tls_certificate_expiring_soon"));
});

test("missing TLS metadata is explicitly marked as not observed", () => {
  assert.deepEqual(analyzeTlsConnection(undefined), {
    status: "not_observed",
    protocol: null,
    certificate: null,
    findings: []
  });
});
