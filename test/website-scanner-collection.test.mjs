import test from "node:test";
import assert from "node:assert/strict";
import { isPublicIPv4, resolvePublicIPv4, validatePublicHostname } from "../src/website-scanner/network-policy.mjs";
import { collectWebsiteSnapshot } from "../src/website-scanner/collection.mjs";

test("public IPv4 policy rejects private, loopback, link-local and reserved ranges", () => {
  for (const address of ["10.0.0.1","127.0.0.1","169.254.10.2","172.16.0.1","192.168.1.1","100.64.0.1","224.0.0.1","0.0.0.0","198.18.0.1"]) {
    assert.equal(isPublicIPv4(address), false, address);
  }
  assert.equal(isPublicIPv4("8.8.8.8"), true);
  assert.equal(isPublicIPv4("1.1.1.1"), true);
});

test("hostname policy rejects localhost, private literals, IPv6 and non-standard host forms", () => {
  for (const host of ["localhost","api.localhost","service.internal","127.0.0.1","[::1]","bad host"]) {
    assert.throws(() => validatePublicHostname(host));
  }
  assert.equal(validatePublicHostname("example.com"), "example.com");
});

test("DNS resolution rejects a hostname if any returned IPv4 address is non-public", async () => {
  await assert.rejects(
    resolvePublicIPv4("example.com", async () => [
      { address: "8.8.8.8", family: 4 },
      { address: "192.168.1.5", family: 4 }
    ]),
    /non-public/
  );
});

test("collector pins a validated address and analyzes a single HTML response", async () => {
  let requestedAddress;
  const report = await collectWebsiteSnapshot("https://example.com", {
    resolve: async () => [{ address: "93.184.216.34", family: 4 }],
    request: async (url, address) => {
      requestedAddress = address;
      return {
        statusCode: 200,
        headers: {
          "content-type": "text/html",
          "strict-transport-security": "max-age=31536000",
          "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
          "x-content-type-options": "nosniff",
          "referrer-policy": "strict-origin-when-cross-origin",
          "permissions-policy": "camera=(), microphone=()"
        },
        body: "<html><body>Public page</body></html>"
      };
    }
  });

  assert.equal(requestedAddress, "93.184.216.34");
  assert.equal(report.scanMode, "passive_network_snapshot");
  assert.equal(report.networkRequestsMade, 1);
  assert.equal(report.collection.activeTesting, false);
  assert.equal(report.assessment, "NO_OBVIOUS_ISSUES_IN_SUPPLIED_SNAPSHOT");
});

test("collector revalidates every redirect destination before requesting it", async () => {
  let resolveCount = 0;
  let requestCount = 0;
  await assert.rejects(
    collectWebsiteSnapshot("https://example.com", {
      resolve: async () => {
        resolveCount++;
        return resolveCount === 1
          ? [{ address: "93.184.216.34", family: 4 }]
          : [{ address: "127.0.0.1", family: 4 }];
      },
      request: async () => {
        requestCount++;
        return { statusCode: 302, headers: { location: "https://private.example.com/" }, body: "" };
      }
    }),
    /non-public|blocked/
  );
  assert.equal(resolveCount, 2);
  assert.equal(requestCount, 1);
});

test("collector blocks HTTPS downgrade redirects", async () => {
  await assert.rejects(
    collectWebsiteSnapshot("https://example.com", {
      resolve: async () => [{ address: "93.184.216.34", family: 4 }],
      request: async () => ({ statusCode: 302, headers: { location: "http://example.com/" }, body: "" })
    }),
    /downgrade/
  );
});

test("collector rejects non-standard ports before DNS or network access", async () => {
  let called = false;
  await assert.rejects(
    collectWebsiteSnapshot("https://example.com:8443", {
      resolve: async () => { called = true; return []; },
      request: async () => { called = true; }
    }),
    /standard HTTP and HTTPS ports/
  );
  assert.equal(called, false);
});

test("collector follows a bounded public redirect and reports the redirect count", async () => {
  let calls = 0;
  const report = await collectWebsiteSnapshot("https://example.com/start", {
    resolve: async () => [{ address: "93.184.216.34", family: 4 }],
    request: async () => {
      calls++;
      if (calls === 1) return { statusCode: 302, headers: { location: "/final" }, body: "" };
      return {
        statusCode: 200,
        headers: { "content-type": "text/html" },
        body: "<html><body>Done</body></html>"
      };
    }
  });
  assert.equal(calls, 2);
  assert.equal(report.collection.redirectCount, 1);
  assert.equal(report.networkRequestsMade, 2);
});

test("collector includes observed TLS protocol and certificate evidence in its report", async () => {
  const report = await collectWebsiteSnapshot("https://example.com/", {
    resolve: async () => [{ address: "93.184.216.34", family: 4 }],
    request: async () => ({
      statusCode: 200,
      headers: { "content-type": "text/html" },
      body: "<html><body>Secure transport metadata</body></html>",
      tls: {
        authorized: true,
        protocol: "TLSv1.1",
        cipher: { name: "ECDHE-RSA-AES128-SHA" },
        certificate: {
          subject: { CN: "example.com" },
          issuer: { CN: "Example CA" },
          valid_from: "Oct 01 00:00:00 2026 GMT",
          valid_to: "Nov 10 00:00:00 2026 GMT",
          fingerprint256: "AA:BB:CC"
        }
      }
    })
  });

  assert.equal(report.tls.status, "verified");
  assert.equal(report.tls.protocol, "TLSv1.1");
  assert.ok(report.findings.some(finding => finding.id === "deprecated_tls_protocol"));
  assert.ok(report.findings.some(finding => finding.id === "tls_certificate_expiring_soon"));
  assert.equal(report.assessment, "FINDINGS_OBSERVED");
});
