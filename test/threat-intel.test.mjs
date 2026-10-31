import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeThreatUrl,
  normalizeThreatIndicator,
  parseOpenPhishFeed,
  parseUrlhausCsvFeed,
  matchThreatIndicators
} from "../src/threat-intel/index.mjs";

test("URL normalization removes fragments and default ports without removing path specificity", () => {
  assert.equal(normalizeThreatUrl("https://EXAMPLE.com:443/login#top"), "https://example.com/login");
  assert.equal(normalizeThreatUrl("http://example.com:80/a"), "http://example.com/a");
  assert.equal(normalizeThreatUrl("javascript:alert(1)"), null);
  assert.equal(normalizeThreatUrl("https://user:pass@example.com/"), null);
});

test("indicator normalization requires a known source identifier and valid HTTP URL", () => {
  assert.equal(normalizeThreatIndicator({ url: "https://evil.example/", source: "OpenPhish" }).source, "openphish");
  assert.equal(normalizeThreatIndicator({ url: "https://evil.example/", source: "bad source" }), null);
  assert.equal(normalizeThreatIndicator({ url: "file:///etc/passwd", source: "feed" }), null);
});

test("OpenPhish parser accepts URL lines and rejects malformed records", () => {
  const result = parseOpenPhishFeed(
    "# feed comment\nhttps://phish.example/login\nnot a url\n\nhttp://bad.example/\n",
    { observedAt: "2026-10-31T10:00:00.000Z" }
  );
  assert.equal(result.provider, "openphish");
  assert.equal(result.indicators.length, 2);
  assert.equal(result.rejected, 1);
  assert.equal(result.indicators[0].threat, "phishing");
});

test("URLhaus CSV parser handles quoted fields and uses URL/date columns", () => {
  const csv = '# comment\n123,"2026-10-31 09:00:00","https://malware.example/payload","online","malware_download","tag1,tag2","https://urlhaus.abuse.ch/url/123/","reporter"\n';
  const result = parseUrlhausCsvFeed(csv);
  assert.equal(result.provider, "urlhaus");
  assert.equal(result.indicators.length, 1);
  assert.equal(result.indicators[0].threat, "malware_download");
  assert.equal(result.indicators[0].reference, "https://urlhaus.abuse.ch/url/123/");
  assert.equal(result.indicators[0].observedAt, "2026-10-31T09:00:00.000Z");
});

test("feed parser enforces size and record-count limits", () => {
  assert.throws(() => parseOpenPhishFeed("x".repeat(5 * 1024 * 1024 + 1)), /5 MiB/);
  assert.throws(() => parseOpenPhishFeed(Array.from({ length: 50_001 }, () => "not-a-url").join("\n")), /50,000/);
});

test("matching requires exact normalized URL and reports source freshness", () => {
  const indicators = [
    normalizeThreatIndicator({
      url: "https://phish.example/login",
      source: "openphish",
      threat: "phishing",
      observedAt: "2026-10-31T11:00:00.000Z",
      reference: "https://openphish.com/"
    })
  ];
  const match = matchThreatIndicators("https://PHISH.example:443/login#fragment", indicators, {
    now: Date.parse("2026-10-31T12:00:00.000Z")
  });
  assert.equal(match.status, "MATCH");
  assert.equal(match.matches[0].freshness, "current");
  assert.equal(match.matches[0].source, "openphish");

  const pathMismatch = matchThreatIndicators("https://phish.example/", indicators);
  assert.equal(pathMismatch.status, "NO_MATCH");
});

test("undated indicators are never presented as current", () => {
  const match = matchThreatIndicators("https://evil.example/", [{
    indicatorType: "url",
    value: "https://evil.example/",
    source: "urlhaus"
  }]);
  assert.equal(match.status, "MATCH");
  assert.equal(match.matches[0].freshness, "stale_or_undated");
});
