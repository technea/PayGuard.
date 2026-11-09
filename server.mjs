import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import {
  analyzeUrlSecurity,
  evaluatePaymentIntent,
  prepareThreatReport,
  payGuardInspectCalldata,
  payGuardCheckTokenSecurity,
  payGuardCheckAddressSecurity,
  payGuardScanWalletTokens
} from "./src/plugin.mjs";
import { BAZAAR_DISCOVERY_METADATA, build402Challenge, verifyPaymentProof } from "./paybox.mjs";

import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVER_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIRECTORY = path.resolve(SERVER_DIRECTORY, "public");
import { renderDocPage } from "./scripts/render-docs.mjs";

function loadDashboardHtml() {
  const candidates = [
    new URL("./public/index.html", import.meta.url),
    new URL("../public/index.html", import.meta.url),
    path.join(process.cwd(), "public", "index.html"),
    path.join(process.cwd(), "index.html")
  ];
  for (const candidate of candidates) {
    try {
      if (existsSync(candidate)) {
        return readFileSync(candidate, "utf8");
      }
    } catch {}
  }
  return null;
}
let cachedDashboardHtml = loadDashboardHtml();

function loadLandingHtml() {
  const candidates = [
    new URL("./public/landing.html", import.meta.url),
    new URL("../public/landing.html", import.meta.url),
    path.join(process.cwd(), "public", "landing.html"),
    path.join(process.cwd(), "landing.html")
  ];
  for (const candidate of candidates) {
    try {
      if (existsSync(candidate)) {
        return readFileSync(candidate, "utf8");
      }
    } catch {}
  }
  return null;
}
let cachedLandingHtml = loadLandingHtml();
function loadDocsHtml() {
  const candidates = [
    new URL("./public/docs.html", import.meta.url),
    new URL("../public/docs.html", import.meta.url),
    path.join(process.cwd(), "public", "docs.html"),
    path.join(process.cwd(), "docs.html")
  ];
  for (const candidate of candidates) {
    try {
      if (existsSync(candidate)) {
        return readFileSync(candidate, "utf8");
      }
    } catch {}
  }
  return null;
}
let cachedDocsHtml = loadDocsHtml();

const PORT = Number.parseInt(process.env.PORT || "8080", 10);
const HOST = process.env.HOST;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_CONCURRENT_REQUESTS = Number.parseInt(process.env.MAX_CONCURRENT_REQUESTS || "100", 10);
const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = Number.parseInt(process.env.MAX_REQUESTS_PER_WINDOW || "120", 10);
const rateLimitMap = new Map();
let lastRateLimitCleanup = Date.now();

const DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5];
const httpRequests = new Map();
const requestDurations = new Map();
const toolVerdicts = new Map();
let inFlight = 0;
const startedAt = Date.now();

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.trim()) {
    return realIp.trim();
  }
  return req.socket?.remoteAddress || "127.0.0.1";
}

function checkRateLimit(ip) {
  const now = Date.now();
  if (now - lastRateLimitCleanup > 30_000) {
    for (const [k, v] of rateLimitMap) {
      if (now - v.windowStart > RATE_LIMIT_WINDOW_MS) rateLimitMap.delete(k);
    }
    lastRateLimitCleanup = now;
  }
  let entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    entry = { windowStart: now, count: 1 };
    rateLimitMap.set(ip, entry);
    return true;
  }
  entry.count++;
  if (entry.count > MAX_REQUESTS_PER_WINDOW) {
    return false;
  }
  return true;
}

function inc(map, key, amount = 1) { map.set(key, (map.get(key) || 0) + amount); }
function routeLabel(path) {
  if (path === "/api/analyze-url") return "analyze_url";
  if (path === "/api/check-payment") return "check_payment";
  if (path === "/api/threat-report") return "threat_report";
  if (path === "/api/inspect-calldata") return "inspect_calldata";
  if (path === "/api/token-security") return "token_security";
  if (path === "/api/address-security") return "address_security";
  if (path === "/api/scan-wallet-tokens") return "scan_wallet_tokens";
  if (path === "/api/capabilities") return "capabilities";
  if (path === "/whitepaper" || path === "/faq" || path === "/docs" || path.startsWith("/docs/")) return "docs";
  if (path === "/health") return "health";
  if (path === "/.well-known/x402-bazaar.json" || path === "/api/bazaar") return "bazaar";
  return "other";
}
function recordRequest(route, statusCode, durationSeconds) {
  inc(httpRequests, route + "|" + statusCode);
  let hist = requestDurations.get(route);
  if (!hist) {
    hist = { count: 0, sum: 0, buckets: new Array(DURATION_BUCKETS.length).fill(0) };
    requestDurations.set(route, hist);
  }
  hist.count++;
  hist.sum += durationSeconds;
  DURATION_BUCKETS.forEach((bound, i) => { if (durationSeconds <= bound) hist.buckets[i]++; });
}
function recordVerdict(tool, verdict) {
  const allowed = new Set(["PASS", "REVIEW", "BLOCK", "KNOWN_MALICIOUS", "SUSPICIOUS", "CAUTION", "NO_KNOWN_THREAT", "EXPECTED_DOMAIN_MATCH", "UNVERIFIED"]);
  if (allowed.has(verdict)) inc(toolVerdicts, tool + "|" + verdict);
}
function renderMetrics() {
  const lines = ["# HELP payguard_http_requests_total HTTP requests handled by the local PayGuard API.", "# TYPE payguard_http_requests_total counter"];
  for (const [key, count] of httpRequests) {
    const parts = key.split("|");
    lines.push('payguard_http_requests_total{route="' + parts[0] + '",status="' + parts[1] + '"} ' + count);
  }
  lines.push("# HELP payguard_request_duration_seconds Request duration histogram in seconds.", "# TYPE payguard_request_duration_seconds histogram");
  for (const [route, hist] of requestDurations) {
    DURATION_BUCKETS.forEach((bound, i) => lines.push('payguard_request_duration_seconds_bucket{route="' + route + '",le="' + bound + '"} ' + hist.buckets[i]));
    lines.push('payguard_request_duration_seconds_bucket{route="' + route + '",le="+Inf"} ' + hist.count);
    lines.push('payguard_request_duration_seconds_sum{route="' + route + '"} ' + hist.sum);
    lines.push('payguard_request_duration_seconds_count{route="' + route + '"} ' + hist.count);
  }
  lines.push("# HELP payguard_tool_verdicts_total Count of finite PayGuard tool verdicts.", "# TYPE payguard_tool_verdicts_total counter");
  for (const [key, count] of toolVerdicts) {
    const parts = key.split("|");
    lines.push('payguard_tool_verdicts_total{tool="' + parts[0] + '",verdict="' + parts[1] + '"} ' + count);
  }
  lines.push("# HELP payguard_in_flight_requests Current number of requests in progress.", "# TYPE payguard_in_flight_requests gauge", "payguard_in_flight_requests " + inFlight);
  lines.push("# HELP payguard_uptime_seconds Process uptime in seconds.", "# TYPE payguard_uptime_seconds gauge", "payguard_uptime_seconds " + ((Date.now() - startedAt) / 1000));
  return lines.join("\n") + "\n";
}
function sendJson(res, statusCode, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, payment-signature, x-payment",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    ...extraHeaders
  });
  res.end(body);
}
async function readJson(req) {
  // In Vercel serverless functions, req.body is often already parsed or buffered
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === "object") return req.body;
    if (typeof req.body === "string") {
      try { return JSON.parse(req.body); }
      catch {
        const error = new Error("Request body must contain valid JSON.");
        error.statusCode = 400;
        throw error;
      }
    }
  }

  const contentType = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    const error = new Error("Content-Type must be application/json.");
    error.statusCode = 415;
    throw error;
  }
  const length = Number(req.headers["content-length"] || 0);
  if (Number.isFinite(length) && length > MAX_BODY_BYTES) {
    const error = new Error("Request body exceeds the 64 KiB limit.");
    error.statusCode = 413;
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      const error = new Error("Request body exceeds the 64 KiB limit.");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch {
    const error = new Error("Request body must contain valid JSON.");
    error.statusCode = 400;
    throw error;
  }
}
const routes = new Map([
  ["/api/analyze-url", async input => {
    const result = await analyzeUrlSecurity(input);
    recordVerdict("analyze_url", result.verdict);
    return result;
  }],
  ["/api/check-payment", async input => {
    const result = evaluatePaymentIntent(input);
    recordVerdict("check_payment", result.status);
    return result;
  }],
  ["/api/threat-report", async input => {
    const result = await prepareThreatReport(input);
    recordVerdict("threat_report", result.verdict);
    return result;
  }],
  ["/api/inspect-calldata", async input => {
    const result = await payGuardInspectCalldata(input);
    recordVerdict("inspect_calldata", result.verdict);
    return result;
  }],
  ["/api/token-security", async input => {
    const result = await payGuardCheckTokenSecurity(input);
    recordVerdict("token_security", result.verdict);
    return result;
  }],
  ["/api/address-security", async input => {
    const result = await payGuardCheckAddressSecurity(input);
    recordVerdict("address_security", result.verdict);
    return result;
  }],
  ["/api/scan-wallet-tokens", async input => {
    const result = await payGuardScanWalletTokens(input);
    recordVerdict("scan_wallet_tokens", result.status === "SUCCESS" ? "PASS" : "UNVERIFIED");
    return result;
  }]
]);

async function requestHandler(req, res) {
  const started = process.hrtime.bigint();
  let route = "other";
  let statusCode = 500;
  inFlight++;
  try {
    const parsed = new URL(req.url || "/", "http://localhost");
    route = routeLabel(parsed.pathname);

    // Handle CORS preflight
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "content-type, authorization, payment-signature, x-payment",
        "access-control-max-age": "86400"
      });
      return res.end();
    }

    // Serve the Tailwind-generated utility stylesheet through the function
    // because this deployment uses a catch-all Vercel Node route.
    if (req.method === "GET" && parsed.pathname === "/assets/css/tailwind.css") {
      const cssPath = new URL("./public/assets/css/tailwind.css", import.meta.url);
      if (!existsSync(cssPath)) {
        statusCode = 404;
        res.writeHead(statusCode, {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff"
        });
        return res.end("Tailwind stylesheet is not built. Run npm run build:css.");
      }
      const css = readFileSync(cssPath);
      statusCode = 200;
      res.writeHead(statusCode, {
        "content-type": "text/css; charset=utf-8",
        "content-length": css.length,
        "cache-control": "public, max-age=31536000, immutable",
        "x-content-type-options": "nosniff"
      });
      return res.end(css);
    }

    // Serve the custom PayGuard brand mark through the catch-all Vercel function.
    if (req.method === "GET" && parsed.pathname === "/assets/payguard-mark.svg") {
      const logoPath = new URL("./public/assets/payguard-mark.svg", import.meta.url);
      if (!existsSync(logoPath)) {
        statusCode = 404;
        res.writeHead(statusCode, {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff"
        });
        return res.end("Brand asset not found.");
      }
      const logo = readFileSync(logoPath);
      statusCode = 200;
      res.writeHead(statusCode, {
        "content-type": "image/svg+xml; charset=utf-8",
        "content-length": logo.length,
        "cache-control": "public, max-age=3600",
        "x-content-type-options": "nosniff"
      });
      return res.end(logo);
    }

    // Serve the remaining public assets through the catch-all Vercel function.
    // Without this handler, linked CSS and deferred JavaScript files resolve to the
    // HTML fallback route, leaving the dashboard workspace unrendered and unstyled.
    if ((req.method === "GET" || req.method === "HEAD") && parsed.pathname.startsWith("/assets/")) {
      let decodedAssetPath;
      try {
        decodedAssetPath = decodeURIComponent(parsed.pathname);
      } catch {
        statusCode = 400;
        res.writeHead(statusCode, {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff"
        });
        return res.end("Invalid asset path.");
      }

      const assetPath = path.resolve(PUBLIC_DIRECTORY, "." + decodedAssetPath);
      if (!assetPath.startsWith(PUBLIC_DIRECTORY + path.sep) || !existsSync(assetPath)) {
        statusCode = 404;
        res.writeHead(statusCode, {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff"
        });
        return res.end("Asset not found.");
      }

      let asset;
      try {
        asset = readFileSync(assetPath);
      } catch {
        statusCode = 404;
        res.writeHead(statusCode, {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff"
        });
        return res.end("Asset not found.");
      }

      const contentTypes = {
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".mjs": "application/javascript; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".svg": "image/svg+xml; charset=utf-8",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
        ".gif": "image/gif",
        ".ico": "image/x-icon",
        ".woff": "font/woff",
        ".woff2": "font/woff2",
        ".ttf": "font/ttf",
        ".otf": "font/otf"
      };
      const extension = path.extname(assetPath).toLowerCase();
      statusCode = 200;
      res.writeHead(statusCode, {
        "content-type": contentTypes[extension] || "application/octet-stream",
        "content-length": asset.length,
        "cache-control": "public, max-age=300, must-revalidate",
        "x-content-type-options": "nosniff"
      });
      return res.end(req.method === "HEAD" ? undefined : asset);
    }

    const isBrowserRequest = (req.headers["accept"] || "").includes("text/html");

    // Documentation & Whitepaper & FAQ Viewer
    if (req.method === "GET" && (parsed.pathname === "/whitepaper" || parsed.pathname === "/faq" || parsed.pathname === "/docs" || parsed.pathname.startsWith("/docs/"))) {
      statusCode = 200;
      if (!cachedDocsHtml) {
        cachedDocsHtml = loadDocsHtml();
      }
      let docSlug = "overview";
      if (parsed.pathname === "/whitepaper") {
        docSlug = "whitepaper";
      } else if (parsed.pathname === "/faq") {
        docSlug = "faq";
      } else if (parsed.pathname.startsWith("/docs/")) {
        docSlug = parsed.pathname.replace(/^\/docs\/?/, "") || "overview";
      }
      const responseHtml = renderDocPage(docSlug, cachedDocsHtml || "<!DOCTYPE html><html><head><title>PayGuard Documentation</title></head><body><div id='docViewer'>{{DOC_CONTENT}}</div></body></html>");
      res.writeHead(statusCode, {
        "content-type": "text/html; charset=utf-8",
        "content-length": Buffer.byteLength(responseHtml),
        "cache-control": "no-cache",
        "access-control-allow-origin": "*"
      });
      return res.end(responseHtml);
    }
    // Interactive Dashboard Operator Console
    if (req.method === "GET" && parsed.pathname === "/dashboard") {
      statusCode = 200;
      if (!cachedDashboardHtml) {
        cachedDashboardHtml = loadDashboardHtml();
      }
      const responseHtml = cachedDashboardHtml || "<!DOCTYPE html><html><head><title>PayGuard Dashboard</title></head><body><h1>PayGuard Dashboard</h1></body></html>";
      res.writeHead(statusCode, {
        "content-type": "text/html; charset=utf-8",
        "content-length": Buffer.byteLength(responseHtml),
        "cache-control": "no-cache",
        "access-control-allow-origin": "*"
      });
      return res.end(responseHtml);
    }

    // High-Impact Landing Page (explains hierarchy & inner workings)
    if (req.method === "GET" && (parsed.pathname === "/landing" || ((parsed.pathname === "/" || parsed.pathname === "") && isBrowserRequest))) {
      statusCode = 200;
      if (!cachedLandingHtml) {
        cachedLandingHtml = loadLandingHtml();
      }
      const responseHtml = cachedLandingHtml || cachedDashboardHtml || "<!DOCTYPE html><html><head><title>PayGuard</title></head><body><h1>PayGuard</h1></body></html>";
      res.writeHead(statusCode, {
        "content-type": "text/html; charset=utf-8",
        "content-length": Buffer.byteLength(responseHtml),
        "cache-control": "no-cache",
        "access-control-allow-origin": "*"
      });
      return res.end(responseHtml);
    }

    if (req.method === "GET" && (parsed.pathname === "/" || parsed.pathname === "")) {
      statusCode = 200;
      return sendJson(res, statusCode, {
        service: "payguard",
        version: "0.1.0",
        description: "PayGuard free Base-first ecosystem security platform — Verify Before You Trust",
        endpoints: {
          landing: "/",
          dashboard: "/dashboard",
          docs: "/docs",
          whitepaper: "/whitepaper",
          faq: "/faq",
          health: "/health",
          analyzeUrl: "/api/analyze-url",
          checkPayment: "/api/check-payment",
          threatReport: "/api/threat-report",
          inspectCalldata: "/api/inspect-calldata",
          tokenSecurity: "/api/token-security",
          addressSecurity: "/api/address-security",
          scanWalletTokens: "/api/scan-wallet-tokens",
          capabilities: "/api/capabilities",
          bazaar: "/.well-known/x402-bazaar.json",
          metrics: "/metrics"
        }
      });
    }

    if (req.method === "GET" && parsed.pathname === "/api/capabilities") {
      statusCode = 200;
      return sendJson(res, statusCode, {
        service: "payguard",
        version: "0.1.0",
        mode: "read-only",
        goPlusConfigured: Boolean(process.env.GOPLUS_API_KEY && process.env.GOPLUS_API_KEY.trim()),
        webRiskConfigured: Boolean(process.env.GOOGLE_WEB_RISK_API_KEY && process.env.GOOGLE_WEB_RISK_API_KEY.trim()),
        supportedChains: ["8453"],
        modules: [
          "url-sentinel",
          "payment-guard",
          "calldata-inspector",
          "token-security",
          "address-security",
          "wallet-token-scanner",
          "threat-report"
        ]
      });
    }

    if (req.method === "GET" && parsed.pathname === "/health") {
      statusCode = 200;
      return sendJson(res, statusCode, { ok: true, service: "payguard", mode: "read-only", paymentExecution: false });
    }

    if (req.method === "GET" && (parsed.pathname === "/.well-known/x402-bazaar.json" || parsed.pathname === "/api/bazaar")) {
      statusCode = 200;
      return sendJson(res, statusCode, BAZAAR_DISCOVERY_METADATA);
    }

    if (req.method === "GET" && parsed.pathname === "/metrics") {
      const body = renderMetrics();
      statusCode = 200;
      res.writeHead(statusCode, {
        "content-type": "text/plain; version=0.0.4; charset=utf-8",
        "content-length": Buffer.byteLength(body),
        "cache-control": "no-store",
        "access-control-allow-origin": "*",
        "x-content-type-options": "nosniff"
      });
      return res.end(body);
    }

    if (req.method !== "POST" || !routes.has(parsed.pathname)) {
      statusCode = 404;
      return sendJson(res, statusCode, { error: "Not found." });
    }

    if (inFlight > MAX_CONCURRENT_REQUESTS) {
      statusCode = 429;
      return sendJson(res, statusCode, { error: "Server busy: maximum concurrency limit reached." });
    }

    const clientIp = getClientIp(req);
    if (!checkRateLimit(clientIp)) {
      statusCode = 429;
      return sendJson(res, statusCode, { error: "Rate limit exceeded. Try again later." });
    }

    // Optional x402 payment verification
    const requireX402 = process.env.PAYGUARD_REQUIRE_X402 === "true";
    const paymentHeader = req.headers["payment-signature"] || req.headers["x-payment"];

    if (requireX402 && !paymentHeader) {
      const challenge = build402Challenge(req.url);
      statusCode = challenge.status;
      return sendJson(res, statusCode, challenge.body, challenge.headers);
    }

    let extraHeaders = {};
    if (paymentHeader) {
      const paymentRes = await verifyPaymentProof(paymentHeader, req.url);
      const liveSettlementVerified = paymentRes.valid === true &&
        paymentRes.mode === "live_facilitator" &&
        paymentRes.settlement?.settled === true &&
        paymentRes.settlement?.simulated === false;

      // A mock/simulated proof is never sufficient to unlock an x402-protected route.
      if (requireX402 && !liveSettlementVerified) {
        statusCode = 402;
        return sendJson(res, statusCode, {
          error: "Live payment settlement is required.",
          reason: paymentRes.reason || "Mock or simulated payment proofs cannot satisfy PAYGUARD_REQUIRE_X402."
        });
      }

      if (liveSettlementVerified) {
        extraHeaders["x-payment-verified"] = "true";
        extraHeaders["x-payment-mode"] = "live_facilitator";
      } else if (paymentRes.mode === "mock_simulation") {
        // Keep simulation visible without implying that a payment was verified or settled.
        extraHeaders["x-payment-mode"] = "mock_simulation";
      }
    }

    const input = await readJson(req);
    const result = await routes.get(parsed.pathname)(input);
    statusCode = 200;
    return sendJson(res, statusCode, result, extraHeaders);
  } catch (error) {
    console.error("[PayGuard Server Error]", error);
    statusCode = Number.isInteger(error && error.statusCode) ? error.statusCode : 500;
    const message = statusCode >= 500 ? (process.env.NODE_ENV === "development" ? (error.stack || error.message) : "Internal error. Check server logs.") : error.message;
    return sendJson(res, statusCode, { error: message });
  } finally {
    inFlight = Math.max(0, inFlight - 1);
    if (!(route === "other" && req.url === "/metrics")) {
      const elapsed = Number(process.hrtime.bigint() - started) / 1e9;
      recordRequest(route, statusCode, elapsed);
    }
  }
}

const server = http.createServer(requestHandler);

server.requestTimeout = 10_000;
server.headersTimeout = 5_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 500;

const isDirectRun = process.argv[1] && (
  process.argv[1].endsWith("server.mjs") ||
  process.argv[1].endsWith("server.js")
);

if (isDirectRun || process.env.PAYGUARD_START_LISTEN === "true") {
  if (HOST) {
    server.listen(PORT, HOST, () => {
      const addr = server.address();
      console.log(`PayGuard API listening on ${HOST}:${typeof addr === "object" && addr ? addr.port : PORT}`);
    });
  } else {
    server.listen(PORT, () => {
      const addr = server.address();
      console.log(`PayGuard API listening on port ${typeof addr === "object" && addr ? addr.port : PORT}`);
    });
  }

  function shutdown() {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  }
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

export { server, requestHandler, routes, checkRateLimit, sendJson, readJson };
export default requestHandler;

