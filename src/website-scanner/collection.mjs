import { isIP } from "node:net";
import { analyzeWebsiteSnapshot } from "./index.mjs";
import { resolvePublicIPv4, validatePublicHostname } from "./network-policy.mjs";
import { requestPublicHtml } from "./safe-http-client.mjs";

const MAX_REDIRECTS = 3;

function parseTarget(value) {
  if (typeof value !== "string" || value.length > 4096 || value.trim() !== value) {
    throw new TypeError("targetUrl must be a trimmed URL no longer than 4096 characters.");
  }
  let url;
  try { url = new URL(value); }
  catch { throw new TypeError("targetUrl must be a valid HTTP(S) URL."); }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new TypeError("Only HTTP(S) URLs without embedded credentials are allowed.");
  }
  if (url.port && !["80", "443"].includes(url.port)) {
    throw new TypeError("Only standard HTTP and HTTPS ports are allowed.");
  }
  validatePublicHostname(url.hostname);
  url.hash = "";
  return url;
}

function createError(message, statusCode = 422) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

/**
 * Fetches one public HTML document using an IPv4 address resolved and checked
 * immediately before each request. Redirects are manual and revalidated.
 * No crawling, form submission, JavaScript execution, or active testing occurs.
 */
export async function collectWebsiteSnapshot(targetUrl, {
  resolver,
  resolve = resolvePublicIPv4,
  request = requestPublicHtml
} = {}) {
  let current = parseTarget(targetUrl);
  const redirects = [];
  let response;
  let requests = 0;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const records = await resolve(current.hostname, resolver);
    const selected = records[0];
    if (!selected || selected.family !== 4) {
      throw createError("Target has no validated public IPv4 address.", 403);
    }

    response = await request(current, selected.address);
    requests++;

    if (![301, 302, 303, 307, 308].includes(response.statusCode)) break;
    if (hop === MAX_REDIRECTS) throw createError("Target exceeded the redirect limit.", 422);
    const location = response.headers.location;
    if (typeof location !== "string" || location.length > 4096) {
      throw createError("Target returned an invalid redirect location.", 502);
    }

    let next;
    try { next = new URL(location, current); }
    catch { throw createError("Target returned an invalid redirect location.", 502); }
    if (current.protocol === "https:" && next.protocol !== "https:") {
      throw createError("HTTPS-to-HTTP redirect downgrade was blocked.", 403);
    }
    current = parseTarget(next.toString());
    redirects.push(current.toString());
  }

  if (!response || typeof response.body !== "string") {
    throw createError("Target did not return a usable HTML response.", 502);
  }

  const report = analyzeWebsiteSnapshot({
    targetUrl: targetUrl,
    finalUrl: current.toString(),
    redirects,
    responseHeaders: response.headers,
    html: response.body
  });

  return {
    ...report,
    scanner: "payguard-safe-passive-website-collector",
    scanMode: "passive_network_snapshot",
    networkRequestsMade: requests,
    collection: {
      method: "GET",
      addressFamily: "IPv4",
      redirectCount: redirects.length,
      maxRedirects: MAX_REDIRECTS,
      contentBytes: Buffer.byteLength(response.body, "utf8"),
      activeTesting: false,
      javascriptExecuted: false,
      crawlingPerformed: false
    },
    limitations: [
      ...report.limitations,
      "Only the initial HTML response was collected; linked assets, scripts, APIs and sub-pages were not fetched.",
      "IPv6-only targets and non-standard ports are not supported by this initial collector.",
      "Only public IPv4 addresses are accepted; DNS answers are revalidated and pinned per request to reduce DNS-rebinding and SSRF risk.",
      "This is passive collection, not an authorized active vulnerability scan."
    ]
  };
}
