import {
  MAX_HEADER_COUNT,
  MAX_HEADER_VALUE_LENGTH,
  MAX_HTML_BYTES,
  MAX_REDIRECTS
} from "./constants.mjs";

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function parseHttpUrl(value, fieldName) {
  if (typeof value !== "string" || value.length < 1 || value.length > 4_096 || value.trim() !== value) {
    throw new TypeError(`${fieldName} must be a trimmed HTTP(S) URL no longer than 4096 characters.`);
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${fieldName} must be a valid HTTP(S) URL.`);
  }

  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new TypeError(`${fieldName} must use HTTP(S) and must not contain embedded credentials.`);
  }
  return parsed;
}

function normalizeHeaders(headers) {
  if (headers === undefined) return {};
  if (!isPlainObject(headers)) throw new TypeError("responseHeaders must be a plain object.");

  const entries = Object.entries(headers);
  if (entries.length > MAX_HEADER_COUNT) {
    throw new TypeError(`responseHeaders cannot contain more than ${MAX_HEADER_COUNT} entries.`);
  }

  const normalized = {};
  for (const [rawName, rawValue] of entries) {
    const name = rawName.toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) {
      throw new TypeError("responseHeaders contains an invalid header name.");
    }
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    if (values.length > 10 || values.some(value =>
      typeof value !== "string" || value.length > MAX_HEADER_VALUE_LENGTH || /[\r\n]/.test(value)
    )) {
      throw new TypeError(`Invalid value for response header '${name}'.`);
    }
    normalized[name] = values.join(", ");
  }
  return normalized;
}

export function validateWebsiteSnapshot(input) {
  if (!isPlainObject(input)) throw new TypeError("Input must be a JSON object.");

  const targetUrl = parseHttpUrl(input.targetUrl, "targetUrl");
  const finalUrl = input.finalUrl === undefined
    ? targetUrl
    : parseHttpUrl(input.finalUrl, "finalUrl");

  const responseHeaders = normalizeHeaders(input.responseHeaders);

  const html = input.html === undefined ? "" : input.html;
  if (typeof html !== "string") throw new TypeError("html must be a string when provided.");
  if (Buffer.byteLength(html, "utf8") > MAX_HTML_BYTES) {
    throw new TypeError(`html exceeds the ${MAX_HTML_BYTES}-byte analysis limit.`);
  }

  const redirects = input.redirects === undefined ? [] : input.redirects;
  if (!Array.isArray(redirects) || redirects.length > MAX_REDIRECTS) {
    throw new TypeError(`redirects must be an array containing at most ${MAX_REDIRECTS} URLs.`);
  }
  const normalizedRedirects = redirects.map((value, index) =>
    parseHttpUrl(value, `redirects[${index}]`).toString()
  );

  return {
    targetUrl,
    finalUrl,
    responseHeaders,
    html,
    redirects: normalizedRedirects
  };
}
