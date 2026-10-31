import http from "node:http";
import https from "node:https";

export const MAX_RESPONSE_BYTES = 48 * 1024;
export const REQUEST_TIMEOUT_MS = 8_000;
const MAX_RESPONSE_HEADERS = 64;

export function requestPublicHtml(url, pinnedAddress, {
  timeoutMs = REQUEST_TIMEOUT_MS,
  maxBytes = MAX_RESPONSE_BYTES
} = {}) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === "https:" ? https : http;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      error ? reject(error) : resolve(value);
    };

    const request = transport.request(url, {
      method: "GET",
      agent: false,
      family: 4,
      lookup: (_hostname, options, callback) => {
        if (options?.all) callback(null, [{ address: pinnedAddress, family: 4 }]);
        else callback(null, pinnedAddress, 4);
      },
      headers: {
        "accept": "text/html,application/xhtml+xml",
        "accept-encoding": "identity",
        "user-agent": "PayGuard-Passive-Scanner/0.1"
      },
      maxHeaderSize: 16 * 1024
    }, response => {
      const headers = {};
      for (const [name, value] of Object.entries(response.headers)) {
        if (Object.keys(headers).length >= MAX_RESPONSE_HEADERS) break;
        if (typeof value === "string") headers[name] = value.slice(0, 8192);
        else if (Array.isArray(value)) headers[name] = value.slice(0, 10).map(item => String(item).slice(0, 8192));
      }

      const statusCode = response.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(statusCode)) {
        response.resume();
        return finish(null, { statusCode, headers, body: "" });
      }

      const contentType = String(headers["content-type"] || "").split(";")[0].trim().toLowerCase();
      if (statusCode < 200 || statusCode >= 300) {
        response.resume();
        const error = new Error(`Target returned HTTP status ${statusCode}.`);
        error.statusCode = 502;
        return finish(error);
      }
      if (!["text/html", "application/xhtml+xml"].includes(contentType)) {
        response.resume();
        const error = new Error("Target response is not an HTML document.");
        error.statusCode = 415;
        return finish(error);
      }
      const encoding = String(headers["content-encoding"] || "identity").toLowerCase();
      if (encoding !== "identity") {
        response.destroy();
        const error = new Error("Compressed target responses are not accepted by this collector.");
        error.statusCode = 415;
        return finish(error);
      }
      const declaredLength = Number(headers["content-length"]);
      if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
        response.destroy();
        const error = new Error("Target HTML response exceeds the collection size limit.");
        error.statusCode = 413;
        return finish(error);
      }

      const chunks = [];
      let size = 0;
      response.on("data", chunk => {
        size += chunk.length;
        if (size > maxBytes) {
          response.destroy();
          const error = new Error("Target HTML response exceeds the collection size limit.");
          error.statusCode = 413;
          finish(error);
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => finish(null, {
        statusCode,
        headers,
        body: Buffer.concat(chunks).toString("utf8")
      }));
      response.on("error", error => finish(error));
    });

    request.setTimeout(timeoutMs, () => {
      const error = new Error("Target request timed out.");
      error.statusCode = 504;
      request.destroy(error);
    });
    request.on("error", error => finish(error));
    request.end();
  });
}
