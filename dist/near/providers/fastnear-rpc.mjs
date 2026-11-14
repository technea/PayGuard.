/**
 * FastNear & Resilient JSON-RPC provider implementation.
 * Strictly read-only, finality: "final", with retry logic and error normalization.
 */

export class NearRpcError extends Error {
  constructor(message, code, data) {
    super(message);
    this.name = "NearRpcError";
    this.code = code;
    this.data = data;
  }
}

export class AccountNotFoundError extends NearRpcError {
  constructor(accountId) {
    super(`Account "${accountId}" does not exist in finalized NEAR state.`, "UNKNOWN_ACCOUNT");
    this.name = "AccountNotFoundError";
    this.accountId = accountId;
  }
}

export class RateLimitError extends NearRpcError {
  constructor(endpoint) {
    super(`Rate limit reached on ${endpoint}`, "RATE_LIMITED");
    this.name = "RateLimitError";
  }
}

export const DEFAULT_NEAR_RPC_ENDPOINTS = Object.freeze([
  process.env.NEAR_RPC_URL || "https://rpc.fastnear.com",
  process.env.NEAR_RPC_FALLBACK_URL || "https://rpc.mainnet.fastnear.com",
  "https://near.drpc.org",
  "https://rpc.mainnet.near.org"
]);

export const DEFAULT_RPC_TIMEOUT_MS = 5000;
export const MAX_RPC_RESPONSE_BYTES = 128 * 1024;

export async function callFastNearRpc(method, params, options = {}) {
  const endpoints = options.endpoints || DEFAULT_NEAR_RPC_ENDPOINTS;
  const timeoutMs = options.timeoutMs || DEFAULT_RPC_TIMEOUT_MS;
  const fetchFn = options.fetchFn || globalThis.fetch;
  const retries = options.retries ?? 2;

  let lastError = null;

  for (const endpoint of endpoints) {
    for (let attempt = 0; attempt <= retries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff with jitter: 200ms * 2^(attempt-1) + jitter (0-100ms)
        const baseDelay = 200 * Math.pow(2, attempt - 1);
        const jitter = Math.floor(Math.random() * 100);
        await new Promise(r => setTimeout(r, baseDelay + jitter));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetchFn(endpoint, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "accept": "application/json"
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: `payguard-fastnear-${Date.now()}`,
            method,
            params
          }),
          signal: controller.signal
        });

        clearTimeout(timer);

        if (response.status === 429) {
          lastError = new RateLimitError(endpoint);
          continue;
        }

        if (!response.ok) {
          lastError = new NearRpcError(`HTTP ${response.status} from ${endpoint}`, response.status);
          continue;
        }

        const bodyText = await response.text();
        if (bodyText.length > MAX_RPC_RESPONSE_BYTES) {
          lastError = new NearRpcError(`RPC response exceeded max limit (${bodyText.length} bytes)`, "OVERSIZED");
          continue;
        }

        let parsed;
        try {
          parsed = JSON.parse(bodyText);
        } catch (jsonErr) {
          lastError = new NearRpcError(`Malformed JSON from ${endpoint}: ${jsonErr.message}`, "MALFORMED_JSON");
          continue;
        }

        if (parsed.error) {
          const errMsg = parsed.error.cause?.name || parsed.error.message || "";
          const isNotFound = errMsg.includes("UNKNOWN_ACCOUNT") ||
                             errMsg.includes("AccountDoesNotExist") ||
                             JSON.stringify(parsed.error).includes("UNKNOWN_ACCOUNT") ||
                             JSON.stringify(parsed.error).includes("does not exist") ||
                             parsed.error.code === -32000;
          if (isNotFound) {
            throw new AccountNotFoundError(params.account_id || "");
          }
          throw new NearRpcError(parsed.error.message || "NEAR RPC Error", parsed.error.name || "RPC_ERROR", parsed.error);
        }

        return {
          ok: true,
          endpoint,
          result: parsed.result
        };
      } catch (err) {
        clearTimeout(timer);
        lastError = err;
        if (err instanceof AccountNotFoundError) {
          throw err;
        }
      }
    }
  }

  return {
    ok: false,
    endpoint: null,
    error: lastError?.message || "All NEAR RPC providers failed or timed out",
    details: lastError
  };
}

