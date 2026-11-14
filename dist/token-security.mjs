/**
 * PayGuard Token Security Inspector for Base
 *
 * Integrates read-only GoPlus Token Security API for Base Mainnet (8453).
 * Evaluates honeypots, malicious taxes, transfer restrictions, mintability,
 * balance modification, and contract security markers.
 *
 * Safe architecture:
 * - Native Node.js ESM (built-in fetch, AbortSignal)
 * - Zero external dependencies
 * - Strict input validation & fixed API endpoint (never user-controlled)
 * - Strict 3,000ms timeout & 64KB max response payload limit
 * - In-memory cache with 10-minute TTL
 * - Never returns SAFE / PASS on missing, unsupported, or incomplete data
 */

export const GOPLUS_TOKEN_SECURITY_ENDPOINT = "https://api.gopluslabs.io/api/v1/token_security";
export const SUPPORTED_CHAIN_ID = "8453"; // Base Mainnet
export const DEFAULT_TIMEOUT_MS = 3000;
export const MAX_RESPONSE_BYTES = 64 * 1024; // 64 KB
export const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// In-memory cache: Map<`${chainId}:${normalizedAddress}`, { timestamp: number, result: object }>
const tokenCache = new Map();

/**
 * Clear the in-memory cache (primarily used in tests)
 */
export function clearTokenCache() {
  tokenCache.clear();
}

/**
 * Get internal cache size
 */
export function getTokenCacheSize() {
  return tokenCache.size;
}

/**
 * Validates 20-byte EVM address format
 */
export function isValidEvmAddress(address) {
  return typeof address === "string" && /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Normalizes chainId to string representation
 */
export function normalizeChainId(chainId) {
  if (typeof chainId === "number") return String(chainId);
  if (typeof chainId === "string") {
    const trimmed = chainId.trim();
    if (trimmed.startsWith("eip155:")) return trimmed.slice(7);
    return trimmed;
  }
  return "";
}

/**
 * Evaluates raw GoPlus provider payload into deterministic PayGuard findings and verdict
 */
export function evaluateTokenSecurityData(rawToken, chainId, contractAddress) {
  const findings = [];
  const reasonCodes = [];

  // Helper to record finding
  const addFinding = (code, severity, message) => {
    findings.push({ code, severity, message });
    reasonCodes.push(code);
  };

  const tokenName = typeof rawToken.token_name === "string" ? rawToken.token_name : null;
  const tokenSymbol = typeof rawToken.token_symbol === "string" ? rawToken.token_symbol : null;

  // 1. Critical Exploit / Honeypot Checks
  if (rawToken.is_honeypot === "1" || rawToken.is_honeypot === 1) {
    addFinding("HONEYPOT_DETECTED", "critical", "Token is identified as a honeypot; users cannot sell their tokens.");
  }
  if (rawToken.cannot_buy === "1" || rawToken.cannot_buy === 1) {
    addFinding("CANNOT_BUY", "high", "Token purchases are blocked or restricted by the contract.");
  }
  if (rawToken.cannot_sell_all === "1" || rawToken.cannot_sell_all === 1) {
    addFinding("CANNOT_SELL_ALL", "high", "Token holders are restricted from selling their full balance.");
  }
  if (rawToken.owner_change_balance === "1" || rawToken.owner_change_balance === 1) {
    addFinding("OWNER_CAN_CHANGE_BALANCE", "critical", "Contract owner has permissions to modify or confiscate holder token balances.");
  }

  // 2. Buy and Sell Taxes
  const buyTaxNum = rawToken.buy_tax !== undefined && rawToken.buy_tax !== null && rawToken.buy_tax !== ""
    ? parseFloat(rawToken.buy_tax)
    : NaN;
  const sellTaxNum = rawToken.sell_tax !== undefined && rawToken.sell_tax !== null && rawToken.sell_tax !== ""
    ? parseFloat(rawToken.sell_tax)
    : NaN;

  if (!Number.isNaN(buyTaxNum)) {
    if (buyTaxNum >= 0.25) {
      addFinding("EXCESSIVE_BUY_TAX", "high", `Excessive buy tax detected: ${(buyTaxNum * 100).toFixed(1)}%.`);
    } else if (buyTaxNum > 0.05) {
      addFinding("HIGH_BUY_TAX", "medium", `Elevated buy tax detected: ${(buyTaxNum * 100).toFixed(1)}%.`);
    }
  }

  if (!Number.isNaN(sellTaxNum)) {
    if (sellTaxNum >= 0.25) {
      addFinding("EXCESSIVE_SELL_TAX", "high", `Excessive sell tax detected: ${(sellTaxNum * 100).toFixed(1)}%.`);
    } else if (sellTaxNum > 0.05) {
      addFinding("HIGH_SELL_TAX", "medium", `Elevated sell tax detected: ${(sellTaxNum * 100).toFixed(1)}%.`);
    }
  }

  // 3. Centralization & Privileged Controls
  if (rawToken.slippage_modifiable === "1" || rawToken.slippage_modifiable === 1) {
    addFinding("SLIPPAGE_MODIFIABLE", "medium", "Contract owner can arbitrarily alter trading fees or slippage.");
  }
  if (rawToken.transfer_pausable === "1" || rawToken.transfer_pausable === 1) {
    addFinding("TRANSFER_PAUSABLE", "medium", "Contract owner has the ability to pause or freeze token transfers.");
  }
  if (rawToken.is_mintable === "1" || rawToken.is_mintable === 1) {
    // Note: Canonical stablecoins like USDC are mintable; flagged as informational/medium
    addFinding("MINTABLE_TOKEN", "medium", "Contract contains mint functions that can create additional token supply.");
  }
  if (rawToken.is_proxy === "1" || rawToken.is_proxy === 1) {
    addFinding("UPGRADEABLE_PROXY", "info", "Contract is an upgradeable proxy; underlying logic could be changed by owner.");
  }
  if (rawToken.is_blacklisted === "1" || rawToken.is_blacklisted === 1) {
    addFinding("BLACKLIST_PERMISSION", "high", "Contract owner has permissions to blacklist addresses and freeze tokens.");
  }
  if (rawToken.is_whitelisted === "1" || rawToken.is_whitelisted === 1) {
    addFinding("WHITELIST_RESTRICTION", "high", "Only whitelisted accounts can trade or transfer this token.");
  }
  if (rawToken.can_take_back_ownership === "1" || rawToken.can_take_back_ownership === 1 || rawToken.hidden_owner === "1" || rawToken.hidden_owner === 1) {
    addFinding("HIDDEN_OWNER_TAKEOVER", "high", "Contract owner can reclaim renounced ownership or hidden owner detected.");
  }
  if (rawToken.is_airdrop_scam === "1" || rawToken.is_airdrop_scam === 1) {
    addFinding("AIRDROP_SCAM_TOKEN", "critical", "Token identified by GoPlus security intelligence as an airdrop scam.");
  }
  if (rawToken.is_anti_whale === "1" || rawToken.is_anti_whale === 1) {
    addFinding("ANTI_WHALE_RESTRICTION", "info", "Anti-whale mechanism limits maximum transaction or holding amount.");
  }
  if (rawToken.is_in_dex === "0" || rawToken.is_in_dex === 0) {
    addFinding("NO_DEX_LIQUIDITY", "medium", "Token does not appear to have active liquidity on recognized decentralized exchanges.");
  }

  // 4. Source Verification & Trust Indicators
  if (rawToken.is_open_source === "0" || rawToken.is_open_source === 0) {
    addFinding("CLOSED_SOURCE_BYTECODE", "medium", "Contract source code is unverified; cannot inspect internal bytecode logic.");
  }
  if (rawToken.trust_list === "1" || rawToken.trust_list === 1) {
    addFinding("RECOGNIZED_TRUST_LIST", "info", "Token is recognized on GoPlus trust list as a known ecosystem asset.");
  }

  // 5. Compute Verdict and Risk Level
  const hasCritical = findings.some(f => f.severity === "critical");
  const hasHigh = findings.some(f => f.severity === "high");
  const mediumFindings = findings.filter(f => f.severity === "medium");

  let verdict = "PASS";
  let riskLevel = "LOW";

  if (hasCritical || hasHigh) {
    verdict = "BLOCK";
    riskLevel = hasCritical ? "CRITICAL" : "HIGH";
  } else if (mediumFindings.length > 0) {
    verdict = "REVIEW";
    riskLevel = "MEDIUM";
  } else {
    verdict = "PASS";
    riskLevel = "LOW";
  }

  return {
    verdict,
    riskLevel,
    chainId,
    contractAddress,
    tokenName,
    tokenSymbol,
    findings,
    reasonCodes,
    provider: "goplus",
    timestamp: Date.now(),
    dataStatus: "AVAILABLE"
  };
}

/**
 * Inspect a token contract via GoPlus Token Security API
 *
 * @param {object} params
 * @param {string|number} params.chainId - Target network chain ID (Base Mainnet: 8453)
 * @param {string} params.contractAddress - 0x-prefixed 20-byte token address
 * @param {Function} [params.fetchImpl] - Optional injectable fetch for deterministic offline testing
 * @param {number} [params.timeoutMs] - Request timeout in milliseconds (default: 3000)
 * @param {string} [params.apiKey] - Optional GoPlus API key/bearer token
 * @returns {Promise<object>} Structured PayGuard token security inspection report
 */
export async function checkTokenSecurity({
  chainId,
  contractAddress,
  fetchImpl,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  apiKey
} = {}) {
  const normChain = normalizeChainId(chainId);
  const now = Date.now();

  // 1. Strict Chain ID Validation
  if (normChain !== SUPPORTED_CHAIN_ID) {
    const isSepolia = normChain === "84532";
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain || null,
      contractAddress: typeof contractAddress === "string" ? contractAddress.toLowerCase() : null,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "UNSUPPORTED_CHAIN",
          severity: "high",
          message: isSepolia
            ? "Base Sepolia (84532) testnet is not supported by GoPlus Security API. Intelligence is only available for Base Mainnet (8453)."
            : `Chain ID '${normChain || "empty"}' is not supported. GoPlus token security currently supports Base Mainnet (8453).`
        }
      ],
      reasonCodes: ["UNSUPPORTED_CHAIN"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "UNSUPPORTED"
    };
  }

  // 2. Strict EVM Contract Address Validation
  if (!isValidEvmAddress(contractAddress)) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: typeof contractAddress === "string" ? contractAddress : null,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "INVALID_CONTRACT_ADDRESS",
          severity: "high",
          message: "Contract address must be a valid 20-byte hexadecimal Ethereum address matching /^0x[0-9a-fA-F]{40}$/."
        }
      ],
      reasonCodes: ["INVALID_CONTRACT_ADDRESS"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "MALFORMED_INPUT"
    };
  }

  const normAddress = contractAddress.toLowerCase();
  const cacheKey = `${normChain}:${normAddress}`;

  // 3. Cache Lookup
  const cached = tokenCache.get(cacheKey);
  if (cached && (now - cached.timestamp < CACHE_TTL_MS)) {
    return {
      ...cached.result,
      cached: true
    };
  }

  // 4. Resolve fetch implementation
  const activeFetch = fetchImpl || (typeof fetch === "function" ? fetch : null);
  if (!activeFetch) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "FETCH_UNAVAILABLE",
          severity: "high",
          message: "No global fetch API or fetchImpl available in current environment."
        }
      ],
      reasonCodes: ["FETCH_UNAVAILABLE"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "ERROR"
    };
  }

  // 5. Build Request
  const targetUrl = `${GOPLUS_TOKEN_SECURITY_ENDPOINT}/${encodeURIComponent(normChain)}?contract_addresses=${encodeURIComponent(normAddress)}`;
  const headers = {
    Accept: "application/json"
  };

  const resolvedApiKey = apiKey || (typeof process !== "undefined" && process.env ? process.env.GOPLUS_API_KEY : null);
  if (resolvedApiKey && typeof resolvedApiKey === "string" && resolvedApiKey.trim()) {
    headers.Authorization = `Bearer ${resolvedApiKey.trim()}`;
  }

  // 6. Execute Request with Timeout
  let response;
  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  const timeoutId = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

  try {
    response = await activeFetch(targetUrl, {
      method: "GET",
      headers,
      signal: controller ? controller.signal : undefined
    });
  } catch (err) {
    if (timeoutId) clearTimeout(timeoutId);
    const isTimeout = err?.name === "AbortError" || (err?.message && err.message.includes("abort"));
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: isTimeout ? "REQUEST_TIMEOUT" : "NETWORK_ERROR",
          severity: "high",
          message: isTimeout
            ? `Token security request exceeded strict timeout of ${timeoutMs}ms.`
            : `Network error connecting to GoPlus API: ${err?.message || String(err)}`
        }
      ],
      reasonCodes: [isTimeout ? "REQUEST_TIMEOUT" : "NETWORK_ERROR"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "UNAVAILABLE"
    };
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }

  // 7. Handle HTTP Status Codes
  if (response.status === 429) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "RATE_LIMITED",
          severity: "high",
          message: "GoPlus API rate limit exceeded (HTTP 429). Unable to verify token intelligence."
        }
      ],
      reasonCodes: ["RATE_LIMITED"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "RATE_LIMITED"
    };
  }

  if (response.status === 401 || response.status === 403) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "AUTH_FAILED",
          severity: "high",
          message: `GoPlus API authentication failure (HTTP ${response.status}).`
        }
      ],
      reasonCodes: ["AUTH_FAILED"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "ERROR"
    };
  }

  if (!response.ok) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "UPSTREAM_ERROR",
          severity: "high",
          message: `GoPlus API returned unexpected HTTP ${response.status}.`
        }
      ],
      reasonCodes: ["UPSTREAM_ERROR"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "UNAVAILABLE"
    };
  }

  // 8. Safe Read & Payload Size Enforcement (Max 64KB)
  let rawText;
  try {
    rawText = await response.text();
  } catch (err) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "PAYLOAD_READ_ERROR",
          severity: "high",
          message: `Failed to read response body: ${err?.message || String(err)}`
        }
      ],
      reasonCodes: ["PAYLOAD_READ_ERROR"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "ERROR"
    };
  }

  if (typeof rawText !== "string" || rawText.length > MAX_RESPONSE_BYTES) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "OVERSIZED_RESPONSE",
          severity: "high",
          message: `GoPlus API response payload exceeded maximum safe threshold of ${MAX_RESPONSE_BYTES} bytes.`
        }
      ],
      reasonCodes: ["OVERSIZED_RESPONSE"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "ERROR"
    };
  }

  // 9. Parse and Validate JSON Structure
  let payload;
  try {
    payload = JSON.parse(rawText);
  } catch {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "MALFORMED_JSON",
          severity: "high",
          message: "GoPlus API returned malformed or unparseable JSON."
        }
      ],
      reasonCodes: ["MALFORMED_JSON"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "ERROR"
    };
  }

  if (!payload || typeof payload !== "object") {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "INVALID_PAYLOAD_STRUCTURE",
          severity: "high",
          message: "GoPlus response payload is not a valid JSON object."
        }
      ],
      reasonCodes: ["INVALID_PAYLOAD_STRUCTURE"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "ERROR"
    };
  }

  // Handle GoPlus API level error code
  if (payload.code !== 1 && payload.code !== "1" && payload.code !== 200) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "PROVIDER_ERROR_CODE",
          severity: "high",
          message: `GoPlus returned error code ${payload.code}: ${payload.message || "Unknown provider error"}`
        }
      ],
      reasonCodes: ["PROVIDER_ERROR_CODE"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "ERROR"
    };
  }

  // 10. Extract Token Result
  const results = payload.result;
  if (!results || typeof results !== "object") {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "UNINDEXED_TOKEN",
          severity: "medium",
          message: "Contract address is not indexed in GoPlus security database."
        }
      ],
      reasonCodes: ["UNINDEXED_TOKEN"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "EMPTY_RESULT"
    };
  }

  // Lookup in results map (keys are lowercased contract addresses)
  const rawToken = results[normAddress] || results[contractAddress];
  if (!rawToken || typeof rawToken !== "object" || Object.keys(rawToken).length === 0) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      contractAddress: normAddress,
      tokenName: null,
      tokenSymbol: null,
      findings: [
        {
          code: "UNINDEXED_TOKEN",
          severity: "medium",
          message: "Token contract has no audit record or index in GoPlus database. Absence of data is not proof of safety."
        }
      ],
      reasonCodes: ["UNINDEXED_TOKEN"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "EMPTY_RESULT"
    };
  }

  // 11. Deterministic Security Evaluation
  const evaluated = evaluateTokenSecurityData(rawToken, normChain, normAddress);

  // 12. In-memory Cache Store
  // Only cache available evaluations, never transient errors
  tokenCache.set(cacheKey, {
    timestamp: now,
    result: evaluated
  });

  return evaluated;
}

export default checkTokenSecurity;
