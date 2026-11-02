/**
 * PayGuard Address Security Inspector for Base
 *
 * Integrates read-only GoPlus Address Security API for Base Mainnet (8453).
 * Evaluates malicious address threats including phishing, stealing attacks,
 * sanctions, blacklists, cybercrime, money laundering, honeypot affiliation,
 * mixer usage, and financial crime.
 *
 * Safe architecture:
 * - Native Node.js ESM (built-in fetch, AbortSignal)
 * - Zero external dependencies
 * - Strict input validation & fixed API endpoint:
 *   GET https://api.gopluslabs.io/api/v1/address_security/{address}?chain_id={chainId}
 * - Strict 3,000ms timeout & 64KB max response payload limit
 * - In-memory cache with 10-minute TTL
 * - Never returns SAFE / PASS on missing, unsupported, or incomplete data
 */

const GOPLUS_ADDRESS_SECURITY_ENDPOINT = "https://api.gopluslabs.io/api/v1/address_security";
const SUPPORTED_CHAIN_ID = "8453"; // Base Mainnet
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_RESPONSE_BYTES = 64 * 1024; // 64 KB
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// In-memory cache: Map<`${chainId}:${normalizedAddress}`, { timestamp: number, result: object }>
const addressCache = new Map();

/**
 * Clear the in-memory cache (primarily used in tests)
 */
function clearAddressCache() {
  addressCache.clear();
}

/**
 * Get internal cache size
 */
function getAddressCacheSize() {
  return addressCache.size;
}

/**
 * Validates 20-byte EVM address format
 */
function isValidEvmAddress(address) {
  return typeof address === "string" && /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Normalizes chainId to string representation
 */
function normalizeChainId(chainId) {
  if (typeof chainId === "number") return String(chainId);
  if (typeof chainId === "string") {
    const trimmed = chainId.trim();
    if (trimmed.startsWith("eip155:")) return trimmed.slice(7);
    return trimmed;
  }
  return "";
}

/**
 * Evaluates raw GoPlus address security payload into deterministic PayGuard findings and verdict
 */
function evaluateAddressSecurityData(rawResult, chainId, address) {
  const findings = [];
  const reasonCodes = [];

  const addFinding = (code, severity, message) => {
    findings.push({ code, severity, message });
    reasonCodes.push(code);
  };

  const isFlagged = (val) => val === "1" || val === 1;

  // 1. Critical Threats (Direct theft, sanctions, high-severity fraud)
  if (isFlagged(rawResult.phishing_activities)) {
    addFinding("PHISHING_ACTIVITIES", "critical", "Address is flagged for involvement in phishing attacks.");
  }
  if (isFlagged(rawResult.stealing_attack)) {
    addFinding("STEALING_ATTACK", "critical", "Address has executed or facilitated theft/draining attacks.");
  }
  if (isFlagged(rawResult.sanctioned)) {
    addFinding("SANCTIONED_ADDRESS", "critical", "Address is present on government or regulatory sanctions lists.");
  }
  if (isFlagged(rawResult.blacklist_doubt)) {
    addFinding("BLACKLIST_SUSPICION", "high", "Address is flagged on suspicious entity blacklists.");
  }
  if (isFlagged(rawResult.honeypot_related_address)) {
    addFinding("HONEYPOT_AFFILIATE", "high", "Address is affiliated with deploying or funding honeypot contracts.");
  }
  if (isFlagged(rawResult.fake_token)) {
    addFinding("FAKE_TOKEN_ISSUER", "high", "Address is associated with creating fake or impersonated tokens.");
  }

  // 2. High & Medium Crime / Compliance Vectors
  if (isFlagged(rawResult.cybercrime)) {
    addFinding("CYBERCRIME_INVOLVEMENT", "high", "Address is linked to broader cybercrime or exploit campaigns.");
  }
  if (isFlagged(rawResult.money_laundering)) {
    addFinding("MONEY_LAUNDERING", "high", "Address has transaction patterns flagged for money laundering.");
  }
  if (isFlagged(rawResult.financial_crime)) {
    addFinding("FINANCIAL_CRIME", "high", "Address is flagged for financial crime or regulatory violations.");
  }
  if (isFlagged(rawResult.blackmail_activities)) {
    addFinding("BLACKMAIL_ACTIVITIES", "high", "Address is linked to extortion or blackmail activities.");
  }
  if (isFlagged(rawResult.darkweb_transactions)) {
    addFinding("DARKWEB_TRANSACTIONS", "medium", "Address has interacted directly with darkweb marketplaces.");
  }
  if (isFlagged(rawResult.mixer)) {
    addFinding("MIXER_USAGE", "medium", "Address has transacted with privacy mixers or obfuscation pools.");
  }
  if (isFlagged(rawResult.fake_kyc)) {
    addFinding("FAKE_KYC", "medium", "Address is associated with fraudulent or bypassed KYC activities.");
  }
  if (isFlagged(rawResult.gas_abuse)) {
    addFinding("GAS_ABUSE", "medium", "Address has engaged in predatory gas abuse or spam manipulation.");
  }
  if (isFlagged(rawResult.malicious_mining_activities)) {
    addFinding("MALICIOUS_MINING", "medium", "Address is associated with illicit crypto-mining activities.");
  }

  // Contract deployment count metric
  const maliciousContracts = parseInt(rawResult.number_of_malicious_contracts_created, 10);
  if (!Number.isNaN(maliciousContracts) && maliciousContracts > 0) {
    addFinding(
      "MALICIOUS_CONTRACTS_CREATED",
      maliciousContracts >= 3 ? "critical" : "high",
      `Address has deployed ${maliciousContracts} known malicious smart contract(s).`
    );
  }

  // 3. Compute Verdict and Risk Level
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
    address,
    findings,
    reasonCodes,
    provider: "goplus",
    timestamp: Date.now(),
    dataStatus: "AVAILABLE"
  };
}

/**
 * Inspect an address via GoPlus Address Security API
 *
 * @param {object} params
 * @param {string|number} params.chainId - Target network chain ID (Base Mainnet: 8453)
 * @param {string} params.address - 0x-prefixed 20-byte EVM address
 * @param {Function} [params.fetchImpl] - Optional injectable fetch for deterministic offline testing
 * @param {number} [params.timeoutMs] - Request timeout in milliseconds (default: 3000)
 * @param {string} [params.apiKey] - Optional GoPlus API key/bearer token
 * @returns {Promise<object>} Structured PayGuard address security inspection report
 */
async function checkAddressSecurity({
  chainId,
  address,
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
      address: typeof address === "string" ? address.toLowerCase() : null,
      findings: [
        {
          code: "UNSUPPORTED_CHAIN",
          severity: "high",
          message: isSepolia
            ? "Base Sepolia (84532) testnet is not supported by GoPlus Address Security. Intelligence is only available for Base Mainnet (8453)."
            : `Chain ID '${normChain || "empty"}' is not supported. GoPlus address security currently supports Base Mainnet (8453).`
        }
      ],
      reasonCodes: ["UNSUPPORTED_CHAIN"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "UNSUPPORTED"
    };
  }

  // 2. Strict EVM Address Validation
  if (!isValidEvmAddress(address)) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      address: typeof address === "string" ? address : null,
      findings: [
        {
          code: "INVALID_ADDRESS",
          severity: "high",
          message: "Address must be a valid 20-byte hexadecimal Ethereum address matching /^0x[0-9a-fA-F]{40}$/."
        }
      ],
      reasonCodes: ["INVALID_ADDRESS"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "MALFORMED_INPUT"
    };
  }

  const normAddress = address.toLowerCase();
  const cacheKey = `${normChain}:${normAddress}`;

  // 3. Cache Lookup
  const cached = addressCache.get(cacheKey);
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
      address: normAddress,
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
  // Format: https://api.gopluslabs.io/api/v1/address_security/{address}?chain_id={chainId}
  const targetUrl = `${GOPLUS_ADDRESS_SECURITY_ENDPOINT}/${encodeURIComponent(normAddress)}?chain_id=${encodeURIComponent(normChain)}`;
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
      address: normAddress,
      findings: [
        {
          code: isTimeout ? "REQUEST_TIMEOUT" : "NETWORK_ERROR",
          severity: "high",
          message: isTimeout
            ? `Address security request exceeded strict timeout of ${timeoutMs}ms.`
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
      address: normAddress,
      findings: [
        {
          code: "RATE_LIMITED",
          severity: "high",
          message: "GoPlus API rate limit exceeded (HTTP 429). Unable to verify address intelligence."
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
      address: normAddress,
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
      address: normAddress,
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
      address: normAddress,
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
      address: normAddress,
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
      address: normAddress,
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
      address: normAddress,
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
      address: normAddress,
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

  // 10. Extract Address Result
  // GoPlus returns { code: 1, message: "ok", result: { ...flags... } } directly in result object
  const result = payload.result;
  if (!result || typeof result !== "object" || Object.keys(result).length === 0) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      address: normAddress,
      findings: [
        {
          code: "EMPTY_RESULT",
          severity: "medium",
          message: "No address security records found in GoPlus response. Absence of data is not proof of safety."
        }
      ],
      reasonCodes: ["EMPTY_RESULT"],
      provider: "goplus",
      timestamp: now,
      dataStatus: "EMPTY_RESULT"
    };
  }

  // 11. Deterministic Security Evaluation
  const evaluated = evaluateAddressSecurityData(result, normChain, normAddress);

  // 12. In-memory Cache Store
  // Only cache available evaluations, never transient errors
  addressCache.set(cacheKey, {
    timestamp: now,
    result: evaluated
  });

  return evaluated;
}



module.exports = { checkAddressSecurity, evaluateAddressSecurityData, clearAddressCache, getAddressCacheSize, isValidEvmAddress, normalizeChainId, SUPPORTED_CHAIN_ID, GOPLUS_ADDRESS_SECURITY_ENDPOINT, default: checkAddressSecurity };
