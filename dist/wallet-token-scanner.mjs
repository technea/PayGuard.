/**
 * PayGuard Base Wallet Token Scanner & Impersonation Detector
 *
 * Scans ERC-20 token holdings and custom tokens for a Base wallet (8453),
 * screens each token contract against GoPlus Security intelligence,
 * cross-references against an authoritative Base official asset registry
 * to detect token impersonation, and flags unsolicited/suspicious airdrops.
 *
 * Safe Architecture:
 * - Read-only: Never asks for private keys, signatures, or payment permissions.
 * - Multi-source token discovery:
 *   1. Blockscout Base API v2 (if reachable or non-blocked)
 *   2. Authoritative Base ecosystem multicall balance scanner (reliable on-chain RPC)
 *   3. Custom user-supplied token contract auditing
 * - Fail-closed security evaluation: Errors or timeouts return UNABLE TO VERIFY / UNVERIFIED.
 * - Impersonation detector: Flags when token symbols match official assets but contract address differs.
 */

import { checkTokenSecurity, isValidEvmAddress } from "./token-security.mjs";

export const BASE_CHAIN_ID = "8453";
export const BASE_RPC_URL = "https://mainnet.base.org";
export const BLOCKSCOUT_BASE_API = "https://base.blockscout.com/api/v2";

/**
 * Curated registry of authoritative, verified official Base token contracts.
 * Sources: Base Official Documentation & Canonical Bridged Contracts.
 * Keyed by lowercased contract address.
 */
export const OFFICIAL_BASE_TOKENS = Object.freeze({
  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": Object.freeze({
    name: "USD Coin",
    symbol: "USDC",
    decimals: 6,
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    verifiedIssuer: "Circle (Canonical)",
    officialSite: "https://circle.com/usdc"
  }),
  "0x4200000000000000000000000000000000000006": Object.freeze({
    name: "Wrapped Ether",
    symbol: "WETH",
    decimals: 18,
    address: "0x4200000000000000000000000000000000000006",
    verifiedIssuer: "Base Official Bridge",
    officialSite: "https://base.org"
  }),
  "0x50c5725949a6f0c72e6c4a641f24049a917db0cb": Object.freeze({
    name: "Dai Stablecoin",
    symbol: "DAI",
    decimals: 18,
    address: "0x50c5725949a6F0c72E6C4a641F24049A917DB0Cb",
    verifiedIssuer: "MakerDAO / Sky",
    officialSite: "https://makerdao.com"
  }),
  "0x2ae3f1ec7f1f5012cfeab0185bfc7aa3cf0dec22": Object.freeze({
    name: "Coinbase Wrapped Staked ETH",
    symbol: "cbETH",
    decimals: 18,
    address: "0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22",
    verifiedIssuer: "Coinbase",
    officialSite: "https://coinbase.com"
  }),
  "0x940181a94a35a4569e4529a3cdfb74e38fd98631": Object.freeze({
    name: "Aerodrome Finance",
    symbol: "AERO",
    decimals: 18,
    address: "0x940181a94A35A4569E4529A3CDfB74e38FD98631",
    verifiedIssuer: "Aerodrome Finance",
    officialSite: "https://aerodrome.finance"
  }),
  "0x532f27101965dd16442e59d40670faf5ebb142e4": Object.freeze({
    name: "Brett",
    symbol: "BRETT",
    decimals: 18,
    address: "0x532f27101965dd16442e59d40670faf5ebb142e4",
    verifiedIssuer: "Brett Community",
    officialSite: "https://basedbrett.com"
  }),
  "0x0578d8a44db98b23bf096a382e016e29a5ce0ffe": Object.freeze({
    name: "Higher",
    symbol: "HIGHER",
    decimals: 18,
    address: "0x0578d8A44db98B23BF096A382e016e29a5CE0ffe",
    verifiedIssuer: "Higher Community",
    officialSite: "https://aimhigher.net"
  })
});

/**
 * Symbol to official address lookup index
 */
const OFFICIAL_SYMBOL_INDEX = new Map();
for (const info of Object.values(OFFICIAL_BASE_TOKENS)) {
  OFFICIAL_SYMBOL_INDEX.set(info.symbol.toUpperCase(), info);
}

/**
 * Check if a token symbol matches an official asset but contract differs
 */
export function checkTokenImpersonation(contractAddress, symbol, name) {
  if (!contractAddress || !symbol) return null;
  const normAddress = contractAddress.toLowerCase();
  const upperSymbol = symbol.trim().toUpperCase();

  const official = OFFICIAL_SYMBOL_INDEX.get(upperSymbol);
  if (!official) return null;

  if (official.address.toLowerCase() === normAddress) {
    return {
      isImpersonation: false,
      isVerifiedOfficial: true,
      officialAsset: official,
      message: `Verified official Base ${official.symbol} contract.`
    };
  }

  // Symbol matches official asset, but contract address is different!
  return {
    isImpersonation: true,
    isVerifiedOfficial: false,
    officialAsset: official,
    message: `Possible token impersonation — contract address does not match the verified ${official.symbol} asset (${official.address}).`
  };
}

/**
 * Helper to execute an eth_call on Base RPC
 */
async function rpcCall(method, params, fetchImpl = globalThis.fetch, rpcUrl = BASE_RPC_URL) {
  const res = await fetchImpl(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  });
  if (!res.ok) throw new Error(`RPC HTTP error: ${res.status}`);
  const data = await res.json();
  if (data.error) throw new Error(data.error.message || "RPC error");
  return data.result;
}

/**
 * Query token balance for a wallet address via Base RPC
 */
export async function getErc20Balance(contractAddress, walletAddress, fetchImpl = globalThis.fetch, rpcUrl = BASE_RPC_URL) {
  if (!isValidEvmAddress(contractAddress) || !isValidEvmAddress(walletAddress)) return "0";
  const data = "0x70a08231" + walletAddress.slice(2).padStart(64, "0").toLowerCase();
  try {
    const hex = await rpcCall("eth_call", [{ to: contractAddress, data }, "latest"], fetchImpl, rpcUrl);
    if (!hex || hex === "0x") return "0";
    return BigInt(hex).toString();
  } catch {
    return "0";
  }
}

/**
 * Query token symbol and decimals via Base RPC
 */
export async function getErc20Metadata(contractAddress, fetchImpl = globalThis.fetch, rpcUrl = BASE_RPC_URL) {
  if (!isValidEvmAddress(contractAddress)) return { symbol: "UNKNOWN", decimals: 18 };
  try {
    const symbolData = "0x95d89b41"; // symbol()
    const decimalsData = "0x313ce567"; // decimals()
    const [symHex, decHex] = await Promise.all([
      rpcCall("eth_call", [{ to: contractAddress, data: symbolData }, "latest"], fetchImpl, rpcUrl).catch(() => "0x"),
      rpcCall("eth_call", [{ to: contractAddress, data: decimalsData }, "latest"], fetchImpl, rpcUrl).catch(() => "0x")
    ]);

    let symbol = "UNKNOWN";
    if (symHex && symHex.length >= 130) {
      // Decode dynamic string
      const offset = parseInt(symHex.slice(2, 66), 16) * 2 + 2;
      const len = parseInt(symHex.slice(offset, offset + 64), 16);
      const strHex = symHex.slice(offset + 64, offset + 64 + len * 2);
      symbol = Buffer.from(strHex, "hex").toString("utf8").replace(/\0/g, "").trim();
    } else if (symHex && symHex.length === 66) {
      // Decode bytes32 string
      symbol = Buffer.from(symHex.slice(2), "hex").toString("utf8").replace(/\0/g, "").trim();
    }

    let decimals = 18;
    if (decHex && decHex !== "0x") {
      decimals = parseInt(decHex, 16);
      if (Number.isNaN(decimals) || decimals < 0 || decimals > 36) decimals = 18;
    }

    return { symbol: symbol || "UNKNOWN", decimals };
  } catch {
    return { symbol: "UNKNOWN", decimals: 18 };
  }
}

/**
 * Retrieve ERC-20 token holdings from Blockscout Base API v2.
 * Returns { items: Array, available: boolean, error?: string }
 */
export async function fetchBlockscoutTokens(walletAddress, options = {}) {
  const { fetchImpl = globalThis.fetch, timeoutMs = 4000 } = options;
  if (!isValidEvmAddress(walletAddress)) {
    return { items: [], available: false, error: "Invalid wallet address." };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const url = `${BLOCKSCOUT_BASE_API}/addresses/${walletAddress}/tokens?type=ERC-20`;
    const res = await fetchImpl(url, {
      headers: {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PayGuard/0.1.0"
      },
      signal: controller.signal
    });

    clearTimeout(timer);

    if (res.status === 403 || res.status === 429) {
      return {
        items: [],
        available: false,
        error: `Blockscout API protected by Cloudflare (HTTP ${res.status}). Fallback RPC scanning engaged.`
      };
    }

    if (!res.ok) {
      return {
        items: [],
        available: false,
        error: `Blockscout returned HTTP ${res.status}.`
      };
    }

    const json = await res.json();
    const items = Array.isArray(json?.items) ? json.items : [];
    return { items, available: true };
  } catch (err) {
    clearTimeout(timer);
    return {
      items: [],
      available: false,
      error: err.name === "AbortError" ? "Blockscout request timed out." : (err.message || "Network error")
    };
  }
}

/**
 * Scan a single token for a wallet: checks balance, runs GoPlus screening,
 * evaluates impersonation, and calculates unified user-friendly verdict.
 */
export async function evaluateWalletToken(tokenData, walletAddress, options = {}) {
  const { fetchImpl = globalThis.fetch, rpcUrl = BASE_RPC_URL } = options;
  const address = tokenData.address || tokenData.contractAddress;
  const normAddress = (address || "").toLowerCase();

  let name = tokenData.name || null;
  let symbol = tokenData.symbol || null;
  let decimals = tokenData.decimals !== undefined ? tokenData.decimals : 18;
  let balance = (tokenData.balance !== undefined && tokenData.balance !== null) ? String(tokenData.balance) : null;

  // If balance not provided, query via Base RPC
  if (balance === null && isValidEvmAddress(normAddress) && isValidEvmAddress(walletAddress)) {
    balance = await getErc20Balance(normAddress, walletAddress, fetchImpl, rpcUrl);
  }

  // If metadata missing, query via Base RPC
  if ((!symbol || symbol === "UNKNOWN") && isValidEvmAddress(normAddress)) {
    const meta = await getErc20Metadata(normAddress, fetchImpl, rpcUrl);
    symbol = meta.symbol;
    decimals = meta.decimals;
  }

  // 1. Screen contract with GoPlus Token Security
  const securityRes = await checkTokenSecurity({
    chainId: BASE_CHAIN_ID,
    contractAddress: normAddress,
    fetchImpl
  });

  if (securityRes.tokenName && !name) name = securityRes.tokenName;
  if (securityRes.tokenSymbol && (!symbol || symbol === "UNKNOWN")) symbol = securityRes.tokenSymbol;

  // 2. Check for Token Impersonation
  const impersonation = checkTokenImpersonation(normAddress, symbol, name);

  // 3. Check for Suspicious / Unsolicited Signals
  const findings = [...(securityRes.findings || [])];
  const detectedIndicators = [];

  if (impersonation && impersonation.isImpersonation) {
    findings.unshift({
      code: "TOKEN_IMPERSONATION_RISK",
      severity: "high",
      message: impersonation.message
    });
    detectedIndicators.push({
      type: "IMPERSONATION",
      severity: "HIGH",
      label: "Impersonation Risk",
      detail: impersonation.message
    });
  } else if (impersonation && impersonation.isVerifiedOfficial) {
    detectedIndicators.push({
      type: "VERIFIED_OFFICIAL",
      severity: "INFO",
      label: "Official Base Asset",
      detail: `Verified contract for official ${impersonation.officialAsset.symbol} issued by ${impersonation.officialAsset.verifiedIssuer}.`
    });
  }

  // Check GoPlus specific indicators
  for (const f of securityRes.findings || []) {
    let indicatorType = "RISK";
    let sev = "MEDIUM";
    if (f.code === "HONEYPOT_DETECTED" || f.code === "CANNOT_SELL_ALL") {
      indicatorType = "HONEYPOT";
      sev = "CRITICAL";
    } else if (f.code.includes("TAX")) {
      indicatorType = "PREDATORY_TAX";
      sev = f.severity === "high" ? "HIGH" : "MEDIUM";
    } else if (f.code.includes("OWNER") || f.code.includes("PRIVILEGE")) {
      indicatorType = "ADMIN_PRIVILEGE";
      sev = "MEDIUM";
    } else if (f.code === "PROXY_CONTRACT" || f.code === "UPGRADEABLE_PROXY") {
      indicatorType = "UPGRADEABLE_PROXY";
      sev = "INFO";
    }
    detectedIndicators.push({
      type: indicatorType,
      severity: sev,
      label: f.code.replace(/_/g, " "),
      detail: f.message
    });
  }

  // Heuristic: Unsolicited / Airdrop detection
  // If token has balance > 0, is NOT verified official, and has high risk markers or is not on trust list
  const isUnsolicitedCandidate = !impersonation?.isVerifiedOfficial &&
    (securityRes.findings || []).some(f => f.severity === "high" || f.code === "HONEYPOT_DETECTED" || f.code === "MALICIOUS_CREATOR");

  if (isUnsolicitedCandidate) {
    detectedIndicators.push({
      type: "SUSPICIOUS_UNSOLICITED",
      severity: "HIGH",
      label: "Suspicious Unsolicited Token",
      detail: "This token exhibits high-risk properties common in unsolicited phishing airdrops. Stay away."
    });
  }

  // 4. Compute User-Friendly Unified Security Status
  let securityStatus = "NO KNOWN ISSUES FOUND";
  let recommendedAction = "Available automated checks found no known threats. Always exercise caution.";

  if (securityRes.verdict === "BLOCK" || (impersonation && impersonation.isImpersonation)) {
    securityStatus = "HIGH RISK";
    recommendedAction = "Avoid interacting. Do not approve, swap, or send this token.";
  } else if (securityRes.verdict === "REVIEW" || isUnsolicitedCandidate) {
    securityStatus = "SUSPICIOUS";
    recommendedAction = "Review before interacting. Token has centralized privileges, high fees, or lookalike properties.";
  } else if (securityRes.verdict === "UNVERIFIED") {
    if (securityRes.dataStatus === "UNSUPPORTED") {
      securityStatus = "UNSUPPORTED";
      recommendedAction = "Network is not supported by GoPlus Security API.";
    } else {
      securityStatus = "UNABLE TO VERIFY";
      recommendedAction = "Security intelligence is currently unavailable for this token contract.";
    }
  }

  return {
    name: name || "Unknown Token",
    symbol: symbol || "UNKNOWN",
    contractAddress: normAddress,
    balance: balance || "0",
    decimals,
    network: "Base Mainnet (8453)",
    securityStatus,
    verdict: securityRes.verdict,
    riskLevel: securityRes.riskLevel,
    isImpersonation: Boolean(impersonation?.isImpersonation),
    isVerifiedOfficial: Boolean(impersonation?.isVerifiedOfficial),
    detectedIndicators,
    findings,
    provider: "GoPlus Security + Base On-Chain Verification",
    lastChecked: new Date().toISOString(),
    recommendedAction
  };
}

/**
 * Main Wallet Token Scanner function
 *
 * @param {Object} input
 * @param {string} input.walletAddress Target Base wallet address (40 hex chars)
 * @param {Array<string>} [input.customTokenAddresses] Optional specific tokens to inspect
 * @param {Object} [options] Injection options (fetchImpl, rpcUrl)
 * @returns {Promise<Object>} Complete wallet scan report
 */
export async function scanBaseWalletTokens(input = {}, options = {}) {
  const { walletAddress, customTokenAddresses = [] } = input;
  const { fetchImpl = globalThis.fetch, rpcUrl = BASE_RPC_URL } = options;

  if (!isValidEvmAddress(walletAddress)) {
    return {
      status: "ERROR",
      walletAddress: walletAddress || null,
      chainId: BASE_CHAIN_ID,
      error: "Invalid wallet address format. Must be a 20-byte hex address (0x...).",
      tokens: [],
      summary: {
        totalTokensScanned: 0,
        highRiskCount: 0,
        suspiciousCount: 0,
        cleanCount: 0,
        unverifiedCount: 0
      },
      timestamp: new Date().toISOString()
    };
  }

  const normWallet = walletAddress.toLowerCase();
  const tokenMap = new Map(); // address -> { address, name, symbol, balance, decimals }

  // 1. Attempt token discovery via Blockscout API v2
  const blockscoutRes = await fetchBlockscoutTokens(normWallet, { fetchImpl });
  if (blockscoutRes.available && blockscoutRes.items.length > 0) {
    for (const item of blockscoutRes.items) {
      const token = item.token || {};
      const addr = (token.address || "").toLowerCase();
      if (isValidEvmAddress(addr)) {
        tokenMap.set(addr, {
          address: addr,
          name: token.name || null,
          symbol: token.symbol || null,
          decimals: token.decimals !== undefined ? Number(token.decimals) : 18,
          balance: item.value || "0"
        });
      }
    }
  }

  // 2. Discover / check authoritative Base ecosystem tokens
  for (const [addr, info] of Object.entries(OFFICIAL_BASE_TOKENS)) {
    if (!tokenMap.has(addr)) {
      tokenMap.set(addr, {
        address: addr,
        name: info.name,
        symbol: info.symbol,
        decimals: info.decimals,
        balance: null // Will be queried via RPC
      });
    }
  }

  // 3. Add any user-specified custom token addresses
  if (Array.isArray(customTokenAddresses)) {
    for (const customAddr of customTokenAddresses) {
      if (typeof customAddr === "string" && isValidEvmAddress(customAddr)) {
        const lower = customAddr.toLowerCase();
        if (!tokenMap.has(lower)) {
          tokenMap.set(lower, {
            address: lower,
            name: null,
            symbol: null,
            decimals: 18,
            balance: null
          });
        }
      }
    }
  }

  // 4. Evaluate each token with bounded concurrency (3 concurrent requests)
  const tokensToScan = Array.from(tokenMap.values());
  const evaluatedTokens = [];

  const BATCH_SIZE = 3;
  for (let i = 0; i < tokensToScan.length; i += BATCH_SIZE) {
    const chunk = tokensToScan.slice(i, i + BATCH_SIZE);
    const chunkResults = await Promise.all(
      chunk.map(token => evaluateWalletToken(token, normWallet, { fetchImpl, rpcUrl }))
    );
    evaluatedTokens.push(...chunkResults);
  }

  // 5. Compute summary statistics
  let highRiskCount = 0;
  let suspiciousCount = 0;
  let cleanCount = 0;
  let unverifiedCount = 0;

  for (const t of evaluatedTokens) {
    if (t.securityStatus === "HIGH RISK") highRiskCount++;
    else if (t.securityStatus === "SUSPICIOUS") suspiciousCount++;
    else if (t.securityStatus === "NO KNOWN ISSUES FOUND") cleanCount++;
    else unverifiedCount++;
  }

  return {
    status: "SUCCESS",
    walletAddress: normWallet,
    chainId: BASE_CHAIN_ID,
    networkName: "Base Mainnet",
    discoveryMode: blockscoutRes.available ? "FULL_INDEXER" : "REGISTRY_AND_CUSTOM_PARTIAL",
    blockscoutStatus: blockscoutRes.available ? "CONNECTED" : (blockscoutRes.error || "UNAVAILABLE"),
    summary: {
      totalTokensScanned: evaluatedTokens.length,
      highRiskCount,
      suspiciousCount,
      cleanCount,
      unverifiedCount
    },
    tokens: evaluatedTokens,
    advisoryNotice: blockscoutRes.available
      ? "Complete wallet token holdings indexed via Blockscout API. Threat screening evaluated via GoPlus Security."
      : "Partial discovery mode active: Audited canonical Base ecosystem registry and caller-specified custom tokens via Base on-chain RPC. Unsolicited or unindexed tokens outside this scope require explicit contract input.",
    timestamp: new Date().toISOString()
  };
}

export default scanBaseWalletTokens;
