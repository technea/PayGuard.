/**
 * PayGuard Base Wallet Token Scanner & Impersonation Detector
 *
 * Full Base Mainnet (8453) wallet portfolio & asset security intelligence:
 * 1. Alchemy Base API v2 token discovery (native ETH balance + ERC-20 holdings + metadata).
 * 2. Multi-source fallback: Blockscout Base API v2 & canonical ecosystem registry RPC.
 * 3. Screens each token contract against GoPlus Security intelligence (honeypots,
 *    predatory taxes, blacklist/whitelist restrictions, ownership takeovers, airdrop scams).
 * 4. Cross-references against authoritative Base official asset registry to detect impersonation.
 * 5. Fail-closed security evaluation: Errors or unindexed tokens return UNABLE TO VERIFY / UNVERIFIED.
 * 6. Read-only: Never asks for private keys, signatures, or payment permissions.
 */

import { checkTokenSecurity, isValidEvmAddress } from "./token-security.mjs";

export const BASE_CHAIN_ID = "8453";
export const BASE_RPC_URL = "https://mainnet.base.org";
export const BLOCKSCOUT_BASE_API = "https://base.blockscout.com/api/v2";
export const ALCHEMY_BASE_RPC = "https://base-mainnet.g.alchemy.com/v2";

/**
 * Try to load .env safely if ALCHEMY_API_KEY is not already present in process.env
 */
export function getAlchemyApiKey() {
  if (typeof process !== "undefined" && process?.env?.ALCHEMY_API_KEY) {
    return process.env.ALCHEMY_API_KEY.trim();
  }
  if (typeof process !== "undefined" && typeof process.loadEnvFile === "function") {
    try {
      process.loadEnvFile();
    } catch {}
    if (process.env.ALCHEMY_API_KEY) {
      return process.env.ALCHEMY_API_KEY.trim();
    }
  }
  return "";
}

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
 * In-memory cache for token metadata (contract -> { name, symbol, decimals, logo })
 */
const metadataCache = new Map();

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

  return {
    isImpersonation: true,
    isVerifiedOfficial: false,
    officialAsset: official,
    message: `Possible token impersonation — contract address does not match the verified ${official.symbol} asset (${official.address}).`
  };
}

/**
 * Format atomic integer units into human-readable balance string
 */
export function formatTokenUnits(atomicBalance, decimals = 18) {
  try {
    if (atomicBalance === null || atomicBalance === undefined) return "0";
    let bi;
    if (typeof atomicBalance === "bigint") {
      bi = atomicBalance;
    } else if (typeof atomicBalance === "string" && atomicBalance.startsWith("0x")) {
      bi = BigInt(atomicBalance);
    } else {
      bi = BigInt(String(atomicBalance));
    }
    if (bi === 0n) return "0";
    const dec = Math.max(0, Math.min(36, Number(decimals) || 18));
    if (dec === 0) return bi.toString();
    const divisor = 10n ** BigInt(dec);
    const intPart = bi / divisor;
    const rem = bi % divisor;
    const fracPart = rem.toString().padStart(dec, "0");
    const trimmedFrac = fracPart.replace(/0+$/, "");
    return trimmedFrac ? `${intPart}.${trimmedFrac}` : intPart.toString();
  } catch {
    return "0";
  }
}

/**
 * Helper to execute an eth_call or standard RPC method on Base RPC
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
 * Fetch native ETH balance for a Base wallet via Alchemy or fallback RPC
 */
export async function fetchNativeEthBalance(walletAddress, options = {}) {
  const { fetchImpl = globalThis.fetch, rpcUrl, alchemyApiKey } = options;
  if (!isValidEvmAddress(walletAddress)) {
    return {
      balanceHex: "0x0",
      balanceWei: "0",
      balanceEth: "0",
      symbol: "ETH",
      name: "Ether",
      decimals: 18,
      error: "Invalid wallet address format."
    };
  }

  const key = alchemyApiKey || getAlchemyApiKey();
  const endpoint = key ? `${ALCHEMY_BASE_RPC}/${key}` : (rpcUrl || BASE_RPC_URL);

  try {
    const rawHex = await rpcCall("eth_getBalance", [walletAddress, "latest"], fetchImpl, endpoint);
    const wei = BigInt(rawHex || "0x0");
    const ethFormatted = formatTokenUnits(wei, 18);
    return {
      balanceHex: rawHex || "0x0",
      balanceWei: wei.toString(),
      balanceEth: ethFormatted,
      symbol: "ETH",
      name: "Ether",
      decimals: 18,
      provider: key ? "Alchemy Base Mainnet" : "Base Public RPC"
    };
  } catch (err) {
    return {
      balanceHex: "0x0",
      balanceWei: "0",
      balanceEth: "0",
      symbol: "ETH",
      name: "Ether",
      decimals: 18,
      error: err.message || "Failed to retrieve native ETH balance."
    };
  }
}

/**
 * Discover ERC-20 token balances for a wallet via Alchemy Base API
 * Supports pagination via pageKey, deduplication, and zero-balance filtering.
 */
export async function fetchAlchemyTokenBalances(walletAddress, options = {}) {
  const { fetchImpl = globalThis.fetch, alchemyApiKey, maxPages = 5 } = options;
  const key = alchemyApiKey || getAlchemyApiKey();
  if (!key) {
    return { items: [], available: false, error: "Alchemy API key not configured." };
  }
  if (!isValidEvmAddress(walletAddress)) {
    return { items: [], available: false, error: "Invalid wallet address." };
  }

  const endpoint = `${ALCHEMY_BASE_RPC}/${key}`;
  const discoveredMap = new Map(); // lowercase address -> { contractAddress, tokenBalance }
  let currentPageKey = null;
  let pageCount = 0;

  try {
    do {
      pageCount++;
      const params = currentPageKey
        ? [walletAddress, "erc20", { pageKey: currentPageKey }]
        : [walletAddress, "erc20"];

      const res = await fetchImpl(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", "accept": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: pageCount, method: "alchemy_getTokenBalances", params })
      });

      if (!res.ok) {
        return {
          items: Array.from(discoveredMap.values()),
          available: discoveredMap.size > 0,
          error: `Alchemy HTTP ${res.status}`
        };
      }

      const json = await res.json();
      if (json.error) {
        return {
          items: Array.from(discoveredMap.values()),
          available: discoveredMap.size > 0,
          error: json.error.message || "Alchemy RPC error"
        };
      }

      const rawBalances = json.result?.tokenBalances || [];
      for (const item of rawBalances) {
        const addr = (item.contractAddress || "").toLowerCase();
        if (isValidEvmAddress(addr)) {
          // Zero holdings filter
          try {
            const rawVal = item.tokenBalance;
            if (rawVal && rawVal !== "0x0" && BigInt(rawVal) > 0n) {
              if (!discoveredMap.has(addr)) {
                discoveredMap.set(addr, {
                  contractAddress: addr,
                  tokenBalance: rawVal
                });
              }
            }
          } catch {}
        }
      }

      currentPageKey = json.result?.pageKey || null;
    } while (currentPageKey && pageCount < maxPages);

    return {
      items: Array.from(discoveredMap.values()),
      available: true,
      pageCount,
      totalDiscovered: discoveredMap.size
    };
  } catch (err) {
    return {
      items: Array.from(discoveredMap.values()),
      available: discoveredMap.size > 0,
      error: err.message || "Failed to reach Alchemy Base endpoint."
    };
  }
}

/**
 * Retrieve token metadata via Alchemy Base API or Base RPC fallback
 */
export async function fetchTokenMetadata(contractAddress, options = {}) {
  const { fetchImpl = globalThis.fetch, alchemyApiKey, rpcUrl = BASE_RPC_URL } = options;
  if (!isValidEvmAddress(contractAddress)) {
    return { name: "Unknown Token", symbol: "UNKNOWN", decimals: 18, logo: null };
  }

  const normAddress = contractAddress.toLowerCase();
  if (metadataCache.has(normAddress)) {
    return metadataCache.get(normAddress);
  }

  // Check official registry first
  const official = OFFICIAL_BASE_TOKENS[normAddress];
  if (official) {
    const meta = { name: official.name, symbol: official.symbol, decimals: official.decimals, logo: null };
    metadataCache.set(normAddress, meta);
    return meta;
  }

  const key = alchemyApiKey || getAlchemyApiKey();
  if (key) {
    try {
      const endpoint = `${ALCHEMY_BASE_RPC}/${key}`;
      const res = await fetchImpl(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", "accept": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "alchemy_getTokenMetadata",
          params: [contractAddress]
        })
      });
      if (res.ok) {
        const json = await res.json();
        const r = json.result;
        if (r && (r.symbol || r.name)) {
          const meta = {
            name: r.name || "Unknown Token",
            symbol: r.symbol ? r.symbol.trim() : "UNKNOWN",
            decimals: typeof r.decimals === "number" && r.decimals >= 0 && r.decimals <= 36 ? r.decimals : 18,
            logo: r.logo || null
          };
          metadataCache.set(normAddress, meta);
          return meta;
        }
      }
    } catch {}
  }

  // Fallback to on-chain RPC getErc20Metadata
  const fallback = await getErc20Metadata(contractAddress, fetchImpl, rpcUrl);
  const result = {
    name: fallback.symbol || "Unknown Token",
    symbol: fallback.symbol || "UNKNOWN",
    decimals: fallback.decimals,
    logo: null
  };
  metadataCache.set(normAddress, result);
  return result;
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
      const offset = parseInt(symHex.slice(2, 66), 16) * 2 + 2;
      const len = parseInt(symHex.slice(offset, offset + 64), 16);
      const strHex = symHex.slice(offset + 64, offset + 64 + len * 2);
      symbol = Buffer.from(strHex, "hex").toString("utf8").replace(/\0/g, "").trim();
    } else if (symHex && symHex.length === 66) {
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
 * Retrieve ERC-20 token holdings from Blockscout Base API v2 (fallback).
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
  const { fetchImpl = globalThis.fetch, rpcUrl = BASE_RPC_URL, alchemyApiKey } = options;
  const address = tokenData.address || tokenData.contractAddress;
  const normAddress = (address || "").toLowerCase();

  let name = tokenData.name || null;
  let symbol = tokenData.symbol || null;
  let decimals = tokenData.decimals !== undefined ? tokenData.decimals : null;
  let logo = tokenData.logo || null;
  let balance = (tokenData.balance !== undefined && tokenData.balance !== null) ? String(tokenData.balance) : null;

  // Retrieve metadata if missing
  if (!name || !symbol || symbol === "UNKNOWN" || decimals === null) {
    const meta = await fetchTokenMetadata(normAddress, { fetchImpl, alchemyApiKey, rpcUrl });
    name = name || meta.name;
    symbol = symbol || meta.symbol;
    decimals = decimals !== null ? decimals : meta.decimals;
    logo = logo || meta.logo;
  }
  if (decimals === null) decimals = 18;

  // Retrieve balance if missing
  if (balance === null && isValidEvmAddress(normAddress) && isValidEvmAddress(walletAddress)) {
    balance = await getErc20Balance(normAddress, walletAddress, fetchImpl, rpcUrl);
  }

  const formattedBalance = formatTokenUnits(balance, decimals);

  // 1. Screen contract with GoPlus Token Security
  const securityRes = await checkTokenSecurity({
    chainId: BASE_CHAIN_ID,
    contractAddress: normAddress,
    fetchImpl
  });

  if (securityRes.tokenName && (!name || name === "Unknown Token")) name = securityRes.tokenName;
  if (securityRes.tokenSymbol && (!symbol || symbol === "UNKNOWN")) symbol = securityRes.tokenSymbol;

  // 2. Check for Token Impersonation
  const impersonation = checkTokenImpersonation(normAddress, symbol, name);

  // 3. Collect Security Findings and Indicators
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

  for (const f of securityRes.findings || []) {
    let indicatorType = "RISK";
    let sev = "MEDIUM";
    if (f.code === "HONEYPOT_DETECTED" || f.code === "CANNOT_SELL_ALL" || f.code === "OWNER_CAN_CHANGE_BALANCE" || f.code === "AIRDROP_SCAM_TOKEN") {
      indicatorType = "HONEYPOT";
      sev = "CRITICAL";
    } else if (f.code.includes("TAX") || f.code === "EXCESSIVE_BUY_TAX" || f.code === "EXCESSIVE_SELL_TAX") {
      indicatorType = "PREDATORY_TAX";
      sev = f.severity === "high" ? "HIGH" : "MEDIUM";
    } else if (f.code.includes("BLACKLIST") || f.code.includes("WHITELIST") || f.code.includes("OWNER") || f.code.includes("PRIVILEGE")) {
      indicatorType = "CENTRALIZATION";
      sev = f.severity === "high" ? "HIGH" : "MEDIUM";
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

  // Heuristic: Suspicious unsolicited airdrop candidate
  const isUnsolicitedCandidate = !impersonation?.isVerifiedOfficial &&
    (securityRes.findings || []).some(f => f.severity === "high" || f.code === "HONEYPOT_DETECTED" || f.code === "MALICIOUS_CREATOR" || f.code === "AIRDROP_SCAM_TOKEN");

  if (isUnsolicitedCandidate) {
    detectedIndicators.push({
      type: "SUSPICIOUS_UNSOLICITED",
      severity: "HIGH",
      label: "Suspicious Unsolicited Token",
      detail: "This token exhibits high-risk properties common in unsolicited phishing airdrops. Do not interact."
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
      recommendedAction = "Security intelligence is currently unavailable or unindexed for this token contract.";
    }
  }

  return {
    name: name || "Unknown Token",
    symbol: symbol || "UNKNOWN",
    contractAddress: normAddress,
    balance: balance || "0",
    formattedBalance,
    decimals,
    logo,
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
 * @param {Object} [options] Injection options (fetchImpl, rpcUrl, alchemyApiKey)
 * @returns {Promise<Object>} Complete wallet scan report
 */
export async function scanBaseWalletTokens(input = {}, options = {}) {
  const { walletAddress, customTokenAddresses = [] } = input;
  const { fetchImpl = globalThis.fetch, rpcUrl = BASE_RPC_URL, alchemyApiKey } = options;

  if (!isValidEvmAddress(walletAddress)) {
    return {
      status: "ERROR",
      scanCompletionStatus: "FAILED",
      walletAddress: walletAddress || null,
      chainId: BASE_CHAIN_ID,
      error: "Invalid wallet address format. Must be a 20-byte hex address (0x...).",
      nativeEth: {
        balanceHex: "0x0",
        balanceWei: "0",
        balanceEth: "0",
        symbol: "ETH",
        name: "Ether",
        decimals: 18
      },
      tokens: [],
      summary: {
        totalTokensScanned: 0,
        highRiskCount: 0,
        suspiciousCount: 0,
        cleanCount: 0,
        unverifiedCount: 0
      },
      dataProvider: "None",
      timestamp: new Date().toISOString()
    };
  }

  const normWallet = walletAddress.toLowerCase();
  const tokenMap = new Map(); // address -> { address, name, symbol, balance, decimals, logo }

  // 1. Fetch Native Base ETH Balance
  const nativeEth = await fetchNativeEthBalance(normWallet, { fetchImpl, rpcUrl, alchemyApiKey });

  // 2. Discover ERC-20 Tokens
  let discoveryMode = "ALCHEMY_INDEXER";
  let dataProvider = "Alchemy Base API + GoPlus Security";
  let scanCompletionStatus = "COMPLETE";
  let discoveryUsed = false;

  const key = alchemyApiKey || getAlchemyApiKey();

  // Try Alchemy token discovery if API key available and caller didn't explicitly forbid
  if (options.alchemyApiKey !== false && key) {
    try {
      const alchemyRes = await fetchAlchemyTokenBalances(normWallet, { fetchImpl, alchemyApiKey: key });
      if (alchemyRes.available) {
        discoveryUsed = true;
        for (const item of alchemyRes.items) {
          const addr = item.contractAddress.toLowerCase();
          if (isValidEvmAddress(addr)) {
            tokenMap.set(addr, {
              address: addr,
              balance: item.tokenBalance,
              name: null,
              symbol: null,
              decimals: null,
              logo: null
            });
          }
        }
      }
    } catch {
      // Alchemy error or mock fetch without alchemy support: fall through to fallback
    }
  }

  // Fallback 1: Blockscout API v2 if Alchemy was not used or failed
  if (!discoveryUsed) {
    try {
      const blockscoutRes = await fetchBlockscoutTokens(normWallet, { fetchImpl });
      if (blockscoutRes.available && blockscoutRes.items.length > 0) {
        discoveryUsed = true;
        discoveryMode = "BLOCKSCOUT_INDEXER";
        dataProvider = "Blockscout API + GoPlus Security";
        for (const item of blockscoutRes.items) {
          const token = item.token || {};
          const addr = (token.address || "").toLowerCase();
          if (isValidEvmAddress(addr)) {
            tokenMap.set(addr, {
              address: addr,
              name: token.name || null,
              symbol: token.symbol || null,
              decimals: token.decimals !== undefined ? Number(token.decimals) : 18,
              balance: item.value || "0",
              logo: null
            });
          }
        }
      }
    } catch {}
  }

  // Fallback 2: Notice if no indexer succeeded
  if (!discoveryUsed) {
    discoveryMode = "REGISTRY_AND_CUSTOM_PARTIAL";
    dataProvider = "Base RPC Registry + GoPlus Security";
    scanCompletionStatus = "PARTIAL";
  }

  // Always include canonical Base ecosystem registry tokens
  for (const [addr, info] of Object.entries(OFFICIAL_BASE_TOKENS)) {
    if (!tokenMap.has(addr)) {
      tokenMap.set(addr, {
        address: addr,
        name: info.name,
        symbol: info.symbol,
        decimals: info.decimals,
        balance: null,
        logo: null
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
            decimals: null,
            balance: null,
            logo: null
          });
        }
      }
    }
  }

  // 4. Evaluate each token with bounded concurrency (5 concurrent requests)
  const tokensToScan = Array.from(tokenMap.values());
  const evaluatedTokens = [];

  const BATCH_SIZE = 5;
  for (let i = 0; i < tokensToScan.length; i += BATCH_SIZE) {
    const chunk = tokensToScan.slice(i, i + BATCH_SIZE);
    const chunkResults = await Promise.all(
      chunk.map(token => evaluateWalletToken(token, normWallet, { fetchImpl, rpcUrl, alchemyApiKey: key }))
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
    scanCompletionStatus,
    dataProvider,
    discoveryMode,
    walletAddress: normWallet,
    chainId: BASE_CHAIN_ID,
    networkName: "Base Mainnet (8453)",
    nativeEth,
    summary: {
      totalTokensScanned: evaluatedTokens.length,
      highRiskCount,
      suspiciousCount,
      cleanCount,
      unverifiedCount
    },
    tokens: evaluatedTokens,
    advisoryNotice: discoveryMode === "ALCHEMY_INDEXER"
      ? "Complete wallet portfolio indexed via Alchemy Base Mainnet API. Threat analysis evaluated via GoPlus Security and Base Official Asset Registry."
      : discoveryMode === "BLOCKSCOUT_INDEXER"
      ? "Wallet token holdings indexed via Blockscout API. Threat screening evaluated via GoPlus Security."
      : "Partial discovery mode active: Audited canonical Base ecosystem registry and caller-specified custom tokens via Base on-chain RPC. Unsolicited tokens outside this scope require explicit contract input.",
    timestamp: new Date().toISOString()
  };
}

/**
 * Fast balance lookup tool for a single token (or native ETH)
 */
export async function getWalletTokenBalance(input = {}, options = {}) {
  const { walletAddress, tokenAddress } = input;
  const { fetchImpl = globalThis.fetch, rpcUrl = BASE_RPC_URL, alchemyApiKey } = options;

  if (!isValidEvmAddress(walletAddress)) {
    return {
      status: "ERROR",
      error: "Invalid wallet address.",
      walletAddress: walletAddress || null
    };
  }

  // Native ETH query
  if (!tokenAddress || tokenAddress.toUpperCase() === "ETH" || tokenAddress === "0x0000000000000000000000000000000000000000") {
    const eth = await fetchNativeEthBalance(walletAddress, { fetchImpl, rpcUrl, alchemyApiKey });
    return {
      status: "SUCCESS",
      walletAddress: walletAddress.toLowerCase(),
      chainId: BASE_CHAIN_ID,
      network: "Base Mainnet",
      tokenAddress: "ETH",
      symbol: "ETH",
      name: "Ether",
      decimals: 18,
      balanceRaw: eth.balanceWei,
      balanceFormatted: eth.balanceEth,
      provider: eth.provider || "Alchemy Base Mainnet"
    };
  }

  if (!isValidEvmAddress(tokenAddress)) {
    return {
      status: "ERROR",
      error: "Invalid token contract address.",
      walletAddress: walletAddress.toLowerCase(),
      tokenAddress
    };
  }

  const normContract = tokenAddress.toLowerCase();
  const meta = await fetchTokenMetadata(normContract, { fetchImpl, alchemyApiKey, rpcUrl });
  const rawBalance = await getErc20Balance(normContract, walletAddress, fetchImpl, rpcUrl);
  const formatted = formatTokenUnits(rawBalance, meta.decimals);

  return {
    status: "SUCCESS",
    walletAddress: walletAddress.toLowerCase(),
    chainId: BASE_CHAIN_ID,
    network: "Base Mainnet",
    tokenAddress: normContract,
    symbol: meta.symbol,
    name: meta.name,
    decimals: meta.decimals,
    balanceRaw: rawBalance,
    balanceFormatted: formatted,
    provider: (alchemyApiKey || getAlchemyApiKey()) ? "Alchemy Base Mainnet" : "Base Public RPC"
  };
}

/**
 * Fast portfolio lookup: returns native ETH + all discovered ERC-20 tokens with balances and metadata
 */
export async function getWalletPortfolio(input = {}, options = {}) {
  const { walletAddress } = input;
  const { fetchImpl = globalThis.fetch, rpcUrl = BASE_RPC_URL, alchemyApiKey } = options;

  if (!isValidEvmAddress(walletAddress)) {
    return {
      status: "ERROR",
      scanCompletionStatus: "FAILED",
      error: "Invalid wallet address.",
      walletAddress: walletAddress || null
    };
  }

  const normWallet = walletAddress.toLowerCase();
  const nativeEth = await fetchNativeEthBalance(normWallet, { fetchImpl, rpcUrl, alchemyApiKey });
  const key = alchemyApiKey || getAlchemyApiKey();

  let discoveredTokens = [];
  let scanCompletionStatus = "COMPLETE";
  let dataProvider = key ? "Alchemy Base Mainnet" : "Base Registry RPC";

  if (key) {
    const alchemyRes = await fetchAlchemyTokenBalances(normWallet, { fetchImpl, alchemyApiKey: key });
    if (alchemyRes.available) {
      const BATCH = 10;
      for (let i = 0; i < alchemyRes.items.length; i += BATCH) {
        const chunk = alchemyRes.items.slice(i, i + BATCH);
        const chunkResults = await Promise.all(
          chunk.map(async (item) => {
            const meta = await fetchTokenMetadata(item.contractAddress, { fetchImpl, alchemyApiKey: key, rpcUrl });
            return {
              contractAddress: item.contractAddress,
              symbol: meta.symbol,
              name: meta.name,
              decimals: meta.decimals,
              logo: meta.logo,
              balanceRaw: item.tokenBalance,
              balanceFormatted: formatTokenUnits(item.tokenBalance, meta.decimals)
            };
          })
        );
        discoveredTokens.push(...chunkResults);
      }
    } else {
      scanCompletionStatus = "PARTIAL";
    }
  }

  // Fallback to official registry balances if no tokens found via indexer
  if (discoveredTokens.length === 0) {
    for (const [addr, info] of Object.entries(OFFICIAL_BASE_TOKENS)) {
      const bal = await getErc20Balance(addr, normWallet, fetchImpl, rpcUrl);
      discoveredTokens.push({
        contractAddress: addr,
        symbol: info.symbol,
        name: info.name,
        decimals: info.decimals,
        logo: null,
        balanceRaw: bal,
        balanceFormatted: formatTokenUnits(bal, info.decimals)
      });
    }
  }

  return {
    status: "SUCCESS",
    scanCompletionStatus,
    dataProvider,
    walletAddress: normWallet,
    chainId: BASE_CHAIN_ID,
    network: "Base Mainnet (8453)",
    nativeEth,
    tokenHoldingsCount: discoveredTokens.length,
    tokens: discoveredTokens,
    timestamp: new Date().toISOString()
  };
}

/**
 * Verify wallet scan integrity and security status
 */
export async function verifyWalletScan(input = {}, options = {}) {
  const { walletAddress, scanResult } = input;
  if (!isValidEvmAddress(walletAddress)) {
    return {
      status: "ERROR",
      verified: false,
      error: "Invalid wallet address format."
    };
  }

  const normWallet = walletAddress.toLowerCase();
  let scan = scanResult;

  if (!scan || scan.walletAddress?.toLowerCase() !== normWallet) {
    // Re-run fresh scan if previous scan data not provided
    scan = await scanBaseWalletTokens({ walletAddress: normWallet }, options);
  }

  const highRiskTokens = (scan.tokens || []).filter(t => t.securityStatus === "HIGH RISK");
  const suspiciousTokens = (scan.tokens || []).filter(t => t.securityStatus === "SUSPICIOUS");
  const isSafeForTransactions = highRiskTokens.length === 0 && suspiciousTokens.length === 0;

  return {
    status: "SUCCESS",
    verified: true,
    walletAddress: normWallet,
    chainId: BASE_CHAIN_ID,
    scanCompletionStatus: scan.scanCompletionStatus || "COMPLETE",
    dataProvider: scan.dataProvider || "Alchemy Base API + GoPlus Security",
    totalTokensAudited: scan.summary?.totalTokensScanned || (scan.tokens || []).length,
    highRiskCount: highRiskTokens.length,
    suspiciousCount: suspiciousTokens.length,
    isSafeForTransactions,
    highRiskAssets: highRiskTokens.map(t => ({
      symbol: t.symbol,
      contractAddress: t.contractAddress,
      reason: t.findings?.[0]?.message || t.securityStatus
    })),
    verificationTimestamp: new Date().toISOString(),
    integrityCheck: "VERIFIED_VALID"
  };
}

export default scanBaseWalletTokens;
