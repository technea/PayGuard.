/**
 * Protocol Account validation, state aggregation, and key categorization.
 */

import { callFastNearRpc, AccountNotFoundError } from "../providers/fastnear-rpc.mjs";
import { KNOWN_TRUSTED_CONTRACT_HASHES } from "../registry/canonical-accounts.mjs";

export const EMPTY_CODE_HASH = "11111111111111111111111111111111";

export function validateNearAccountId(accountId) {
  if (typeof accountId !== "string" || !accountId.trim()) {
    return { valid: false, error: "Account ID must be a non-empty string" };
  }

  if (/[A-Z]/.test(accountId)) {
    return { valid: false, error: "NEAR Account ID must not contain uppercase characters" };
  }

  const normalized = accountId.trim();

  // ETH implicit check (0x + 40-64 hex chars)
  if (/^0x[0-9a-f]{40,64}$/.test(normalized)) {
    return {
      valid: true,
      accountId: normalized,
      accountType: "eth_implicit",
      isTopLevel: false,
      subAccounts: []
    };
  }

  if (normalized.length < 2 || normalized.length > 64) {
    return { valid: false, error: `Account ID length (${normalized.length}) must be between 2 and 64 characters` };
  }

  // 64-char lowercase hex implicit check
  if (/^[0-9a-f]{64}$/.test(normalized)) {
    return {
      valid: true,
      accountId: normalized,
      accountType: "implicit",
      isTopLevel: false,
      subAccounts: []
    };
  }

  const validCharsRegex = /^(([a-z0-9]+[_-])*[a-z0-9]+\.)*([a-z0-9]+[_-])*[a-z0-9]+$/;
  if (!validCharsRegex.test(normalized)) {
    return { valid: false, error: "Account ID contains invalid characters or consecutive separators (. - _)" };
  }

  const parts = normalized.split(".");
  const isTopLevel = parts.length === 1;

  return {
    valid: true,
    accountId: normalized,
    accountType: isTopLevel ? "top_level" : "named",
    isTopLevel,
    subAccounts: parts.slice(0, -1),
    rootTld: parts[parts.length - 1]
  };
}

export function formatYoctoToNear(yoctoStr) {
  if (!yoctoStr || typeof yoctoStr !== "string") return "0";
  try {
    const raw = BigInt(yoctoStr);
    const divisor = 10n ** 24n;
    const integerPart = raw / divisor;
    const remainder = raw % divisor;
    if (remainder === 0n) return integerPart.toString();
    const remStr = remainder.toString().padStart(24, "0").slice(0, 4);
    return `${integerPart}.${remStr}`;
  } catch {
    return yoctoStr;
  }
}

export async function fetchNearAccountIntelligence(accountId, options = {}) {
  const parseResult = validateNearAccountId(accountId);
  if (!parseResult.valid) {
    return {
      success: false,
      status: "INVALID_SYNTAX",
      target: accountId,
      error: parseResult.error
    };
  }

  const target = parseResult.accountId;

  try {
    // 1. Fetch account state
    const stateRpc = await callFastNearRpc("query", {
      request_type: "view_account",
      finality: "final",
      account_id: target
    }, options);

    if (!stateRpc.ok) {
      return {
        success: false,
        status: "UNVERIFIED",
        target,
        error: stateRpc.error
      };
    }

    const state = stateRpc.result;
    const isContract = state.code_hash && state.code_hash !== EMPTY_CODE_HASH;

    // 2. Fetch access keys pinned to block height if possible
    const keysParams = {
      request_type: "view_access_key_list",
      finality: "final",
      account_id: target
    };
    if (state.block_height) {
      // Pinning by block_id ensures point-in-time consistency
      keysParams.block_id = state.block_height;
      delete keysParams.finality;
    }

    let keysRpc = await callFastNearRpc("query", keysParams, options);

    // Fallback if provider doesn't support block_id query for access keys
    if (!keysRpc.ok && state.block_height) {
      keysRpc = await callFastNearRpc("query", {
        request_type: "view_access_key_list",
        finality: "final",
        account_id: target
      }, options);
    }

    let keyMetrics = null;
    let keysList = [];
    let keysStatus = "AVAILABLE";

    if (keysRpc.ok && Array.isArray(keysRpc.result?.keys)) {
      keysList = keysRpc.result.keys;
      const fullAccess = keysList.filter(k => k.access_key?.permission === "FullAccess");
      const functionCall = keysList.filter(k => typeof k.access_key?.permission === "object" && k.access_key?.permission?.FunctionCall);

      keyMetrics = {
        totalKeys: keysList.length,
        fullAccessKeysCount: fullAccess.length,
        functionCallKeysCount: functionCall.length,
        fullAccessKeys: fullAccess.map(k => k.public_key),
        functionCallKeys: functionCall.map(k => {
          const fc = k.access_key.permission.FunctionCall;
          const allowanceYocto = fc.allowance || null;
          return {
            publicKey: k.public_key,
            receiverId: fc.receiver_id || "",
            methodNames: Array.isArray(fc.method_names) ? fc.method_names : [],
            isWildcardMethod: !fc.method_names || fc.method_names.length === 0,
            allowance: allowanceYocto,
            allowanceNear: allowanceYocto ? formatYoctoToNear(allowanceYocto) : null,
            isUnlimitedAllowance: allowanceYocto === null
          };
        })
      };
    } else {
      keysStatus = "UNAVAILABLE";
    }

    // 3. Block reference coherence check
    const keysBlockHeight = keysRpc.result?.block_height || state.block_height;
    const isBlockDivergent = keysRpc.result?.block_height ? keysRpc.result.block_height !== state.block_height : false;
    const blockDifference = keysRpc.result?.block_height ? Math.abs(keysRpc.result.block_height - state.block_height) : 0;

    const blockRef = {
      height: state.block_height,
      hash: state.block_hash,
      keysBlockHeight,
      isBlockDivergent,
      blockDifference,
      isAtomicSnapshot: !isBlockDivergent
    };

    return {
      success: true,
      status: "EXISTS",
      target,
      accountType: parseResult.accountType,
      provider: stateRpc.endpoint,
      blockReference: blockRef,
      profile: {
        balanceYocto: state.amount,
        balanceNear: formatYoctoToNear(state.amount),
        storageUsageBytes: state.storage_usage,
        codeHash: state.code_hash,
        hasContract: isContract,
        knownContract: KNOWN_TRUSTED_CONTRACT_HASHES[target] || null
      },
      keys: keyMetrics,
      keysStatus
    };
  } catch (err) {
    if (err instanceof AccountNotFoundError) {
      return {
        success: true,
        status: "UNREGISTERED",
        target,
        accountType: parseResult.accountType,
        error: err.message
      };
    }
    return {
      success: false,
      status: "UNVERIFIED",
      target,
      accountType: parseResult.accountType,
      error: err.message
    };
  }
}

