/**
 * PayGuard EVM Calldata Inspector Module
 *
 * Provides pure, deterministic, read-only analysis of proposed EVM transaction
 * payloads (to, value, data) before user or agent signing.
 *
 * Architectural Boundary:
 * PayGuard is an advisory security sentinel, not a wallet or transaction executor.
 * This inspector performs zero outbound network requests and requires no private keys.
 * A verdict of PASS indicates compliance with configured constraints for recognized
 * standard operations; it does NOT guarantee the target contract bytecode is safe.
 */

const UINT256_MAX = (1n << 256n) - 1n; // 2^256 - 1

// Standard 4-byte ERC-20 Function Selectors
const SELECTORS = Object.freeze({
  ERC20_APPROVE: "0x095ea7b3",      // approve(address,uint256)
  ERC20_TRANSFER: "0xa9059cbb",     // transfer(address,uint256)
  ERC20_TRANSFER_FROM: "0x23b872dd" // transferFrom(address,address,uint256)
});

const ADDRESS_REGEX = /^0x[0-9a-fA-F]{40}$/;
const HEX_DATA_REGEX = /^0x([0-9a-fA-F]{2})*$/;

function isRecord(val) {
  return typeof val === "object" && val !== null && !Array.isArray(val);
}

function normalizeAddress(val) {
  if (typeof val !== "string" || !ADDRESS_REGEX.test(val)) return null;
  return val.toLowerCase();
}

function parseBigIntHex(sliceHex) {
  try {
    return BigInt("0x" + sliceHex);
  } catch {
    return null;
  }
}

function sliceAddress(sliceHex) {
  if (sliceHex.length !== 64) return null;
  // Left 24 chars (12 bytes) must be zero padding for standard ABI encoded address
  const padding = sliceHex.slice(0, 24);
  const addrHex = sliceHex.slice(24);
  if (!/^0+$/.test(padding)) {
    // Non-standard padding, but still extract address
  }
  return "0x" + addrHex.toLowerCase();
}

/**
 * Inspects a proposed transaction object against optional security policies.
 *
 * @param {Object} tx Proposed transaction parameters
 * @param {string} tx.to Target contract address
 * @param {string|number|bigint} [tx.value="0"] Native asset value sent (in wei)
 * @param {string} [tx.data="0x"] Calldata hex string
 * @param {Object} [policy={}] Optional security policy constraints
 * @param {string[]} [policy.allowedTargets] Whitelist of allowed contract target addresses
 * @param {string[]} [policy.allowedSpenders] Whitelist of allowed approval spenders
 * @param {string[]} [policy.allowedRecipients] Whitelist of allowed transfer recipients
 * @param {string|number|bigint} [policy.maxAllowance] Maximum allowed token allowance
 * @param {string|number|bigint} [policy.maxTransferAmount] Maximum allowed token transfer amount
 * @param {string|number|bigint} [policy.maxNativeValue] Maximum allowed native value (ETH)
 * @returns {Object} Structured inspection verdict with risk factors and extracted details
 */
function inspectCalldata(tx, policy = {}) {
  const checks = [];
  const riskFactors = [];

  if (!isRecord(tx)) {
    return {
      verdict: "BLOCK",
      riskLevel: "CRITICAL",
      operation: "MALFORMED_INPUT",
      reasons: ["Transaction input must be a valid object"],
      checks: [{ id: "tx_structure", status: "FAIL", detail: "Transaction payload is not a valid object" }],
      details: null
    };
  }

  // 1. Validate 'to' address
  const target = normalizeAddress(tx.to);
  if (!target) {
    return {
      verdict: "BLOCK",
      riskLevel: "CRITICAL",
      operation: "INVALID_TARGET",
      reasons: ["Missing, invalid, or malformed target 'to' address"],
      checks: [{ id: "target_address", status: "FAIL", detail: `Invalid 'to' address: ${tx.to}` }],
      details: null
    };
  }
  checks.push({ id: "target_address", status: "PASS", detail: target });

  // Target Policy Check
  if (Array.isArray(policy.allowedTargets) && policy.allowedTargets.length > 0) {
    const allowed = policy.allowedTargets.map(a => typeof a === "string" ? a.toLowerCase() : "");
    if (!allowed.includes(target)) {
      riskFactors.push("TARGET_NOT_IN_ALLOWLIST");
      checks.push({ id: "target_policy", status: "FAIL", detail: `Target ${target} is not in allowedTargets policy` });
    } else {
      checks.push({ id: "target_policy", status: "PASS", detail: "Target matches allowed policy" });
    }
  }

  // 2. Validate 'value' (Native Currency)
  let nativeValue = 0n;
  try {
    if (tx.value !== undefined && tx.value !== null && tx.value !== "") {
      if (typeof tx.value === "string" && tx.value.startsWith("0x")) {
        nativeValue = BigInt(tx.value);
      } else {
        nativeValue = BigInt(tx.value);
      }
      if (nativeValue < 0n) throw new Error("Negative value");
    }
    checks.push({ id: "native_value", status: "PASS", detail: nativeValue.toString() });
  } catch {
    return {
      verdict: "BLOCK",
      riskLevel: "CRITICAL",
      operation: "INVALID_VALUE",
      reasons: ["Invalid or malformed native transaction 'value'"],
      checks: [{ id: "native_value", status: "FAIL", detail: `Could not parse value: ${tx.value}` }],
      details: null
    };
  }

  if (policy.maxNativeValue !== undefined && policy.maxNativeValue !== null) {
    try {
      const maxVal = BigInt(policy.maxNativeValue);
      if (nativeValue > maxVal) {
        riskFactors.push("NATIVE_VALUE_EXCEEDS_POLICY");
        checks.push({ id: "native_value_policy", status: "FAIL", detail: `Value ${nativeValue} exceeds policy max ${maxVal}` });
      }
    } catch {
      // Invalid policy limit
    }
  }

  // 3. Inspect 'data' (Calldata)
  const rawData = tx.data || "0x";
  if (typeof rawData !== "string" || !HEX_DATA_REGEX.test(rawData)) {
    return {
      verdict: "BLOCK",
      riskLevel: "CRITICAL",
      operation: "MALFORMED_CALLDATA",
      reasons: ["Transaction calldata is not a valid hex string"],
      checks: [{ id: "calldata_hex", status: "FAIL", detail: "Calldata must be 0x-prefixed hex string" }],
      details: null
    };
  }

  // Standard ETH Transfer (empty calldata)
  if (rawData === "0x" || rawData === "") {
    const hasFail = checks.some(c => c.status === "FAIL");
    return {
      verdict: hasFail ? "BLOCK" : "PASS",
      riskLevel: hasFail ? "HIGH" : "LOW",
      operation: "NATIVE_TRANSFER",
      reasons: riskFactors,
      checks,
      details: {
        target,
        nativeValue: nativeValue.toString(),
        dataLengthBytes: 0
      }
    };
  }

  // If calldata is present but less than 4 bytes (selector length)
  if (rawData.length < 10) {
    return {
      verdict: "REVIEW",
      riskLevel: "MEDIUM",
      operation: "TRUNCATED_CALLDATA",
      reasons: ["Calldata is shorter than 4-byte function selector"],
      checks: [...checks, { id: "calldata_length", status: "WARN", detail: `Length ${rawData.length} is less than selector (10 chars)` }],
      details: { target, rawData }
    };
  }

  const selector = rawData.slice(0, 10).toLowerCase();
  const payload = rawData.slice(10);

  // ----------------------------------------------------
  // Operation A: ERC-20 approve(address spender, uint256 amount)
  // Expected length: 10 + 64 + 64 = 138 characters (68 bytes)
  // ----------------------------------------------------
  if (selector === SELECTORS.ERC20_APPROVE) {
    if (payload.length !== 128) {
      return {
        verdict: "BLOCK",
        riskLevel: "HIGH",
        operation: "ERC20_APPROVE",
        reasons: [`Malformed approve() calldata length: expected 68 bytes, got ${rawData.length / 2 - 1}`],
        checks: [...checks, { id: "calldata_decode", status: "FAIL", detail: "Invalid parameter payload size" }],
        details: { selector, expectedBytes: 68 }
      };
    }

    const spender = sliceAddress(payload.slice(0, 64));
    const rawAmount = parseBigIntHex(payload.slice(64, 128));

    if (!spender || rawAmount === null) {
      return {
        verdict: "BLOCK",
        riskLevel: "HIGH",
        operation: "ERC20_APPROVE",
        reasons: ["Failed to decode valid spender address or uint256 amount"],
        checks: [...checks, { id: "calldata_decode", status: "FAIL", detail: "ABI decoding error" }],
        details: null
      };
    }

    const isUnlimited = rawAmount === UINT256_MAX;
    const isUnusuallyLarge = rawAmount > (UINT256_MAX / 2n);

    if (isUnlimited) {
      riskFactors.push("UNLIMITED_ALLOWANCE_UINT256_MAX");
      checks.push({ id: "allowance_size", status: "WARN", detail: "Spender is granted maximum possible token allowance (2^256 - 1)" });
    } else if (isUnusuallyLarge) {
      riskFactors.push("UNUSUALLY_LARGE_ALLOWANCE");
      checks.push({ id: "allowance_size", status: "WARN", detail: "Spender is granted unusually large allowance (> 2^255)" });
    } else {
      checks.push({ id: "allowance_size", status: "PASS", detail: `Limited allowance: ${rawAmount.toString()}` });
    }

    // Spender Policy Check
    if (Array.isArray(policy.allowedSpenders) && policy.allowedSpenders.length > 0) {
      const allowed = policy.allowedSpenders.map(a => typeof a === "string" ? a.toLowerCase() : "");
      if (!allowed.includes(spender)) {
        riskFactors.push("SPENDER_NOT_IN_ALLOWLIST");
        checks.push({ id: "spender_policy", status: "FAIL", detail: `Spender ${spender} is not in allowedSpenders policy` });
      } else {
        checks.push({ id: "spender_policy", status: "PASS", detail: "Spender matches allowed policy" });
      }
    }

    // Max Allowance Policy Check
    if (policy.maxAllowance !== undefined && policy.maxAllowance !== null) {
      try {
        const maxLimit = BigInt(policy.maxAllowance);
        if (rawAmount > maxLimit) {
          riskFactors.push("ALLOWANCE_EXCEEDS_POLICY_MAX");
          checks.push({ id: "allowance_limit", status: "FAIL", detail: `Allowance ${rawAmount} exceeds configured policy limit ${maxLimit}` });
        }
      } catch {
        // Ignored invalid limit
      }
    }

    const isBlocked = checks.some(c => c.status === "FAIL");
    const isReview = isUnlimited || isUnusuallyLarge || checks.some(c => c.status === "WARN");

    return {
      verdict: isBlocked ? "BLOCK" : (isReview ? "REVIEW" : "PASS"),
      riskLevel: isBlocked ? "HIGH" : (isReview ? "MEDIUM" : "LOW"),
      operation: "ERC20_APPROVE",
      reasons: riskFactors,
      checks,
      details: {
        tokenContract: target,
        spender,
        rawAmount: rawAmount.toString(),
        isUnlimited,
        isUnusuallyLarge
      }
    };
  }

  // ----------------------------------------------------
  // Operation B: ERC-20 transfer(address recipient, uint256 amount)
  // Expected length: 10 + 64 + 64 = 138 characters (68 bytes)
  // ----------------------------------------------------
  if (selector === SELECTORS.ERC20_TRANSFER) {
    if (payload.length !== 128) {
      return {
        verdict: "BLOCK",
        riskLevel: "HIGH",
        operation: "ERC20_TRANSFER",
        reasons: [`Malformed transfer() calldata length: expected 68 bytes, got ${rawData.length / 2 - 1}`],
        checks: [...checks, { id: "calldata_decode", status: "FAIL", detail: "Invalid parameter payload size" }],
        details: { selector, expectedBytes: 68 }
      };
    }

    const recipient = sliceAddress(payload.slice(0, 64));
    const amount = parseBigIntHex(payload.slice(64, 128));

    if (!recipient || amount === null) {
      return {
        verdict: "BLOCK",
        riskLevel: "HIGH",
        operation: "ERC20_TRANSFER",
        reasons: ["Failed to decode valid recipient address or uint256 amount"],
        checks: [...checks, { id: "calldata_decode", status: "FAIL", detail: "ABI decoding error" }],
        details: null
      };
    }

    // Recipient Policy Check
    if (Array.isArray(policy.allowedRecipients) && policy.allowedRecipients.length > 0) {
      const allowed = policy.allowedRecipients.map(a => typeof a === "string" ? a.toLowerCase() : "");
      if (!allowed.includes(recipient)) {
        riskFactors.push("RECIPIENT_NOT_IN_ALLOWLIST");
        checks.push({ id: "recipient_policy", status: "FAIL", detail: `Recipient ${recipient} is not in allowedRecipients policy` });
      } else {
        checks.push({ id: "recipient_policy", status: "PASS", detail: "Recipient matches allowed policy" });
      }
    }

    // Max Transfer Amount Check
    if (policy.maxTransferAmount !== undefined && policy.maxTransferAmount !== null) {
      try {
        const maxLimit = BigInt(policy.maxTransferAmount);
        if (amount > maxLimit) {
          riskFactors.push("TRANSFER_EXCEEDS_POLICY_MAX");
          checks.push({ id: "transfer_limit", status: "FAIL", detail: `Amount ${amount} exceeds configured policy limit ${maxLimit}` });
        }
      } catch {
        // Ignored invalid limit
      }
    }

    const isBlocked = checks.some(c => c.status === "FAIL");

    return {
      verdict: isBlocked ? "BLOCK" : "PASS",
      riskLevel: isBlocked ? "HIGH" : "LOW",
      operation: "ERC20_TRANSFER",
      reasons: riskFactors,
      checks,
      details: {
        tokenContract: target,
        recipient,
        amount: amount.toString()
      }
    };
  }

  // ----------------------------------------------------
  // Operation C: ERC-20 transferFrom(address from, address to, uint256 amount)
  // Expected length: 10 + 64 + 64 + 64 = 202 characters (100 bytes)
  // ----------------------------------------------------
  if (selector === SELECTORS.ERC20_TRANSFER_FROM) {
    if (payload.length !== 192) {
      return {
        verdict: "BLOCK",
        riskLevel: "HIGH",
        operation: "ERC20_TRANSFER_FROM",
        reasons: [`Malformed transferFrom() calldata length: expected 100 bytes, got ${rawData.length / 2 - 1}`],
        checks: [...checks, { id: "calldata_decode", status: "FAIL", detail: "Invalid parameter payload size" }],
        details: { selector, expectedBytes: 100 }
      };
    }

    const from = sliceAddress(payload.slice(0, 64));
    const to = sliceAddress(payload.slice(64, 128));
    const amount = parseBigIntHex(payload.slice(128, 192));

    if (!from || !to || amount === null) {
      return {
        verdict: "BLOCK",
        riskLevel: "HIGH",
        operation: "ERC20_TRANSFER_FROM",
        reasons: ["Failed to decode valid from/to addresses or uint256 amount"],
        checks: [...checks, { id: "calldata_decode", status: "FAIL", detail: "ABI decoding error" }],
        details: null
      };
    }

    // Recipient Policy Check on 'to' address
    if (Array.isArray(policy.allowedRecipients) && policy.allowedRecipients.length > 0) {
      const allowed = policy.allowedRecipients.map(a => typeof a === "string" ? a.toLowerCase() : "");
      if (!allowed.includes(to)) {
        riskFactors.push("RECIPIENT_NOT_IN_ALLOWLIST");
        checks.push({ id: "recipient_policy", status: "FAIL", detail: `Recipient ${to} is not in allowedRecipients policy` });
      } else {
        checks.push({ id: "recipient_policy", status: "PASS", detail: "Recipient matches allowed policy" });
      }
    }

    // Max Transfer Amount Check
    if (policy.maxTransferAmount !== undefined && policy.maxTransferAmount !== null) {
      try {
        const maxLimit = BigInt(policy.maxTransferAmount);
        if (amount > maxLimit) {
          riskFactors.push("TRANSFER_EXCEEDS_POLICY_MAX");
          checks.push({ id: "transfer_limit", status: "FAIL", detail: `Amount ${amount} exceeds configured policy limit ${maxLimit}` });
        }
      } catch {
        // Ignored invalid limit
      }
    }

    const isBlocked = checks.some(c => c.status === "FAIL");

    return {
      verdict: isBlocked ? "BLOCK" : "PASS",
      riskLevel: isBlocked ? "HIGH" : "LOW",
      operation: "ERC20_TRANSFER_FROM",
      reasons: riskFactors,
      checks,
      details: {
        tokenContract: target,
        from,
        to,
        amount: amount.toString()
      }
    };
  }

  // ----------------------------------------------------
  // Operation Unknown / Unsupported Selector
  // Fails safe with advisory REVIEW
  // ----------------------------------------------------
  return {
    verdict: "REVIEW",
    riskLevel: "MEDIUM",
    operation: "UNKNOWN_OPERATION",
    reasons: [`Unrecognized or unsupported function selector: ${selector}`],
    checks: [
      ...checks,
      { id: "calldata_selector", status: "WARN", detail: `Selector ${selector} is not an analyzed standard ERC-20 method` }
    ],
    details: {
      target,
      selector,
      calldataByteLength: rawData.length / 2 - 1
    }
  };
}



module.exports = { inspectCalldata, UINT256_MAX, SELECTORS, default: inspectCalldata };
