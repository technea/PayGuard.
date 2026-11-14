/**
 * Pure deterministic detection engine.
 * Categorizes observable facts, suspicious indicators, and confirmed threats.
 */

import { NEAR_CANONICAL_ACCOUNTS, SUSPICIOUS_NEAR_KEYWORDS } from "../registry/canonical-accounts.mjs";

export function evaluateDeterministicRules(accountIntel) {
  const findings = [];

  if (accountIntel.status === "INVALID_SYNTAX") {
    findings.push({
      ruleId: "NEAR_SYNTAX_INVALID_ACCOUNT_ID",
      category: "SYNTAX",
      type: "CONFIRMED_THREAT",
      severity: "HIGH",
      description: `Account ID violates NEAR protocol specification: ${accountIntel.error}`
    });
    return findings;
  }

  if (accountIntel.status === "UNREGISTERED") {
    findings.push({
      ruleId: "NEAR_STATE_ACCOUNT_UNREGISTERED",
      category: "STATE",
      type: "FACT",
      severity: "INFO",
      confidence: "HIGH",
      description: "Account has not been created or registered on-chain in finalized state."
    });
  }

  const target = accountIntel.target || "";
  const lower = target.toLowerCase();

  // 1. Phishing & Malicious Lexer Rules
  for (const kw of SUSPICIOUS_NEAR_KEYWORDS) {
    if (lower.includes(kw)) {
      findings.push({
        ruleId: "NEAR_PHISH_SUSPICIOUS_KEYWORD",
        category: "IMPERSONATION",
        type: "SUSPICIOUS_INDICATOR",
        severity: "MEDIUM",
        description: `Account identifier contains sensitive promotional or credential keyword: "${kw}"`
      });
      break;
    }
  }

  // 2. Canonical Impersonation Rule
  for (const canon of NEAR_CANONICAL_ACCOUNTS) {
    const base = canon.split(".")[0];
    if (base.length >= 4 && lower !== canon && lower.includes(base) && !lower.endsWith("." + canon) && !lower.startsWith(canon + ".")) {
      findings.push({
        ruleId: "NEAR_IMPERSONATION_CANONICAL_NAME",
        category: "IMPERSONATION",
        type: "SUSPICIOUS_INDICATOR",
        severity: "HIGH",
        description: `Account name mimics official ecosystem protocol or project entity "${canon}"`
      });
      break;
    }
  }

  // 3. Homoglyph / Confusable detection (excludes exact canonical entries)
  const isExactCanonical = NEAR_CANONICAL_ACCOUNTS.includes(lower) || lower.endsWith(".near") && NEAR_CANONICAL_ACCOUNTS.includes(lower.slice(0, -5));
  if (!isExactCanonical && /ne[43]r|teth[e3]r|w[4a]ll[e3]t|r[3e]f-f[1i]n/.test(lower)) {
    findings.push({
      ruleId: "NEAR_IMPERSONATION_HOMOGLYPH_DECEPTION",
      category: "IMPERSONATION",
      type: "CONFIRMED_THREAT",
      severity: "HIGH",
      description: "Account name employs leetspeak or homoglyph substitutions to mimic protocol terms."
    });
  }

  if (accountIntel.status !== "EXISTS") {
    return findings;
  }

  const { profile, keys, blockReference } = accountIntel;

  // 4. Block Divergence Rule (Atomic snapshot validation)
  if (blockReference?.isBlockDivergent) {
    findings.push({
      ruleId: "NEAR_STATE_BLOCK_DIVERGENCE",
      category: "CONSISTENCY",
      type: "SUSPICIOUS_INDICATOR",
      severity: "LOW",
      confidence: "HIGH",
      description: `State and access keys were fetched across divergent block heights (account block ${blockReference.height} vs keys block ${blockReference.keysBlockHeight}, delta = ${blockReference.blockDifference}). Evidence is not an atomic point-in-time snapshot.`
    });
  }

  // 5. Bytecode & Contract Rules
  if (profile?.hasContract) {
    if (profile.knownContract) {
      findings.push({
        ruleId: "NEAR_FACT_CANONICAL_CONTRACT_MATCH",
        category: "BYTECODE",
        type: "FACT",
        severity: "INFO",
        confidence: "HIGH",
        description: `Verified bytecode matches canonical ecosystem registry: ${profile.knownContract.name}`
      });
    } else {
      findings.push({
        ruleId: "NEAR_FACT_CUSTOM_CONTRACT_DEPLOYED",
        category: "BYTECODE",
        type: "FACT",
        severity: "INFO",
        confidence: "HIGH",
        description: `Custom smart contract bytecode deployed (Code hash: ${profile.codeHash.slice(0, 10)}...)`
      });
    }

    // 6. Access Key Security on Contracts
    if (keys?.fullAccessKeysCount === 0) {
      findings.push({
        ruleId: "NEAR_FACT_NO_FULL_ACCESS_KEYS",
        category: "AUTHENTICATION",
        type: "FACT",
        severity: "INFO",
        confidence: "HIGH",
        description: "Contract possesses 0 FullAccess keys: contract code cannot be directly replaced via standard DeployContract transaction."
      });
    } else if (keys && keys.fullAccessKeysCount > 0) {
      findings.push({
        ruleId: "NEAR_AUTH_CONTRACT_HAS_FULL_ACCESS",
        category: "AUTHENTICATION",
        type: "FACT",
        severity: "INFO", // Kept as INFO per NR-003 guidelines
        confidence: "HIGH",
        description: `Contract possesses ${keys.fullAccessKeysCount} active FullAccess key(s). State or code could be modified by key holders.`
      });
    }
  } else {
    findings.push({
      ruleId: "NEAR_FACT_NO_CONTRACT",
      category: "BYTECODE",
      type: "FACT",
      severity: "INFO",
      confidence: "HIGH",
      description: "Standard account without smart contract bytecode."
    });
  }

  // 7. NR-002: Zero Access Keys (Keyless Account evaluation)
  if (keys && keys.totalKeys === 0) {
    if (profile?.hasContract) {
      findings.push({
        ruleId: "NEAR_FACT_IMMUTABLE_CONTRACT_STATE",
        category: "AUTHENTICATION",
        type: "FACT",
        severity: "INFO",
        confidence: "HIGH",
        description: "Account has 0 access keys but hosts deployed contract code (autonomous/immutable contract state)."
      });
    } else {
      findings.push({
        ruleId: "NEAR_AUTH_ZERO_ACCESS_KEYS",
        category: "AUTHENTICATION",
        type: "FACT",
        severity: "INFO",
        confidence: "HIGH",
        description: "Operational status: Account has 0 active access keys and no contract code deployed (inactive or locked key state). Does not imply malicious compromise."
      });
    }
  }

  // 8. NR-003: FullAccess Key Inventory (Informational only, no automatic risk points)
  if (keys && keys.fullAccessKeysCount > 3) {
    findings.push({
      ruleId: "NEAR_AUTH_MULTIPLE_FULL_ACCESS_KEYS",
      category: "AUTHENTICATION",
      type: "FACT",
      severity: "INFO",
      confidence: "HIGH",
      description: `Account maintains ${keys.fullAccessKeysCount} active FullAccess keys (common for multi-device setups; review to ensure all keys are recognized).`
    });
  }

  // 9. NR-004: FunctionCall Permission & Gas Exposure
  if (keys && Array.isArray(keys.functionCallKeys)) {
    for (const fc of keys.functionCallKeys) {
      // Flag as indicator only if receiver is missing or unverified, or explicitly flagged
      if (fc.isWildcardMethod && fc.isUnlimitedAllowance && !profile?.hasContract) {
        findings.push({
          ruleId: "NEAR_PERM_UNRESTRICTED_FUNCTION_CALL",
          category: "AUTHENTICATION",
          type: "SUSPICIOUS_INDICATOR",
          severity: "MEDIUM",
          confidence: "HIGH",
          description: `FunctionCall key for receiver "${fc.receiverId || 'any'}" has unrestricted method execution and unlimited gas allowance.`
        });
      } else if (fc.isUnlimitedAllowance || fc.isWildcardMethod) {
        findings.push({
          ruleId: "NEAR_PERM_FUNCTION_CALL_INFO",
          category: "AUTHENTICATION",
          type: "FACT",
          severity: "INFO",
          confidence: "HIGH",
          description: `FunctionCall key for receiver "${fc.receiverId || 'any'}" with ${fc.isUnlimitedAllowance ? 'unlimited gas allowance' : 'custom allowance'}${fc.methodNames.length > 0 ? ` on methods: ${fc.methodNames.join(', ')}` : ' (all methods permitted)'}.`
        });
      }
    }
  }

  // 10. NR-005: Storage Capacity & Operational Health
  if (profile?.storageUsageBytes && profile?.balanceYocto) {
    try {
      const storageBytes = BigInt(profile.storageUsageBytes);
      const balanceYocto = BigInt(profile.balanceYocto);
      // NEAR storage staking cost: 1 NEAR (10^24 yocto) per 100 KB (100,000 bytes) -> 10^19 yocto per byte
      const storageStakeRequiredYocto = storageBytes * 10000000000000000000n;
      
      // If liquid balance is less than 10% of the storage stake requirement, flag as operational health note
      if (balanceYocto < (storageStakeRequiredYocto / 10n)) {
        findings.push({
          ruleId: "NEAR_STORAGE_PRESSURE_INDICATOR",
          category: "STORAGE",
          type: "FACT",
          severity: "LOW",
          confidence: "HIGH",
          description: "Operational Health: Liquid NEAR balance is very low relative to consumed storage stake. State additions may fail without additional deposits."
        });
      }
    } catch {
      // Precision handling fallback
    }
  }

  return findings;
}

export function analyzeNearAccountNameHeuristics(accountId) {
  const findings = [];
  const lower = (accountId || "").toLowerCase();

  for (const kw of SUSPICIOUS_NEAR_KEYWORDS) {
    if (lower.includes(kw)) {
      findings.push({
        code: "SUSPICIOUS_KEYWORD",
        severity: "medium",
        message: `Account name contains high-risk security keyword: "${kw}"`
      });
    }
  }

  for (const canon of NEAR_CANONICAL_ACCOUNTS) {
    const base = canon.split(".")[0];
    if (base.length >= 3 && lower !== canon && lower.includes(base) && !lower.endsWith("." + canon)) {
      findings.push({
        code: "CANONICAL_IMPERSONATION_RISK",
        severity: "high",
        message: `Account name mimics or embeds official ecosystem entity "${canon}"`
      });
      break;
    }
  }

  if (/ne[43]r|teth[e3]r|w[4a]ll[e3]t|r[3e]f-f[1i]n/.test(lower)) {
    findings.push({
      code: "HOMOGLYPH_DECEPTION",
      severity: "high",
      message: "Account name contains confusable leetspeak/homoglyph patterns mimicking official protocol terms"
    });
  }

  return findings;
}
