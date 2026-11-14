/**
 * PayGuard — NEAR Security Agent Workflow Orchestration
 * Coordinates input validation, data retrieval, deterministic rule execution,
 * and synthesis of canonical evidence report.
 */

import { fetchNearAccountIntelligence } from "../modules/account-intelligence.mjs";
import { evaluateDeterministicRules } from "../modules/detection-engine.mjs";

export async function runNearSecurityAgent(input, options = {}) {
  const accountId = typeof input === "string" ? input : input?.accountId;

  // 1. Fetch normalized account intelligence
  const intel = await fetchNearAccountIntelligence(accountId, options);

  // 2. Fail-closed provider check
  if (intel.status === "UNVERIFIED") {
    return {
      status: "UNVERIFIED",
      verdict: "UNVERIFIED",
      target: intel.target,
      network: {
        networkId: "mainnet",
        rpcProvider: "FastNear",
        finality: "final"
      },
      assessment: {
        status: "UNVERIFIED",
        verdict: "UNVERIFIED",
        confidence: 0.0,
        coverage: {
          accountValidation: "FAILED",
          onChainState: "UNAVAILABLE",
          accessKeys: "UNAVAILABLE",
          bytecodeDecompilation: "NOT_CHECKED_PHASE_1",
          historicalTransactions: "NOT_CHECKED_PHASE_1"
        },
        error: intel.error,
        uncertaintyExplanation: "FastNear RPC state could not be finalized. Fail-closed: Never treat missing data as proof of safety.",
        limitations: [
          "RPC provider was unreachable or returned an unrecoverable error.",
          "Off-chain data was not queried."
        ]
      },
      uncertaintyExplanation: "FastNear RPC state could not be finalized. Fail-closed: Never treat missing data as proof of safety.",
      unavailableChecks: [
        "view_account",
        "view_access_key_list",
        "Contract Bytecode Verification"
      ],
      findings: [],
      timestamp: new Date().toISOString()
    };
  }

  // 3. Run deterministic detection engine
  const findings = evaluateDeterministicRules(intel);

  // 4. Calculate verdict
  const hasHighOrCritical = findings.some(f => f.severity === "HIGH" || f.severity === "CRITICAL");
  const hasMedium = findings.some(f => f.severity === "MEDIUM");

  let verdict = "LOW";
  if (intel.status === "INVALID_SYNTAX") {
    verdict = "HIGH";
  } else if (hasHighOrCritical) {
    verdict = "HIGH";
  } else if (hasMedium) {
    verdict = "MEDIUM";
  } else {
    verdict = "LOW";
  }

  // 5. Structure final evidence report
  const reportStatus = intel.status === "INVALID_SYNTAX" ? "INVALID_ACCOUNT_ID" :
                       (intel.status === "UNREGISTERED" ? "ACCOUNT_UNREGISTERED" :
                       (intel.status === "EXISTS" ? "AVAILABLE" : intel.status));

  return {
    status: reportStatus,
    verdict,
    target: intel.target,
    exists: intel.status === "EXISTS",
    contractSecurity: intel.profile?.hasContract ? {
      isDeployed: true,
      codeHash: intel.profile.codeHash,
      isKnownCanonical: Boolean(intel.profile.knownContract),
      details: intel.profile.knownContract
    } : {
      isDeployed: false,
      codeHash: intel.profile?.codeHash || null
    },
    keyAnalysis: intel.keys ? {
      totalKeys: intel.keys.totalKeys,
      fullAccessKeysCount: intel.keys.fullAccessKeysCount,
      functionCallKeysCount: intel.keys.functionCallKeysCount,
      noFullAccessKeys: intel.profile?.hasContract && intel.keys.fullAccessKeysCount === 0
    } : null,
    evidence: intel.blockReference ? [
      { type: "BLOCK_HEIGHT", value: intel.blockReference.height },
      { type: "BLOCK_HASH", value: intel.blockReference.hash },
      { type: "CODE_HASH", value: intel.profile?.codeHash },
      { type: "STORAGE_USAGE_BYTES", value: intel.profile?.storageUsageBytes },
      { type: "BALANCE_NEAR", value: intel.profile?.balanceNear },
      { type: "RPC_PROVIDER", value: intel.provider }
    ] : [],
    network: {
      networkId: "mainnet",
      rpcProvider: intel.provider || "FastNear",
      finality: "final"
    },
    blockReference: intel.blockReference || null,
    accountProfile: intel.profile ? {
      accountType: intel.accountType,
      status: intel.status,
      balanceYocto: intel.profile.balanceYocto,
      balanceNear: intel.profile.balanceNear,
      storageUsageBytes: intel.profile.storageUsageBytes,
      codeHash: intel.profile.codeHash,
      hasContract: intel.profile.hasContract,
      keyMetrics: intel.keys ? {
        totalKeys: intel.keys.totalKeys,
        fullAccessKeys: intel.keys.fullAccessKeysCount,
        functionCallKeys: intel.keys.functionCallKeysCount
      } : null
    } : {
      accountType: intel.accountType,
      status: intel.status
    },
    findings,
    unavailableChecks: [
      "Contract Source AST & Dynamic Taint Analysis",
      "Off-Chain KYC / Social Identity Proofs",
      "Historical mempool frontrunning logs"
    ],
    assessment: {
      status: intel.status,
      verdict,
      confidence: intel.status === "EXISTS" ? 0.95 : (intel.status === "UNREGISTERED" ? 0.85 : 0.0),
      coverage: {
        accountValidation: "VERIFIED",
        onChainState: intel.status === "EXISTS" ? "VERIFIED" : (intel.status === "UNREGISTERED" ? "CONFIRMED_NONEXISTENT" : "FAILED"),
        accessKeys: intel.keysStatus === "AVAILABLE" ? "VERIFIED" : "UNAVAILABLE",
        bytecodeDecompilation: "NOT_CHECKED_PHASE_1",
        historicalTransactions: "NOT_CHECKED_PHASE_1"
      },
      limitations: [
        "Phase 1 evaluates canonical state and access keys. Historical transfer graph requires indexer APIs (Phase 2).",
        "Zero FullAccess keys does not guarantee internal immutability if contract has self-upgrade methods.",
        "Off-chain social identity and DNS ownership were not inspected."
      ]
    },
    timestamp: new Date().toISOString()
  };
}
