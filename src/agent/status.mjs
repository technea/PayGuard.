/**
 * @module agent/status
 * @section Status normalization and precedence
 * Maps current PayGuard tool result conventions into the five-state evidence vocabulary.
 */
import { EVIDENCE_STATUSES, STATUS_PRECEDENCE } from "./constants.mjs";

const RISK_VERDICTS = new Set(["BLOCK", "SUSPICIOUS", "KNOWN_MALICIOUS", "RISK_DETECTED"]);
const UNKNOWN_VERDICTS = new Set(["REVIEW", "UNVERIFIED", "UNKNOWN", "NO_KNOWN_THREAT", "CAUTION"]);

function walletHasRisk(result) {
  return Array.isArray(result.tokens) && result.tokens.some(token =>
    RISK_VERDICTS.has(String(token?.verdict || "").toUpperCase()) ||
    ["HIGH", "CRITICAL"].includes(String(token?.riskLevel || "").toUpperCase()) ||
    ["HIGH RISK", "SUSPICIOUS"].includes(String(token?.securityStatus || "").toUpperCase())
  );
}

function calldataHasRisk(result) {
  if (result.verdict === "BLOCK") return true;
  return Array.isArray(result.checks) && result.checks.some(check =>
    ["FAIL", "FAILED", "fail", "failed"].includes(String(check?.status || ""))
  );
}

export function normalizeToolStatus(toolName, result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    return { status: "UNVERIFIED", reason: "Tool returned no structured result." };
  }

  const explicit = String(result.status || "").toUpperCase();
  const data = String(result.dataStatus || "").toUpperCase();
  const verdict = String(result.verdict || "").toUpperCase();

  if (["ERROR", "TIMEOUT", "FAILED"].includes(explicit)) {
    return { status: "ERROR", reason: "The tool reported an execution failure." };
  }
  if (RISK_VERDICTS.has(explicit) || RISK_VERDICTS.has(verdict)) {
    return { status: "RISK_DETECTED", reason: "The tool returned an explicit risk verdict." };
  }
  if (data === "ERROR") {
    return { status: "ERROR", reason: "The tool reported a provider or data-processing error." };
  }
  if (["UNAVAILABLE", "NOT_CONFIGURED", "UNSUPPORTED", "MALFORMED_INPUT", "INCOMPLETE"].includes(data)) {
    return { status: "UNVERIFIED", reason: "Tool data is unavailable, unsupported, or incomplete." };
  }

  if (toolName === "payguard_scan_wallet_tokens") {
    if (walletHasRisk(result)) return { status: "RISK_DETECTED", reason: "One or more wallet holdings contain explicit risk findings." };
    if (Number(result.summary?.unverifiedCount || 0) > 0) return { status: "UNVERIFIED", reason: "One or more wallet holdings could not be verified." };
    if (result.discoveryMode && result.discoveryMode !== "FULL_INDEXER") {
      return { status: "UNVERIFIED", reason: "Wallet discovery was partial; holdings outside the discovered scope were not checked." };
    }
    if (["SUCCESS", "COMPLETED", "PASS"].includes(explicit)) {
      return { status: "VERIFIED", reason: "The discovered wallet holdings passed implemented checks; this is not a safety guarantee." };
    }
  }

  if (toolName === "payguard_analyze_url" || toolName === "payguard_prepare_threat_report") {
    if (verdict === "CAUTION" || RISK_VERDICTS.has(verdict)) return { status: "RISK_DETECTED", reason: "URL analysis returned an explicit risk signal." };
    if (verdict === "EXPECTED_DOMAIN_MATCH") return { status: "VERIFIED", reason: "The URL matched an expected domain; this does not verify page content or payment safety." };
    if (UNKNOWN_VERDICTS.has(verdict)) return { status: "UNVERIFIED", reason: "The URL result is inconclusive; no known threat is not proof of legitimacy." };
  }

  if (toolName === "payguard_inspect_calldata") {
    if (calldataHasRisk(result)) return { status: "RISK_DETECTED", reason: "Calldata inspection identified an explicit failing check or risk reason." };
    if (verdict === "PASS") return { status: "VERIFIED", reason: "Supported calldata checks passed; unsupported selectors and execution effects are not covered." };
    if (UNKNOWN_VERDICTS.has(verdict)) return { status: "UNVERIFIED", reason: "Calldata inspection could not fully verify the proposed operation." };
  }

  if (toolName === "payguard_check_token_security" || toolName === "payguard_check_address_security") {
    if (verdict === "REVIEW") return { status: "UNVERIFIED", reason: "The provider returned review-level findings; this is inconclusive rather than a confirmed malicious verdict." };
    if (verdict === "PASS" && data === "AVAILABLE") {
      return { status: "VERIFIED", reason: "The provider returned data and implemented checks found no flagged issue; this is not a safety guarantee." };
    }
    if (verdict === "UNVERIFIED") return { status: "UNVERIFIED", reason: "Provider data or supported coverage was insufficient." };
  }

  if (toolName === "payguard_check_payment_intent") {
    if (explicit === "PASS" || verdict === "PASS") {
      return { status: "VERIFIED", reason: "Supplied payment fields matched explicit policy; merchant legitimacy and chain execution were not verified." };
    }
    if (explicit === "REVIEW" || UNKNOWN_VERDICTS.has(verdict)) {
      return { status: "UNVERIFIED", reason: "Payment policy checks were incomplete or inconclusive." };
    }
  }

  if (explicit === "PASS" || verdict === "PASS" || verdict === "VERIFIED") {
    return { status: "VERIFIED", reason: "Implemented checks passed; this is not a guarantee of safety." };
  }
  if (explicit === "UNVERIFIED" || UNKNOWN_VERDICTS.has(verdict) || result.error) {
    return { status: "UNVERIFIED", reason: "The tool result is incomplete or inconclusive." };
  }
  return { status: EVIDENCE_STATUSES.includes(explicit) ? explicit : "UNVERIFIED", reason: "No recognized verdict was present." };
}

export function resolveStatus(statuses) {
  if (!Array.isArray(statuses) || statuses.length === 0) return "NOT_CHECKED";
  return statuses.reduce((highest, current) => {
    const normalized = EVIDENCE_STATUSES.includes(current) ? current : "UNVERIFIED";
    return STATUS_PRECEDENCE[normalized] > STATUS_PRECEDENCE[highest] ? normalized : highest;
  }, "VERIFIED");
}
