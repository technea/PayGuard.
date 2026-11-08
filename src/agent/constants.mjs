/**
 * @module agent/constants
 * @section Evidence vocabulary and bounded defaults
 * Shared immutable constants for the deterministic PayGuard evidence layer.
 */

export const EVIDENCE_STATUSES = Object.freeze([
  "VERIFIED",
  "RISK_DETECTED",
  "UNVERIFIED",
  "NOT_CHECKED",
  "ERROR"
]);

export const STATUS_PRECEDENCE = Object.freeze({
  RISK_DETECTED: 5,
  ERROR: 4,
  UNVERIFIED: 3,
  NOT_CHECKED: 2,
  VERIFIED: 1
});

export const EVIDENCE_SCHEMA_VERSION = "payguard-evidence-v1";
export const MAX_RAW_OUTPUT_CHARS = 512_000;
export const MAX_UNTRUSTED_TEXT_ENTRIES = 64;
export const MAX_UNTRUSTED_TEXT_LENGTH = 2_048;
export const MAX_EVIDENCE_RECORDS = 32;

export const TOOL_CATALOG = Object.freeze({
  payguard_check_payment_intent: Object.freeze({ category: "payment-policy", title: "Payment intent policy" }),
  payguard_analyze_url: Object.freeze({ category: "url-security", title: "URL and domain analysis" }),
  payguard_prepare_threat_report: Object.freeze({ category: "threat-report", title: "Threat report preparation" }),
  payguard_inspect_calldata: Object.freeze({ category: "transaction-inspection", title: "Calldata inspection" }),
  payguard_check_token_security: Object.freeze({ category: "token-security", title: "Token security" }),
  payguard_check_address_security: Object.freeze({ category: "address-security", title: "Address reputation" }),
  payguard_scan_wallet_tokens: Object.freeze({ category: "wallet-security", title: "Wallet token scan" })
});
