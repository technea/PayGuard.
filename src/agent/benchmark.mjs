/**
 * @module agent/benchmark
 * @section Synthetic offline benchmark runner
 * Exercises existing deterministic evaluators with local fixtures only.
 * Results measure fixture regression behavior, not real-world detection accuracy.
 */

import { analyzeUrlSecurity, evaluatePaymentIntent } from "../plugin.mjs";
import { inspectCalldata, SELECTORS, UINT256_MAX } from "../calldata-inspector.mjs";
import { evaluateTokenSecurityData } from "../token-security.mjs";
import { evaluateAddressSecurityData } from "../address-security.mjs";
import { normalizeToolResult } from "./normalize-result.mjs";
import { correlatePaymentAndTransaction, CORRELATION_SOURCE } from "./correlation.mjs";
import { createDerivedEvidence } from "./evidence-record.mjs";
import {
  SYNTHETIC_BENCHMARK_VERSION,
  SYNTHETIC_ADDRESSES,
  SYNTHETIC_PAYMENT_POLICY,
  SYNTHETIC_PAYMENT_REQUIREMENTS
} from "./benchmark-fixtures.mjs";

function padAddress(address) {
  return address.toLowerCase().slice(2).padStart(64, "0");
}

function padUint256(value) {
  return BigInt(value).toString(16).padStart(64, "0");
}

function addCase(cases, id, category, expectedStatus, actual, note) {
  cases.push({
    id,
    category,
    expectedStatus,
    actualStatus: actual.status,
    matched: actual.status === expectedStatus,
    reason: actual.reason || note || null
  });
}

function summarize(cases) {
  const benign = cases.filter(item => item.expectedStatus === "VERIFIED");
  const risks = cases.filter(item => item.expectedStatus === "RISK_DETECTED");
  const unresolvedExpected = cases.filter(item => item.expectedStatus === "UNVERIFIED");
  const matched = cases.filter(item => item.matched).length;
  const detectedRisks = risks.filter(item => item.actualStatus === "RISK_DETECTED").length;
  const falsePositives = benign.filter(item => item.actualStatus === "RISK_DETECTED").map(item => item.id);
  const falseNegatives = risks.filter(item => item.actualStatus === "VERIFIED").map(item => item.id);
  const missedRisks = risks.filter(item => item.actualStatus !== "RISK_DETECTED").map(item => item.id);
  const unresolved = cases.filter(item => ["UNVERIFIED", "NOT_CHECKED", "ERROR"].includes(item.actualStatus));

  return {
    totalCases: cases.length,
    matchedCases: matched,
    fixtureMatchRate: Number((matched / Math.max(cases.length, 1)).toFixed(4)),
    expectedRiskCases: risks.length,
    detectedRiskCases: detectedRisks,
    syntheticRiskDetectionRate: Number((detectedRisks / Math.max(risks.length, 1)).toFixed(4)),
    expectedBenignCases: benign.length,
    falsePositiveCases: falsePositives,
    syntheticFalsePositiveRate: Number((falsePositives.length / Math.max(benign.length, 1)).toFixed(4)),
    falseNegativeCases: falseNegatives,
    missedRiskCases: missedRisks,
    unresolvedCases: unresolved.map(item => ({ id: item.id, actualStatus: item.actualStatus })),
    expectedUnverifiedCases: unresolvedExpected.length
  };
}

export async function runSyntheticBenchmark() {
  const cases = [];
  const { token, trustedRecipient, alternateRecipient, spender } = SYNTHETIC_ADDRESSES;

  const trustedUrl = await analyzeUrlSecurity({
    url: "https://merchant.example/pay",
    expectedDomain: "merchant.example"
  });
  addCase(cases, "url.trusted-domain-match", "url", "VERIFIED",
    normalizeToolResult("payguard_analyze_url", trustedUrl), "Trusted-domain match fixture.");

  const phishingUrl = await analyzeUrlSecurity({
    url: "https://merchant-wallet-claim.attacker.example/connect-wallet",
    expectedDomain: "merchant.example"
  });
  addCase(cases, "url.lookalike-phishing", "url", "RISK_DETECTED",
    normalizeToolResult("payguard_analyze_url", phishingUrl), "Synthetic phishing-style URL fixture.");

  const cleanToken = evaluateTokenSecurityData({
    is_honeypot: "0",
    cannot_buy: "0",
    cannot_sell_all: "0",
    owner_change_balance: "0",
    buy_tax: "0",
    sell_tax: "0",
    slippage_modifiable: "0",
    transfer_pausable: "0",
    is_mintable: "0",
    is_proxy: "0",
    is_open_source: "1",
    trust_list: "0"
  }, "8453", token);
  addCase(cases, "token.no-known-risk-signals", "token", "VERIFIED",
    normalizeToolResult("payguard_check_token_security", cleanToken), "Synthetic clean GoPlus-shaped payload.");

  const honeypotToken = evaluateTokenSecurityData({
    is_honeypot: "1",
    buy_tax: "0",
    sell_tax: "0"
  }, "8453", token);
  addCase(cases, "token.honeypot-flag", "token", "RISK_DETECTED",
    normalizeToolResult("payguard_check_token_security", honeypotToken), "Synthetic honeypot provider flag.");

  const cleanAddress = evaluateAddressSecurityData({
    phishing_activities: "0",
    stealing_attack: "0",
    sanctioned: "0",
    blacklist_doubt: "0",
    honeypot_related_address: "0",
    fake_token: "0",
    cybercrime: "0",
    money_laundering: "0",
    financial_crime: "0",
    blackmail_activities: "0",
    darkweb_transactions: "0",
    mixer: "0",
    fake_kyc: "0",
    gas_abuse: "0",
    malicious_mining_activities: "0",
    number_of_malicious_contracts_created: "0"
  }, "8453", trustedRecipient);
  addCase(cases, "address.no-known-risk-flags", "address", "VERIFIED",
    normalizeToolResult("payguard_check_address_security", cleanAddress), "Synthetic clean GoPlus-shaped payload.");

  const phishingAddress = evaluateAddressSecurityData({
    phishing_activities: "1"
  }, "8453", alternateRecipient);
  addCase(cases, "address.phishing-flag", "address", "RISK_DETECTED",
    normalizeToolResult("payguard_check_address_security", phishingAddress), "Synthetic phishing address flag.");

  const normalTransferData = SELECTORS.ERC20_TRANSFER + padAddress(trustedRecipient) + padUint256(5_000_000n);
  const normalTransfer = inspectCalldata({ to: token, data: normalTransferData });
  const normalTransferEvidence = normalizeToolResult("payguard_inspect_calldata", normalTransfer);
  addCase(cases, "calldata.standard-transfer", "calldata", "VERIFIED",
    normalTransferEvidence, "Synthetic ERC-20 transfer fixture.");

  const unlimitedApprovalData = SELECTORS.ERC20_APPROVE + padAddress(spender) + padUint256(UINT256_MAX);
  const unlimitedApproval = inspectCalldata({ to: token, data: unlimitedApprovalData });
  addCase(cases, "calldata.unlimited-approval", "calldata", "RISK_DETECTED",
    normalizeToolResult("payguard_inspect_calldata", unlimitedApproval), "Synthetic unlimited-allowance fixture.");

  const unsupportedSelector = inspectCalldata({ to: token, data: "0x12345678" });
  addCase(cases, "calldata.unsupported-selector", "calldata", "UNVERIFIED",
    normalizeToolResult("payguard_inspect_calldata", unsupportedSelector), "Unsupported selectors remain unverified.");

  const safePayment = evaluatePaymentIntent({
    intent: { ...SYNTHETIC_PAYMENT_POLICY },
    paymentRequirements: structuredClone(SYNTHETIC_PAYMENT_REQUIREMENTS)
  });
  const safePaymentEvidence = normalizeToolResult("payguard_check_payment_intent", safePayment);
  addCase(cases, "payment-intent.policy-match", "payment-intent", "VERIFIED",
    safePaymentEvidence, "Synthetic x402 payment option matching the explicit policy.");

  const mismatchedPaymentRequirements = structuredClone(SYNTHETIC_PAYMENT_REQUIREMENTS);
  mismatchedPaymentRequirements.accepts[0].payTo = alternateRecipient;
  const mismatchedPayment = evaluatePaymentIntent({
    intent: { ...SYNTHETIC_PAYMENT_POLICY },
    paymentRequirements: mismatchedPaymentRequirements
  });
  addCase(cases, "payment-intent.recipient-policy-mismatch", "payment-intent", "RISK_DETECTED",
    normalizeToolResult("payguard_check_payment_intent", mismatchedPayment), "Synthetic x402 recipient mismatch.");

  const correlationInput = {
    intent: { ...SYNTHETIC_PAYMENT_POLICY },
    paymentRequirements: structuredClone(SYNTHETIC_PAYMENT_REQUIREMENTS),
    transaction: { network: "eip155:8453", to: token, data: normalTransferData }
  };
  const matchingCorrelation = correlatePaymentAndTransaction({
    input: correlationInput,
    paymentEvidence: safePaymentEvidence,
    calldataEvidence: normalTransferEvidence
  });
  const matchingCorrelationEvidence = createDerivedEvidence(CORRELATION_SOURCE, matchingCorrelation, {
    status: matchingCorrelation.status,
    reason: matchingCorrelation.reason
  });
  addCase(cases, "correlation.intent-transfer-match", "payment-correlation", "VERIFIED",
    matchingCorrelationEvidence, "Synthetic payment intent and transfer fields match.");

  const mismatchedTransferData = SELECTORS.ERC20_TRANSFER + padAddress(alternateRecipient) + padUint256(5_000_000n);
  const mismatchedTransfer = inspectCalldata({ to: token, data: mismatchedTransferData });
  const mismatchedTransferEvidence = normalizeToolResult("payguard_inspect_calldata", mismatchedTransfer);
  const mismatchedCorrelation = correlatePaymentAndTransaction({
    input: correlationInput,
    paymentEvidence: safePaymentEvidence,
    calldataEvidence: mismatchedTransferEvidence
  });
  const mismatchedCorrelationEvidence = createDerivedEvidence(CORRELATION_SOURCE, mismatchedCorrelation, {
    status: mismatchedCorrelation.status,
    reason: mismatchedCorrelation.reason
  });
  addCase(cases, "correlation.recipient-mismatch", "payment-correlation", "RISK_DETECTED",
    mismatchedCorrelationEvidence, "Synthetic intended-recipient versus decoded-recipient mismatch.");

  return {
    benchmarkVersion: SYNTHETIC_BENCHMARK_VERSION,
    benchmarkType: "SYNTHETIC_OFFLINE",
    fixtureSource: "Hand-authored synthetic fixtures; no live threat samples.",
    externalNetworkCalls: 0,
    realWorldAccuracyClaim: false,
    summary: summarize(cases),
    cases
  };
}
