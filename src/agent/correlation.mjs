/**
 * @module agent/correlation
 * @section Payment intent to transaction correlation
 * Compares a selected x402 payment option with decoded ERC-20 transfer calldata.
 * This is deterministic correlation of supplied data, not chain execution or settlement proof.
 */

export const CORRELATION_SOURCE = "payguard_agent_intent_transaction_correlation";

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const ATOMIC_INTEGER = /^(0|[1-9][0-9]{0,77})$/;

function record(status, reason, checks, extra = {}) {
  return { status, reason, checks, ...extra };
}

function normalizeAddress(value) {
  return typeof value === "string" && EVM_ADDRESS.test(value) ? value.toLowerCase() : null;
}

function normalizeNetwork(value) {
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return `eip155:${value}`;
  if (typeof value !== "string" || !value.trim()) return null;
  const normalized = value.trim().toLowerCase();
  if (/^[0-9]+$/.test(normalized)) return `eip155:${normalized}`;
  return /^eip155:[0-9]+$/.test(normalized) ? normalized : null;
}

function normalizeAmount(value) {
  if (typeof value === "bigint" && value >= 0n) return value.toString();
  if (typeof value !== "string" || !ATOMIC_INTEGER.test(value)) return null;
  return BigInt(value).toString();
}

function check(checks, id, status, detail, expected = null, actual = null) {
  checks.push({ id, status, detail, expected, actual });
}

export function correlatePaymentAndTransaction({ input, paymentEvidence, calldataEvidence } = {}) {
  if (!input || !Object.hasOwn(input, "transaction") ||
      (!Object.hasOwn(input, "intent") && !Object.hasOwn(input, "paymentRequirements"))) {
    return record("NOT_CHECKED", "A transaction and payment context were not both requested.", []);
  }
  if (!Object.hasOwn(input, "intent") || !Object.hasOwn(input, "paymentRequirements")) {
    return record("NOT_CHECKED", "Correlation requires both trusted user intent and received payment requirements.", []);
  }
  if (paymentEvidence?.status === "ERROR" || calldataEvidence?.status === "ERROR") {
    return record("ERROR", "A required payment or calldata check failed to execute.", []);
  }
  if (!paymentEvidence || !calldataEvidence ||
      paymentEvidence.status === "NOT_CHECKED" || calldataEvidence.status === "NOT_CHECKED") {
    return record("NOT_CHECKED", "The payment policy or calldata check was not executed.", []);
  }
  if (calldataEvidence.status === "RISK_DETECTED") {
    return record("RISK_DETECTED", "Calldata inspection already identified an explicit transaction risk.", []);
  }
  if (calldataEvidence.status !== "VERIFIED") {
    return record("UNVERIFIED", "Calldata did not produce a fully supported transfer result for correlation.", []);
  }

  const paymentOutput = paymentEvidence.rawOutput;
  const calldataOutput = calldataEvidence.rawOutput;
  const accepts = input.paymentRequirements?.accepts;
  if (!paymentOutput || !Array.isArray(accepts) || accepts.length === 0 || !calldataOutput) {
    return record("UNVERIFIED", "Payment options or decoded transaction evidence are missing.", []);
  }

  let selectedIndex = input.selectedPaymentIndex;
  if (selectedIndex === undefined && accepts.length === 1) selectedIndex = 0;
  if (!Number.isSafeInteger(selectedIndex) || selectedIndex < 0 || selectedIndex >= accepts.length) {
    return record("UNVERIFIED", "Select the payment option used for this transaction; multiple alternatives cannot be correlated safely without an explicit selection.", []);
  }

  const candidate = accepts[selectedIndex];
  const candidateResult = Array.isArray(paymentOutput.candidateResults)
    ? paymentOutput.candidateResults.find(item => item?.index === selectedIndex)
    : null;
  if (candidateResult?.status === "BLOCK") {
    return record("RISK_DETECTED", "The selected payment option violates the explicit user payment policy.", [], { selectedPaymentIndex: selectedIndex });
  }
  if (candidateResult?.status !== "PASS") {
    return record("UNVERIFIED", "The selected payment option did not receive a complete PASS from the payment policy check.", [], { selectedPaymentIndex: selectedIndex });
  }

  if (!["ERC20_TRANSFER", "ERC20_TRANSFER_FROM"].includes(calldataOutput.operation)) {
    return record("UNVERIFIED", "Only decoded ERC-20 transfer and transferFrom operations can be correlated to an x402 token payment. Approval and unsupported operations are not treated as payment transfers.", [], {
      selectedPaymentIndex: selectedIndex,
      operation: calldataOutput.operation || "UNKNOWN"
    });
  }

  const details = calldataOutput.details || {};
  const transaction = input.transaction && typeof input.transaction === "object" ? input.transaction : {};
  const checks = [];

  const expectedNetwork = normalizeNetwork(candidate?.network);
  const actualNetwork = normalizeNetwork(transaction.network);
  if (!expectedNetwork || !actualNetwork) {
    check(checks, "payment_network", "UNKNOWN", "Network could not be compared because the payment option or transaction context omitted it.");
  } else if (expectedNetwork !== actualNetwork) {
    check(checks, "payment_network", "FAIL", "Transaction network differs from the selected payment option.", expectedNetwork, actualNetwork);
  } else {
    check(checks, "payment_network", "PASS", "Transaction network matches the selected payment option.", expectedNetwork, actualNetwork);
  }

  const expectedAsset = normalizeAddress(candidate?.asset);
  const actualAsset = normalizeAddress(details.tokenContract);
  if (!expectedAsset || !actualAsset) {
    check(checks, "payment_asset", "UNKNOWN", "The payment asset or decoded token contract is not a supported EVM address.");
  } else if (expectedAsset !== actualAsset) {
    check(checks, "payment_asset", "FAIL", "Decoded token contract differs from the selected payment asset.", expectedAsset, actualAsset);
  } else {
    check(checks, "payment_asset", "PASS", "Decoded token contract matches the selected payment asset.", expectedAsset, actualAsset);
  }

  const expectedRecipient = normalizeAddress(candidate?.payTo);
  const actualRecipient = normalizeAddress(details.recipient || details.to);
  if (!expectedRecipient || !actualRecipient) {
    check(checks, "payment_recipient", "UNKNOWN", "The selected recipient or decoded transfer recipient is not a supported EVM address.");
  } else if (expectedRecipient !== actualRecipient) {
    check(checks, "payment_recipient", "FAIL", "Decoded transfer recipient differs from the selected payment recipient.", expectedRecipient, actualRecipient);
  } else {
    check(checks, "payment_recipient", "PASS", "Decoded transfer recipient matches the selected payment recipient.", expectedRecipient, actualRecipient);
  }

  const expectedAmount = normalizeAmount(candidate?.amount ?? candidate?.maxAmountRequired);
  const actualAmount = normalizeAmount(details.amount);
  if (expectedAmount === null || actualAmount === null) {
    check(checks, "payment_amount", "UNKNOWN", "The payment amount or decoded transfer amount is missing or malformed.");
  } else if (expectedAmount !== actualAmount) {
    check(checks, "payment_amount", "FAIL", "Decoded transfer amount differs from the selected payment amount.", expectedAmount, actualAmount);
  } else {
    check(checks, "payment_amount", "PASS", "Decoded transfer amount matches the selected payment amount.", expectedAmount, actualAmount);
  }

  const failed = checks.some(item => item.status === "FAIL");
  const unknown = checks.some(item => item.status === "UNKNOWN");
  if (failed) {
    return record("RISK_DETECTED", "At least one decoded transaction field conflicts with the selected payment option.", checks, { selectedPaymentIndex: selectedIndex });
  }
  if (unknown) {
    return record("UNVERIFIED", "The supplied payment and transaction context could not be fully correlated.", checks, { selectedPaymentIndex: selectedIndex });
  }
  return record("VERIFIED", "The decoded ERC-20 transfer matches the selected payment option's network, asset, recipient, and amount. This does not prove on-chain execution or settlement.", checks, {
    selectedPaymentIndex: selectedIndex
  });
}
