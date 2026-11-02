import test from "node:test";
import assert from "node:assert/strict";
import {
  inspectCalldata,
  UINT256_MAX,
  SELECTORS
} from "../src/calldata-inspector.mjs";

const TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"; // Base USDC
const SPENDER = "0x111111125421ca6dc452d289314280a0f8842a65"; // 1inch router
const RECIPIENT = "0x2222222222222222222222222222222222222222";
const SENDER = "0x3333333333333333333333333333333333333333";

// Helper to encode standard ERC-20 calldata
function padAddress(addr) {
  return addr.toLowerCase().replace("0x", "").padStart(64, "0");
}

function padUint256(val) {
  return BigInt(val).toString(16).padStart(64, "0");
}

test("1. approve() with uint256.max returns REVIEW with warning for unlimited allowance", () => {
  const calldata = SELECTORS.ERC20_APPROVE + padAddress(SPENDER) + padUint256(UINT256_MAX);
  const result = inspectCalldata({ to: TOKEN, data: calldata });

  assert.equal(result.verdict, "REVIEW");
  assert.equal(result.riskLevel, "MEDIUM");
  assert.equal(result.operation, "ERC20_APPROVE");
  assert.ok(result.reasons.includes("UNLIMITED_ALLOWANCE_UINT256_MAX"));
  assert.equal(result.details.isUnlimited, true);
  assert.equal(result.details.spender, SPENDER.toLowerCase());
});

test("2. approve() with normal limited allowance returns PASS when no policy violated", () => {
  const calldata = SELECTORS.ERC20_APPROVE + padAddress(SPENDER) + padUint256(100000000n); // 100 USDC
  const result = inspectCalldata({ to: TOKEN, data: calldata });

  assert.equal(result.verdict, "PASS");
  assert.equal(result.riskLevel, "LOW");
  assert.equal(result.operation, "ERC20_APPROVE");
  assert.equal(result.details.isUnlimited, false);
  assert.equal(result.details.rawAmount, "100000000");
});

test("3. valid transfer() and transferFrom() decoding returns PASS with extracted details", () => {
  // transfer(recipient, 5000000)
  const transferData = SELECTORS.ERC20_TRANSFER + padAddress(RECIPIENT) + padUint256(5000000n);
  const transferRes = inspectCalldata({ to: TOKEN, data: transferData });

  assert.equal(transferRes.verdict, "PASS");
  assert.equal(transferRes.operation, "ERC20_TRANSFER");
  assert.equal(transferRes.details.recipient, RECIPIENT.toLowerCase());
  assert.equal(transferRes.details.amount, "5000000");

  // transferFrom(sender, recipient, 2500000)
  const tfData = SELECTORS.ERC20_TRANSFER_FROM + padAddress(SENDER) + padAddress(RECIPIENT) + padUint256(2500000n);
  const tfRes = inspectCalldata({ to: TOKEN, data: tfData });

  assert.equal(tfRes.verdict, "PASS");
  assert.equal(tfRes.operation, "ERC20_TRANSFER_FROM");
  assert.equal(tfRes.details.from, SENDER.toLowerCase());
  assert.equal(tfRes.details.to, RECIPIENT.toLowerCase());
  assert.equal(tfRes.details.amount, "2500000");
});

test("4. invalid or truncated calldata returns BLOCK or REVIEW properly", () => {
  // Truncated approve: 4 bytes selector + 30 bytes (less than 68 bytes total)
  const truncatedApprove = SELECTORS.ERC20_APPROVE + "00".repeat(30);
  const res1 = inspectCalldata({ to: TOKEN, data: truncatedApprove });
  assert.equal(res1.verdict, "BLOCK");
  assert.match(res1.reasons[0], /Malformed approve\(\) calldata length/);

  // Calldata shorter than 4-byte selector (e.g. 0x12)
  const shortData = "0x1234";
  const res2 = inspectCalldata({ to: TOKEN, data: shortData });
  assert.equal(res2.verdict, "REVIEW");
  assert.equal(res2.operation, "TRUNCATED_CALLDATA");

  // Non-hex calldata
  const nonHex = "0xINVALIDHEXSTRING!!";
  const res3 = inspectCalldata({ to: TOKEN, data: nonHex });
  assert.equal(res3.verdict, "BLOCK");
  assert.equal(res3.operation, "MALFORMED_CALLDATA");
});

test("5. invalid target address or malformed native value returns BLOCK", () => {
  // Bad target address
  const res1 = inspectCalldata({ to: "0xInvalidShort", data: "0x" });
  assert.equal(res1.verdict, "BLOCK");
  assert.equal(res1.operation, "INVALID_TARGET");

  // Malformed native value
  const res2 = inspectCalldata({ to: TOKEN, value: "not-a-number", data: "0x" });
  assert.equal(res2.verdict, "BLOCK");
  assert.equal(res2.operation, "INVALID_VALUE");
});

test("6. unapproved target, spender, or recipient violates configured policy and returns BLOCK", () => {
  const policy = {
    allowedTargets: [TOKEN],
    allowedSpenders: [SPENDER],
    allowedRecipients: [RECIPIENT],
    maxTransferAmount: 1000000n // Max 1 USDC
  };

  // Case A: Target not in allowlist
  const badTarget = "0x9999999999999999999999999999999999999999";
  const resA = inspectCalldata({ to: badTarget, data: "0x" }, policy);
  assert.equal(resA.verdict, "BLOCK");
  assert.ok(resA.reasons.includes("TARGET_NOT_IN_ALLOWLIST"));

  // Case B: Spender not in allowlist
  const unapprovedSpender = "0x8888888888888888888888888888888888888888";
  const approveData = SELECTORS.ERC20_APPROVE + padAddress(unapprovedSpender) + padUint256(500n);
  const resB = inspectCalldata({ to: TOKEN, data: approveData }, policy);
  assert.equal(resB.verdict, "BLOCK");
  assert.ok(resB.reasons.includes("SPENDER_NOT_IN_ALLOWLIST"));

  // Case C: Recipient not in allowlist
  const unapprovedRecipient = "0x7777777777777777777777777777777777777777";
  const transferData = SELECTORS.ERC20_TRANSFER + padAddress(unapprovedRecipient) + padUint256(500n);
  const resC = inspectCalldata({ to: TOKEN, data: transferData }, policy);
  assert.equal(resC.verdict, "BLOCK");
  assert.ok(resC.reasons.includes("RECIPIENT_NOT_IN_ALLOWLIST"));

  // Case D: Exceeds maxTransferAmount policy limit
  const overLimitTransfer = SELECTORS.ERC20_TRANSFER + padAddress(RECIPIENT) + padUint256(2000000n);
  const resD = inspectCalldata({ to: TOKEN, data: overLimitTransfer }, policy);
  assert.equal(resD.verdict, "BLOCK");
  assert.ok(resD.reasons.includes("TRANSFER_EXCEEDS_POLICY_MAX"));
});

test("7. unknown selector returns advisory REVIEW, never silently treated as safe", () => {
  const unknownCalldata = "0x12345678" + padAddress(RECIPIENT) + padUint256(100n);
  const res = inspectCalldata({ to: TOKEN, data: unknownCalldata });

  assert.equal(res.verdict, "REVIEW");
  assert.equal(res.riskLevel, "MEDIUM");
  assert.equal(res.operation, "UNKNOWN_OPERATION");
  assert.match(res.reasons[0], /Unrecognized or unsupported function selector/);
});

test("8. missing transaction fields and malformed input objects fail closed with BLOCK", () => {
  assert.equal(inspectCalldata(null).verdict, "BLOCK");
  assert.equal(inspectCalldata(undefined).verdict, "BLOCK");
  assert.equal(inspectCalldata("0x123").verdict, "BLOCK");
  assert.equal(inspectCalldata([]).verdict, "BLOCK");
  assert.equal(inspectCalldata({}).verdict, "BLOCK"); // missing 'to'
});

test("9. native ETH transfer with empty calldata evaluates cleanly", () => {
  const ethTransfer = {
    to: RECIPIENT,
    value: "1000000000000000000", // 1 ETH
    data: "0x"
  };
  const res = inspectCalldata(ethTransfer);

  assert.equal(res.verdict, "PASS");
  assert.equal(res.operation, "NATIVE_TRANSFER");
  assert.equal(res.details.nativeValue, "1000000000000000000");
});
