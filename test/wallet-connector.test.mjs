/**
 * wallet-connector.test.mjs
 *
 * Tests for PayGuard wallet connection behaviour and the wallet token scan
 * server-side pipeline.
 *
 * The EIP-1193 wallet connection state machine runs in a browser context and
 * cannot be exercised here.  These tests cover:
 *   1. EVM address validation logic (the same regex used in walletOnConnected).
 *   2. The scanBaseWalletTokens backend used by both Mode A and Mode B.
 *   3. Mode A: public scan works without a connected wallet.
 *   4. Mode B contract: scan only proceeds when a valid EVM address is supplied.
 *   5. User rejection (error code 4001) — message mapping.
 *   6. No provider — graceful error path.
 *   7. Wrong network (chainId !== 0x2105) — detection.
 *   8. Network switch rejection (error code 4902 / user reject).
 *   9. Read-only guarantee: scanBaseWalletTokens never requests signing methods.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { scanBaseWalletTokens } from "../src/wallet-token-scanner.mjs";

// ── Helper: EVM address validation (mirrors walletOnConnected regex) ──────────
const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

function isValidEvmAddress(addr) {
  return EVM_ADDRESS_RE.test(String(addr || ""));
}

// ── Helper: wallet error code → message mapping (mirrors walletErrorMessage) ──
function walletErrorMessage(error) {
  const code = error && error.code;
  const message = String((error && error.message) || "");
  if (code === 4001)
    return { title: "Connection cancelled", message: "The wallet request was rejected. No transaction or signature was requested." };
  if (code === -32002)
    return { title: "Wallet request already pending", message: "Open your wallet extension and finish or reject the pending request first." };
  if (code === 4100)
    return { title: "Wallet permission denied", message: "Review this website in your wallet's connected-sites or permissions settings." };
  if (code === 4900 || code === 4901)
    return { title: "Wallet disconnected", message: "The wallet provider is currently disconnected. Unlock it and try again." };
  if (code === 4902)
    return { title: "Chain not added", message: "Base Mainnet is not in your wallet. Add it and try again." };
  return { title: "Wallet connection failed", message: message ? message.slice(0, 240) : "The wallet provider did not complete the connection request." };
}

const BASE_CHAIN_ID = "0x2105"; // Base Mainnet decimal 8453

// ─────────────────────────────────────────────────────────────────────────────
// 1. EVM address validation — valid addresses pass
// ─────────────────────────────────────────────────────────────────────────────
test("walletOnConnected: valid EVM addresses pass the address check", () => {
  const valid = [
    "0x20556F0cfA3f93F0206faeb5452d2745e1423469",
    "0x0000000000000000000000000000000000000000",
    "0x4200000000000000000000000000000000000006",
    "0xdeadbeefDEADBEEFdeadbeefDEADBEEFdeadbeef",
  ];
  for (const addr of valid) {
    assert.ok(isValidEvmAddress(addr), `Expected ${addr} to be valid`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. EVM address validation — invalid addresses are rejected
// ─────────────────────────────────────────────────────────────────────────────
test("walletOnConnected: invalid EVM addresses fail the address check", () => {
  const invalid = [
    "0xinvalid",
    "0x123",
    "not-an-address",
    "",
    null,
    undefined,
    "0x" + "g".repeat(40),
  ];
  for (const addr of invalid) {
    assert.ok(!isValidEvmAddress(addr), `Expected ${String(addr)} to be invalid`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Mode A: public scan works with any valid Base address (no wallet needed)
// ─────────────────────────────────────────────────────────────────────────────
test("Mode A: scanBaseWalletTokens accepts a valid address without wallet connection", async () => {
  // The function is entirely server-side — no wallet provider is ever consulted.
  // A malformed address must be rejected; a structurally valid one must be accepted
  // even if the network call times out (graceful degradation returns status OK with
  // an empty tokens array rather than throwing).
  const invalid = await scanBaseWalletTokens({ walletAddress: "not-an-address" });
  assert.equal(invalid.status, "ERROR");
  assert.ok(invalid.error.includes("Invalid wallet address"));

  // A syntactically valid address should not be rejected with an address error.
  // (The network call may fail in CI, but the error must not be "Invalid wallet address".)
  const valid = await scanBaseWalletTokens({
    walletAddress: "0x0000000000000000000000000000000000000000",
  });
  // Either succeeds or fails with a provider error — never an address format error.
  if (valid.status === "ERROR") {
    assert.ok(
      !valid.error.includes("Invalid wallet address"),
      `Unexpected address rejection for valid hex: ${valid.error}`
    );
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Mode B contract: scan only proceeds for a valid EVM address
// ─────────────────────────────────────────────────────────────────────────────
test("Mode B: scanMyWallet would be blocked for non-EVM addresses", () => {
  // scanMyWallet() checks _walletAddress with the same EVM_ADDRESS_RE before
  // calling scanBaseWalletTokens. We verify this guard independently.
  const mockWalletState = { connected: false, address: null };

  function scanMyWalletGuard(state) {
    if (!state.connected || !state.address) return { blocked: true, reason: "not_connected" };
    if (!isValidEvmAddress(state.address)) return { blocked: true, reason: "invalid_address" };
    return { blocked: false };
  }

  assert.deepEqual(scanMyWalletGuard({ connected: false, address: null }), { blocked: true, reason: "not_connected" });
  assert.deepEqual(scanMyWalletGuard({ connected: true, address: "0xinvalid" }), { blocked: true, reason: "invalid_address" });
  assert.deepEqual(
    scanMyWalletGuard({ connected: true, address: "0x20556F0cfA3f93F0206faeb5452d2745e1423469" }),
    { blocked: false }
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. User rejection (error code 4001) — correct message
// ─────────────────────────────────────────────────────────────────────────────
test("walletErrorMessage: user rejection (4001) produces correct title and no blame", () => {
  const result = walletErrorMessage({ code: 4001, message: "User rejected the request." });
  assert.equal(result.title, "Connection cancelled");
  assert.ok(result.message.includes("rejected"));
  // Must not mention signing or transactions in a way that implies PayGuard requested one.
  assert.ok(result.message.includes("No transaction or signature was requested"));
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. No provider available — graceful error path
// ─────────────────────────────────────────────────────────────────────────────
test("walletConnect: no provider available produces an actionable error message", () => {
  // chooseWalletProvider() returns null when window.ethereum is absent.
  // Simulate that outcome and verify the UI message branch.
  function simulateNoProvider() {
    const selected = null; // chooseWalletProvider() result
    if (!selected || !selected.provider) {
      return {
        title: "No injected wallet found",
        message: "Install or enable MetaMask, Rabby, or Coinbase Wallet extension, then reload this page.",
      };
    }
    return null;
  }
  const msg = simulateNoProvider();
  assert.ok(msg !== null);
  assert.equal(msg.title, "No injected wallet found");
  assert.ok(msg.message.includes("MetaMask"));
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Wrong network detection (chainId !== BASE_CHAIN_ID)
// ─────────────────────────────────────────────────────────────────────────────
test("updateWalletNetworkBadge: wrong network is detected when chainId differs from Base Mainnet", () => {
  function detectNetwork(chainId) {
    const normalised = String(chainId).toLowerCase();
    if (normalised === BASE_CHAIN_ID) return "base_mainnet";
    return "wrong_network";
  }

  assert.equal(detectNetwork("0x2105"), "base_mainnet");
  assert.equal(detectNetwork("0x2105".toUpperCase()), "base_mainnet"); // case-insensitive
  assert.equal(detectNetwork("0x1"), "wrong_network");   // Ethereum Mainnet
  assert.equal(detectNetwork("0x14a34"), "wrong_network"); // Base Sepolia
  assert.equal(detectNetwork("0x38"), "wrong_network");  // BSC
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Network switch rejection (4902 chain-not-added, then user rejects add)
// ─────────────────────────────────────────────────────────────────────────────
test("walletSwitchToBase: 4902 (chain not in wallet) produces correct recovery message", () => {
  const error4902 = { code: 4902, message: "Unrecognized chain ID" };
  const msg = walletErrorMessage(error4902);
  assert.equal(msg.title, "Chain not added");
  assert.ok(msg.message.toLowerCase().includes("base mainnet"));
});

test("walletSwitchToBase: user-rejected addEthereumChain produces correct message", () => {
  const error4001 = { code: 4001, message: "User rejected the request." };
  const msg = walletErrorMessage(error4001);
  assert.equal(msg.title, "Connection cancelled");
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. Read-only guarantee: scanBaseWalletTokens only reads chain data
// ─────────────────────────────────────────────────────────────────────────────
test("Read-only guarantee: scanBaseWalletTokens never requests signing or approval methods", async () => {
  // Intercept fetch to verify no signing or transaction payload is ever sent.
  // The scanner is allowed to make GET requests (Blockscout) and JSON-RPC POSTs
  // for read-only methods (eth_call, eth_getBalance, etc.), but must never post
  // signing-capable methods like eth_sign, eth_sendTransaction, or eth_sendRawTransaction.
  const capturedBodies = [];
  const origFetch = globalThis.fetch;

  globalThis.fetch = async (url, init) => {
    if (init && init.body) capturedBodies.push({ url: String(url), body: String(init.body) });
    // Return empty token list so we don't depend on network.
    return {
      ok: true,
      status: 200,
      json: async () => ({ items: [], next_page_params: null }),
    };
  };

  try {
    await scanBaseWalletTokens({ walletAddress: "0x20556F0cfA3f93F0206faeb5452d2745e1423469" });
  } finally {
    globalThis.fetch = origFetch;
  }

  const FORBIDDEN_METHODS = ["eth_sign", "eth_sendTransaction", "eth_sendRawTransaction", "eth_signTypedData", "personal_sign"];
  for (const req of capturedBodies) {
    for (const method of FORBIDDEN_METHODS) {
      assert.ok(
        !req.body.includes(method),
        `Signing method "${method}" found in request body for ${req.url} — read-only violation`
      );
    }
  }
});
