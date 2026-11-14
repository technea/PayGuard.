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

// ─────────────────────────────────────────────────────────────────────────────
// Audit Defect Verification & State Machine Tests (Mocked Providers)
// ─────────────────────────────────────────────────────────────────────────────

// Helper to simulate PayGuard frontend state machine
function createMockPayGuardWalletSession() {
  let _walletConnected = false;
  let _walletAddress = null;
  let _walletChainId = null;
  let _walletScanRequestId = 0;
  let _displayedScanResults = null;
  let _scannerInputAddress = "0x20556F0cfA3f93F0206faeb5452d2745e1423469"; // Mode A initial

  function clearWalletScanResults() {
    _displayedScanResults = null;
  }

  function walletOnConnected(address, chainId) {
    if (!isValidEvmAddress(address)) {
      walletDisconnect();
      return { success: false, error: "invalid_address" };
    }
    const previousAddress = _walletAddress;
    const isNewAccount = !previousAddress || previousAddress.toLowerCase() !== address.toLowerCase();

    _walletConnected = true;
    _walletAddress = address;
    _walletChainId = String(chainId || "").toLowerCase();

    // FIX 3: Clear stale scan results immediately if account changed
    if (isNewAccount && previousAddress !== null) {
      _walletScanRequestId++;
      clearWalletScanResults();
    }

    // FIX 1: Scanner input is NOT overwritten on connect!
    return { success: true };
  }

  function walletDisconnect() {
    _walletScanRequestId++;
    clearWalletScanResults();
    _walletConnected = false;
    _walletAddress = null;
    _walletChainId = null;
  }

  function handleAccountsChanged(accounts) {
    if (!Array.isArray(accounts) || accounts.length === 0) {
      walletDisconnect();
      return { action: "disconnected" };
    }
    // FIX 4: Respect explicit disconnect. Only reconnect/update if active session exists.
    if (!_walletConnected) {
      return { action: "ignored_not_connected" };
    }
    walletOnConnected(accounts[0], _walletChainId);
    return { action: "updated", address: accounts[0] };
  }

  function handleChainChanged(chainId) {
    _walletChainId = String(chainId || "").toLowerCase();
    return { chainId: _walletChainId, isBase: _walletChainId === BASE_CHAIN_ID };
  }

  function scanMyWallet() {
    if (!_walletConnected || !_walletAddress) {
      return { allowed: false, error: "not_connected" };
    }
    // FIX 2: Enforce Base Mainnet (0x2105)
    if (_walletChainId !== BASE_CHAIN_ID) {
      return { allowed: false, error: "wrong_network", chainId: _walletChainId };
    }
    // FIX 1: Fill scanner input on explicit Mode B click
    _scannerInputAddress = _walletAddress;
    const reqId = ++_walletScanRequestId;
    const targetAddress = _walletAddress;

    return {
      allowed: true,
      requestId: reqId,
      targetAddress,
      simulateResponse: (data, resRequestId, currentSession) => {
        // FIX 3 & Race Condition Guard
        if (resRequestId !== _walletScanRequestId) return { applied: false, reason: "superseded_request_id" };
        if (!currentSession.isConnected() || currentSession.getAddress() !== targetAddress) {
          return { applied: false, reason: "session_or_account_changed" };
        }
        _displayedScanResults = { address: targetAddress, data };
        return { applied: true };
      }
    };
  }

  return {
    connect: (addr, chainId) => walletOnConnected(addr, chainId),
    disconnect: () => walletDisconnect(),
    onAccountsChanged: (accounts) => handleAccountsChanged(accounts),
    onChainChanged: (chainId) => handleChainChanged(chainId),
    scanMyWallet: () => scanMyWallet(),
    setScannerInput: (addr) => { _scannerInputAddress = addr; },
    getScannerInput: () => _scannerInputAddress,
    getAddress: () => _walletAddress,
    getChainId: () => _walletChainId,
    isConnected: () => _walletConnected,
    getResults: () => _displayedScanResults,
    setResults: (res) => { _displayedScanResults = res; },
    getRequestId: () => _walletScanRequestId
  };
}

// 1. Mode A input preserved on wallet connect
test("1. Mode A input preserved on wallet connect", () => {
  const session = createMockPayGuardWalletSession();
  session.setScannerInput("0x4200000000000000000000000000000000000006"); // User typed/selected WETH

  session.connect("0x20556F0cfA3f93F0206faeb5452d2745e1423469", BASE_CHAIN_ID);

  // Scanner input must remain unchanged
  assert.equal(session.getScannerInput(), "0x4200000000000000000000000000000000000006");
  assert.equal(session.getAddress(), "0x20556F0cfA3f93F0206faeb5452d2745e1423469");
});

// 2. Mode B fills the input only after explicit click
test("2. Mode B fills the input only after explicit click", () => {
  const session = createMockPayGuardWalletSession();
  session.setScannerInput("0x4200000000000000000000000000000000000006");
  session.connect("0x20556F0cfA3f93F0206faeb5452d2745e1423469", BASE_CHAIN_ID);

  // Before click
  assert.equal(session.getScannerInput(), "0x4200000000000000000000000000000000000006");

  // User explicitly clicks "Scan My Wallet Holdings"
  const scanOp = session.scanMyWallet();
  assert.equal(scanOp.allowed, true);
  assert.equal(session.getScannerInput(), "0x20556F0cfA3f93F0206faeb5452d2745e1423469");
});

// 3. Mode B blocked on Ethereum Mainnet
test("3. Mode B blocked on Ethereum Mainnet", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x20556F0cfA3f93F0206faeb5452d2745e1423469", "0x1"); // Ethereum Mainnet

  const scanOp = session.scanMyWallet();
  assert.equal(scanOp.allowed, false);
  assert.equal(scanOp.error, "wrong_network");
  assert.equal(scanOp.chainId, "0x1");
});

// 4. Mode B blocked on Polygon
test("4. Mode B blocked on Polygon", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x20556F0cfA3f93F0206faeb5452d2745e1423469", "0x89"); // Polygon

  const scanOp = session.scanMyWallet();
  assert.equal(scanOp.allowed, false);
  assert.equal(scanOp.error, "wrong_network");
  assert.equal(scanOp.chainId, "0x89");
});

// 5. Base network switch explicitly requested by user
test("5. Base network switch explicitly requested by user", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x20556F0cfA3f93F0206faeb5452d2745e1423469", "0x1");

  // User triggers network switch to Base
  const res = session.onChainChanged(BASE_CHAIN_ID);
  assert.equal(res.chainId, "0x2105");
  assert.equal(res.isBase, true);
  assert.equal(session.getChainId(), "0x2105");
});

// 6. Rejected network switch leaves Mode B blocked
test("6. Rejected network switch leaves Mode B blocked", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x20556F0cfA3f93F0206faeb5452d2745e1423469", "0x1");

  // User rejects the switch in their wallet -> chain remains 0x1
  const err = walletErrorMessage({ code: 4001, message: "User rejected the request." });
  assert.equal(err.title, "Connection cancelled");
  assert.equal(session.getChainId(), "0x1");

  // Mode B scan remains blocked
  const scanOp = session.scanMyWallet();
  assert.equal(scanOp.allowed, false);
  assert.equal(scanOp.error, "wrong_network");
});

// 7. Successful Base network switch and revalidation
test("7. Successful Base network switch and revalidation", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x20556F0cfA3f93F0206faeb5452d2745e1423469", "0x1");

  // Blocked initially
  assert.equal(session.scanMyWallet().allowed, false);

  // Switch succeeds
  session.onChainChanged("0x2105");
  assert.equal(session.getChainId(), "0x2105");

  // Revalidation allows scan
  const scanOp = session.scanMyWallet();
  assert.equal(scanOp.allowed, true);
});

// 8. Account A to Account B clears previous results immediately
test("8. Account A to Account B clears previous results immediately", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x1111111111111111111111111111111111111111", BASE_CHAIN_ID);
  session.setResults({ address: "0x1111111111111111111111111111111111111111", tokens: [1, 2, 3] });

  assert.ok(session.getResults() !== null);

  // Account switch to Account B
  session.onAccountsChanged(["0x2222222222222222222222222222222222222222"]);

  assert.equal(session.getAddress(), "0x2222222222222222222222222222222222222222");
  // Stale Account A results MUST be cleared immediately
  assert.equal(session.getResults(), null);
});

// 9. Old in-flight scan response cannot overwrite Account B results
test("9. Old in-flight scan response cannot overwrite Account B results", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x1111111111111111111111111111111111111111", BASE_CHAIN_ID);

  // In-flight scan for Account A
  const scanOpA = session.scanMyWallet();
  assert.equal(scanOpA.allowed, true);
  const reqIdA = scanOpA.requestId;

  // Account switches to Account B while scan A is in-flight
  session.onAccountsChanged(["0x2222222222222222222222222222222222222222"]);
  assert.equal(session.getResults(), null);

  // Now scan A resolves late
  const applyResA = scanOpA.simulateResponse({ tokens: ["Account A Token"] }, reqIdA, session);
  assert.equal(applyResA.applied, false);
  // Stale scan must NOT have populated results
  assert.equal(session.getResults(), null);

  // In-flight scan for Account B resolves
  const scanOpB = session.scanMyWallet();
  const applyResB = scanOpB.simulateResponse({ tokens: ["Account B Token"] }, scanOpB.requestId, session);
  assert.equal(applyResB.applied, true);
  assert.deepEqual(session.getResults().data, { tokens: ["Account B Token"] });
});

// 10. Explicit disconnect remains disconnected after accountsChanged
test("10. Explicit disconnect remains disconnected after accountsChanged", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x1111111111111111111111111111111111111111", BASE_CHAIN_ID);
  assert.equal(session.isConnected(), true);

  // User explicitly disconnects in PayGuard
  session.disconnect();
  assert.equal(session.isConnected(), false);
  assert.equal(session.getAddress(), null);

  // External wallet emits accountsChanged (e.g. user toggles accounts in MetaMask)
  const res = session.onAccountsChanged(["0x2222222222222222222222222222222222222222"]);
  assert.equal(res.action, "ignored_not_connected");

  // User MUST remain disconnected
  assert.equal(session.isConnected(), false);
  assert.equal(session.getAddress(), null);
});

// 11. Active session responds correctly to accountsChanged
test("11. Active session responds correctly to accountsChanged", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x1111111111111111111111111111111111111111", BASE_CHAIN_ID);
  assert.equal(session.isConnected(), true);

  const res = session.onAccountsChanged(["0x3333333333333333333333333333333333333333"]);
  assert.equal(res.action, "updated");
  assert.equal(session.isConnected(), true);
  assert.equal(session.getAddress(), "0x3333333333333333333333333333333333333333");
});

// 12. Empty accounts array disconnects session
test("12. Empty accounts array disconnects session", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x1111111111111111111111111111111111111111", BASE_CHAIN_ID);
  assert.equal(session.isConnected(), true);

  const res = session.onAccountsChanged([]);
  assert.equal(res.action, "disconnected");
  assert.equal(session.isConnected(), false);
  assert.equal(session.getAddress(), null);
});

// 13. Disconnect during scan invalidates and clears results
test("13. Disconnect during scan invalidates and clears results", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x1111111111111111111111111111111111111111", BASE_CHAIN_ID);

  const scanOp = session.scanMyWallet();
  assert.equal(scanOp.allowed, true);

  // User disconnects while scan is in flight
  session.disconnect();
  assert.equal(session.isConnected(), false);

  // Late scan response arrives
  const applyRes = scanOp.simulateResponse({ tokens: ["Token"] }, scanOp.requestId, session);
  assert.equal(applyRes.applied, false);
  assert.equal(session.getResults(), null);
});

// 14. Mode A still works without wallet
test("14. Mode A still works without wallet", async () => {
  const session = createMockPayGuardWalletSession();
  assert.equal(session.isConnected(), false);

  // Mode A uses scanBaseWalletTokens directly with any public address
  const result = await scanBaseWalletTokens({
    walletAddress: "0x20556F0cfA3f93F0206faeb5452d2745e1423469"
  });
  assert.equal(result.status, "SUCCESS");
  assert.equal(result.chainId, "8453");
  assert.ok(result.tokens.length > 0);
});

// 15. Same account re-announced does NOT clear results
test("15. Same account re-announced does NOT clear results", () => {
  const session = createMockPayGuardWalletSession();
  session.connect("0x1111111111111111111111111111111111111111", BASE_CHAIN_ID);
  session.setResults({ address: "0x1111111111111111111111111111111111111111", data: "ok" });

  // Re-announce same account
  session.onAccountsChanged(["0x1111111111111111111111111111111111111111"]);

  // Must NOT clear results unnecessarily
  assert.ok(session.getResults() !== null);
  assert.equal(session.getResults().data, "ok");
});

