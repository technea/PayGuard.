import test from "node:test";
import assert from "node:assert/strict";
import {
  createBaseSmartWalletClient,
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_CHAIN_ID_HEX,
  BASE_MAINNET_CHAIN_ID
} from "../src/smart-wallet.mjs";
import { SELECTORS, UINT256_MAX } from "../src/calldata-inspector.mjs";

const TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"; // Base USDC
const SPENDER = "0x111111125421ca6dc452d289314280a0f8842a65"; // 1inch router
const RECIPIENT = "0x2222222222222222222222222222222222222222";

function padAddress(addr) {
  return addr.toLowerCase().replace("0x", "").padStart(64, "0");
}

function padUint256(val) {
  return BigInt(val).toString(16).padStart(64, "0");
}

test("Base Smart Wallet SDK exports and constants are correct", () => {
  assert.equal(BASE_MAINNET_CHAIN_ID, 8453);
  assert.equal(BASE_SEPOLIA_CHAIN_ID, 84532);
  assert.equal(BASE_SEPOLIA_CHAIN_ID_HEX, "0x14a34");
  assert.equal(typeof createBaseSmartWalletClient, "function");
});

test("createBaseSmartWalletClient configures preference and handles non-browser environment gracefully", () => {
  const client = createBaseSmartWalletClient({
    appName: "Test PayGuard Agent",
    preference: "smartWalletOnly"
  });

  assert.equal(client.appName, "Test PayGuard Agent");
  assert.equal(client.preference, "smartWalletOnly");
  assert.equal(typeof client.connect, "function");
  assert.equal(typeof client.switchChain, "function");
  assert.equal(typeof client.disconnect, "function");
  assert.equal(typeof client.inspectCandidate, "function");
  assert.equal(typeof client.requestTransaction, "function");
});

test("connect() successfully extracts address and chainId from provider", async () => {
  const client = createBaseSmartWalletClient();

  const mockProvider = {
    async request({ method }) {
      if (method === "eth_requestAccounts") {
        return ["0x1234567890123456789012345678901234567890"];
      }
      if (method === "eth_chainId") {
        return "0x14a34";
      }
      throw new Error(`Unexpected method: ${method}`);
    }
  };

  const session = await client.connect(mockProvider);
  assert.equal(session.address, "0x1234567890123456789012345678901234567890");
  assert.equal(session.chainId, "0x14a34");
});

test("connect() handles user rejection (4001) properly without crashing", async () => {
  const client = createBaseSmartWalletClient();

  const mockRejectingProvider = {
    async request({ method }) {
      if (method === "eth_requestAccounts") {
        const error = new Error("User rejected the request.");
        error.code = 4001;
        throw error;
      }
      throw new Error("Unexpected call");
    }
  };

  await assert.rejects(
    async () => {
      await client.connect(mockRejectingProvider);
    },
    (err) => {
      assert.equal(err.code, 4001);
      assert.match(err.message, /rejected/i);
      return true;
    }
  );
});

test("connect() rejects when provider returns empty accounts array", async () => {
  const client = createBaseSmartWalletClient();

  const mockEmptyProvider = {
    async request({ method }) {
      if (method === "eth_requestAccounts") {
        return [];
      }
      return "0x1";
    }
  };

  await assert.rejects(
    async () => {
      await client.connect(mockEmptyProvider);
    },
    /No accounts returned/
  );
});

test("switchChain() requests wallet_switchEthereumChain for Base Sepolia", async () => {
  const client = createBaseSmartWalletClient();
  const calls = [];

  const mockSwitchProvider = {
    async request({ method, params }) {
      calls.push({ method, params });
      return null;
    }
  };

  await client.switchChain(BASE_SEPOLIA_CHAIN_ID_HEX, mockSwitchProvider);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "wallet_switchEthereumChain");
  assert.deepEqual(calls[0].params, [{ chainId: "0x14a34" }]);
});

test("switchChain() falls back to wallet_addEthereumChain if chain is not yet registered (code 4902)", async () => {
  const client = createBaseSmartWalletClient();
  const calls = [];

  const mockProviderWithAdd = {
    async request({ method, params }) {
      calls.push({ method, params });
      if (method === "wallet_switchEthereumChain") {
        const err = new Error("Chain not added");
        err.code = 4902;
        throw err;
      }
      if (method === "wallet_addEthereumChain") {
        return null;
      }
      throw new Error("Unexpected method");
    }
  };

  await client.switchChain(BASE_SEPOLIA_CHAIN_ID, mockProviderWithAdd);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].method, "wallet_switchEthereumChain");
  assert.equal(calls[1].method, "wallet_addEthereumChain");
  assert.equal(calls[1].params[0].chainId, "0x14a34");
  assert.equal(calls[1].params[0].chainName, "Base Sepolia");
});

test("disconnect() invokes provider disconnect if available", async () => {
  const client = createBaseSmartWalletClient();
  let disconnected = false;

  const mockProvider = {
    async disconnect() {
      disconnected = true;
    }
  };

  await client.disconnect(mockProvider);
  assert.equal(disconnected, true);
});

test("Browser environment with localStorage initializes official createCoinbaseWalletSDK", () => {
  const originalLocalStorage = globalThis.localStorage;
  globalThis.localStorage = {
    getItem: () => null,
    setItem: () => {},
    removeItem: () => {}
  };

  try {
    const client = createBaseSmartWalletClient({
      appName: "Browser Test App",
      preference: "smartWalletOnly"
    });

    assert.ok(client.sdk, "SDK instance should be initialized when storage exists");
    assert.ok(client.provider, "Provider instance should be created");
    assert.equal(typeof client.provider.request, "function");
  } finally {
    globalThis.localStorage = originalLocalStorage;
  }
});

// -------------------------------------------------------------
// Pre-Signing Inspection & Transaction Authorization Tests
// -------------------------------------------------------------

test("Pre-signing flow: safe transaction candidate evaluates to PASS and triggers wallet eth_sendTransaction", async () => {
  const client = createBaseSmartWalletClient();
  let ethSendTxCalled = false;

  const transferCalldata = SELECTORS.ERC20_TRANSFER + padAddress(RECIPIENT) + padUint256(1000000n);
  const txCandidate = {
    to: TOKEN,
    data: transferCalldata
  };

  const mockProvider = {
    async request({ method, params }) {
      if (method === "eth_sendTransaction") {
        ethSendTxCalled = true;
        assert.deepEqual(params[0], txCandidate);
        return "0xMOCK_TRANSACTION_HASH_123";
      }
      throw new Error(`Unexpected call: ${method}`);
    }
  };

  const res = await client.requestTransaction(txCandidate, { provider: mockProvider });

  assert.equal(res.aborted, false);
  assert.equal(res.verdict, "PASS");
  assert.equal(res.txHash, "0xMOCK_TRANSACTION_HASH_123");
  assert.equal(ethSendTxCalled, true);
});

test("Pre-signing flow: unlimited ERC-20 approval triggers REVIEW and aborts before wallet request", async () => {
  const client = createBaseSmartWalletClient();
  let ethSendTxCalled = false;

  const approveCalldata = SELECTORS.ERC20_APPROVE + padAddress(SPENDER) + padUint256(UINT256_MAX);
  const txCandidate = {
    to: TOKEN,
    data: approveCalldata
  };

  const mockProvider = {
    async request({ method }) {
      if (method === "eth_sendTransaction") {
        ethSendTxCalled = true;
        return "0xSHOULD_NOT_BE_CALLED";
      }
      throw new Error(`Unexpected call: ${method}`);
    }
  };

  const res = await client.requestTransaction(txCandidate, { provider: mockProvider });

  assert.equal(res.aborted, true);
  assert.equal(res.verdict, "REVIEW");
  assert.equal(res.riskLevel, "MEDIUM");
  assert.ok(res.reasons.includes("UNLIMITED_ALLOWANCE_UINT256_MAX"));
  assert.equal(res.txHash, null);
  assert.equal(ethSendTxCalled, false, "Wallet eth_sendTransaction MUST NOT be invoked when verdict is REVIEW");
});

test("Pre-signing flow: unapproved spender triggers BLOCK and aborts before wallet request", async () => {
  const client = createBaseSmartWalletClient();
  let ethSendTxCalled = false;

  const UNAPPROVED_SPENDER = "0x9999999999999999999999999999999999999999";
  const approveCalldata = SELECTORS.ERC20_APPROVE + padAddress(UNAPPROVED_SPENDER) + padUint256(1000n);
  const txCandidate = {
    to: TOKEN,
    data: approveCalldata
  };

  const policy = {
    allowedSpenders: [SPENDER] // only SPENDER is allowed
  };

  const mockProvider = {
    async request() {
      ethSendTxCalled = true;
      return "0xSHOULD_NOT_BE_CALLED";
    }
  };

  const res = await client.requestTransaction(txCandidate, { policy, provider: mockProvider });

  assert.equal(res.aborted, true);
  assert.equal(res.verdict, "BLOCK");
  assert.ok(res.reasons.includes("SPENDER_NOT_IN_ALLOWLIST"));
  assert.equal(ethSendTxCalled, false, "Wallet eth_sendTransaction MUST NOT be invoked on policy BLOCK");
});

test("Pre-signing flow: unknown function selector triggers REVIEW and aborts before wallet request", async () => {
  const client = createBaseSmartWalletClient();
  let ethSendTxCalled = false;

  const unknownCalldata = "0xdeadbeef" + padAddress(RECIPIENT) + padUint256(100n);
  const txCandidate = {
    to: TOKEN,
    data: unknownCalldata
  };

  const mockProvider = {
    async request() {
      ethSendTxCalled = true;
      return "0xSHOULD_NOT_BE_CALLED";
    }
  };

  const res = await client.requestTransaction(txCandidate, { provider: mockProvider });

  assert.equal(res.aborted, true);
  assert.equal(res.verdict, "REVIEW");
  assert.equal(res.operation, "UNKNOWN_OPERATION");
  assert.equal(ethSendTxCalled, false);
});

test("Pre-signing flow: malformed calldata triggers BLOCK and aborts before wallet request", async () => {
  const client = createBaseSmartWalletClient();
  let ethSendTxCalled = false;

  const txCandidate = {
    to: TOKEN,
    data: "0xINVALID_HEX_DATA"
  };

  const mockProvider = {
    async request() {
      ethSendTxCalled = true;
      return "0xSHOULD_NOT_BE_CALLED";
    }
  };

  const res = await client.requestTransaction(txCandidate, { provider: mockProvider });

  assert.equal(res.aborted, true);
  assert.equal(res.verdict, "BLOCK");
  assert.equal(res.operation, "MALFORMED_CALLDATA");
  assert.equal(ethSendTxCalled, false);
});

test("Pre-signing flow: wallet rejection (code 4001) is handled gracefully after inspection PASS", async () => {
  const client = createBaseSmartWalletClient();

  const transferCalldata = SELECTORS.ERC20_TRANSFER + padAddress(RECIPIENT) + padUint256(1000000n);
  const txCandidate = {
    to: TOKEN,
    data: transferCalldata
  };

  const mockProvider = {
    async request({ method }) {
      if (method === "eth_sendTransaction") {
        const error = new Error("User denied transaction signature.");
        error.code = 4001;
        throw error;
      }
      throw new Error("Unexpected method");
    }
  };

  const res = await client.requestTransaction(txCandidate, { provider: mockProvider });

  assert.equal(res.aborted, true);
  assert.equal(res.verdict, "REJECTED_BY_USER");
  assert.equal(res.errorCode, 4001);
  assert.match(res.reasons[0], /User denied/i);
  assert.equal(res.txHash, null);
});
