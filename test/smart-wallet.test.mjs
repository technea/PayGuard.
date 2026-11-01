import test from "node:test";
import assert from "node:assert/strict";
import {
  createBaseSmartWalletClient,
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_CHAIN_ID_HEX,
  BASE_MAINNET_CHAIN_ID
} from "../src/smart-wallet.mjs";

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
