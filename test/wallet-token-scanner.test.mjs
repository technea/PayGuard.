import test from "node:test";
import assert from "node:assert/strict";
import {
  scanBaseWalletTokens,
  checkTokenImpersonation,
  OFFICIAL_BASE_TOKENS
} from "../src/wallet-token-scanner.mjs";
import { clearTokenCache } from "../src/token-security.mjs";

test("checkTokenImpersonation correctly identifies official canonical Base tokens", () => {
  const result = checkTokenImpersonation(
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "USDC",
    "USD Coin"
  );
  assert.equal(result.isImpersonation, false);
  assert.equal(result.isVerifiedOfficial, true);
  assert.equal(result.officialAsset.symbol, "USDC");
});

test("checkTokenImpersonation detects lookalike asset with differing contract address", () => {
  const fakeContract = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
  const result = checkTokenImpersonation(fakeContract, "USDC", "USD Coin");
  assert.equal(result.isImpersonation, true);
  assert.equal(result.isVerifiedOfficial, false);
  assert.ok(result.message.includes("Possible token impersonation"));
  assert.ok(result.message.includes("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"));
});

test("checkTokenImpersonation returns null for unindexed non-conflicting symbols", () => {
  const result = checkTokenImpersonation(
    "0x1234567890123456789012345678901234567890",
    "RANDOM_COIN",
    "Random Coin"
  );
  assert.equal(result, null);
});

test("scanBaseWalletTokens rejects malformed or invalid wallet addresses fail-closed", async () => {
  const result = await scanBaseWalletTokens({ walletAddress: "0xinvalid" });
  assert.equal(result.status, "ERROR");
  assert.ok(result.error.includes("Invalid wallet address"));
  assert.equal(result.tokens.length, 0);
  assert.equal(result.summary.totalTokensScanned, 0);
});

test("scanBaseWalletTokens handles mock Blockscout responses and provider timeouts gracefully", async () => {
  clearTokenCache();
  const mockFetch = async (url) => {
    if (url.includes("blockscout.com")) {
      return {
        status: 403,
        ok: false,
        text: async () => "<!DOCTYPE html>Cloudflare Block",
        json: async () => ({})
      };
    }
    if (url.includes("gopluslabs.io")) {
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          code: 1,
          result: {
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": {
              is_honeypot: "0",
              buy_tax: "0",
              sell_tax: "0",
              is_open_source: 1,
              is_proxy: 1,
              token_name: "USD Coin",
              token_symbol: "USDC"
            }
          }
        }),
        json: async () => ({})
      };
    }
    if (url.includes("mainnet.base.org")) {
      return {
        ok: true,
        status: 200,
        text: async () => "",
        json: async () => ({
          jsonrpc: "2.0",
          id: 1,
          result: "0x0000000000000000000000000000000000000000000000000000000005f5e100" // 100 USDC
        })
      };
    }
    throw new Error(`Unexpected mock URL: ${url}`);
  };

  const scan = await scanBaseWalletTokens(
    { walletAddress: "0x20556F0cfA3f93F0206faeb5452d2745e1423469" },
    { fetchImpl: mockFetch }
  );

  assert.equal(scan.status, "SUCCESS");
  assert.equal(scan.walletAddress, "0x20556f0cfa3f93f0206faeb5452d2745e1423469");
  assert.ok(scan.tokens.length >= 7);
  const usdcToken = scan.tokens.find(t => t.symbol === "USDC");
  assert.ok(usdcToken);
  assert.equal(usdcToken.securityStatus, "NO KNOWN ISSUES FOUND");
  assert.equal(usdcToken.isVerifiedOfficial, true);
  assert.equal(usdcToken.isImpersonation, false);
});

test("scanBaseWalletTokens flags impersonating custom token as HIGH RISK", async () => {
  clearTokenCache();
  const fakeUsdcAddress = "0x9999999999999999999999999999999999999999";
  const mockFetch = async (url) => {
    if (url.includes("blockscout.com")) {
      return { status: 403, ok: false, text: async () => "", json: async () => ({}) };
    }
    if (url.includes("gopluslabs.io")) {
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          code: 1,
          result: {
            [fakeUsdcAddress]: {
              is_honeypot: "0",
              buy_tax: "0",
              sell_tax: "0",
              is_open_source: 1,
              token_name: "USD Coin Impersonator",
              token_symbol: "USDC"
            }
          }
        }),
        json: async () => ({})
      };
    }
    if (url.includes("mainnet.base.org")) {
      return {
        ok: true,
        status: 200,
        text: async () => "",
        json: async () => ({ jsonrpc: "2.0", id: 1, result: "0x0" })
      };
    }
    throw new Error(`Unexpected mock URL: ${url}`);
  };

  const scan = await scanBaseWalletTokens(
    {
      walletAddress: "0x20556F0cfA3f93F0206faeb5452d2745e1423469",
      customTokenAddresses: [fakeUsdcAddress]
    },
    { fetchImpl: mockFetch }
  );

  assert.equal(scan.status, "SUCCESS");
  const fakeToken = scan.tokens.find(t => t.contractAddress === fakeUsdcAddress);
  assert.ok(fakeToken);
  assert.equal(fakeToken.symbol, "USDC");
  assert.equal(fakeToken.isImpersonation, true);
  assert.equal(fakeToken.securityStatus, "HIGH RISK");
  assert.ok(fakeToken.detectedIndicators.some(i => i.type === "IMPERSONATION"));
});
