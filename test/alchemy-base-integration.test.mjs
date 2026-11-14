/**
 * PayGuard Alchemy Base Mainnet Integration Test Suite
 *
 * Verifies real Alchemy API connectivity against Base Mainnet (8453):
 * 1. Native ETH balance retrieval (real Alchemy Base endpoint)
 * 2. ERC-20 token discovery (real Alchemy Base endpoint)
 * 3. Wallets with multiple token holdings (vitalik.eth)
 * 4. Tokens outside canonical registry with live metadata retrieval
 * 5. Empty wallets (zero holdings handled cleanly)
 * 6. Invalid wallet addresses fail-closed
 * 7. Wrong network handling and validation
 * 8. API failures & rate limit handling (graceful fallback to Base RPC)
 * 9. Pagination via pageKey
 * 10. MCP tool get_token_balance
 * 11. MCP tool get_wallet_portfolio
 * 12. MCP tool scan_wallet_holdings
 * 13. MCP tool verify_wallet_scan
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  fetchNativeEthBalance,
  fetchAlchemyTokenBalances,
  fetchTokenMetadata,
  scanBaseWalletTokens,
  getWalletTokenBalance,
  getWalletPortfolio,
  verifyWalletScan,
  getAlchemyApiKey,
  BASE_CHAIN_ID
} from "../src/wallet-token-scanner.mjs";
import { plugin } from "../src/plugin.mjs";

const VITALIK_ETH = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const EMPTY_WALLET = "0x71C83e25b375bE27145789647C9A4c478B4598F1";
const SAMPLE_WALLET = "0x20556F0cfA3f93F0206faeb5452d2745e1423469";
const USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

const apiKey = getAlchemyApiKey();

test("1. Native ETH balance retrieval on Base Mainnet via Alchemy", async () => {
  assert.ok(apiKey, "ALCHEMY_API_KEY must be configured in .env");
  const eth = await fetchNativeEthBalance(VITALIK_ETH, { alchemyApiKey: apiKey });
  assert.equal(eth.symbol, "ETH");
  assert.equal(eth.decimals, 18);
  assert.ok(BigInt(eth.balanceWei) > 0n, "vitalik.eth should have non-zero ETH balance on Base");
  assert.ok(parseFloat(eth.balanceEth) > 0, "Formatted ETH should be > 0");
  assert.equal(eth.provider, "Alchemy Base Mainnet");
});

test("2. ERC-20 token discovery on Base Mainnet via Alchemy", async () => {
  const result = await fetchAlchemyTokenBalances(VITALIK_ETH, { alchemyApiKey: apiKey, maxPages: 1 });
  assert.equal(result.available, true);
  assert.ok(result.items.length > 0, "Should discover held tokens");
  const first = result.items[0];
  assert.ok(first.contractAddress.startsWith("0x"));
  assert.ok(first.tokenBalance.startsWith("0x"));
  assert.ok(BigInt(first.tokenBalance) > 0n, "Discovered balance must be non-zero");
});

test("3. Wallets with multiple token holdings discovery", async () => {
  const result = await fetchAlchemyTokenBalances(VITALIK_ETH, { alchemyApiKey: apiKey, maxPages: 2 });
  assert.ok(result.items.length >= 10, "vitalik.eth holds dozens of tokens on Base");
});

test("4. Discovers tokens outside the existing canonical registry", async () => {
  const result = await fetchAlchemyTokenBalances(VITALIK_ETH, { alchemyApiKey: apiKey, maxPages: 1 });
  const canonicalAddrs = new Set([
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    "0x4200000000000000000000000000000000000006",
    "0x50c5725949a6f0c72e6c4a641f24049a917db0cb",
    "0x2ae3f1ec7f1f5012cfeab0185bfc7aa3cf0dec22",
    "0x940181a94a35a4569e4529a3cdfb74e38fd98631",
    "0x532f27101965dd16442e59d40670faf5ebb142e4",
    "0x0578d8a44db98b23bf096a382e016e29a5ce0ffe"
  ]);

  const nonCanonical = result.items.filter(t => !canonicalAddrs.has(t.contractAddress.toLowerCase()));
  assert.ok(nonCanonical.length > 0, "Should discover arbitrary non-canonical community tokens held by wallet");

  // Verify metadata retrieval for a non-canonical token
  const sample = nonCanonical[0];
  const meta = await fetchTokenMetadata(sample.contractAddress, { alchemyApiKey: apiKey });
  assert.ok(typeof meta.symbol === "string");
  assert.ok(typeof meta.decimals === "number");
});

test("5. Empty wallet with zero holdings returns empty list cleanly", async () => {
  const result = await fetchAlchemyTokenBalances(EMPTY_WALLET, { alchemyApiKey: apiKey, maxPages: 1 });
  assert.equal(result.available, true);
  assert.equal(result.items.length, 0, "Fresh random wallet must have 0 non-zero token holdings");

  const portfolio = await getWalletPortfolio({ walletAddress: EMPTY_WALLET }, { alchemyApiKey: apiKey });
  assert.equal(portfolio.status, "SUCCESS");
  assert.equal(portfolio.nativeEth.balanceEth, "0");
});

test("6. Invalid wallet addresses fail closed", async () => {
  const badAddr = "0x123";
  const eth = await fetchNativeEthBalance(badAddr, { alchemyApiKey: apiKey });
  assert.ok(eth.error, "Invalid address must return error");

  const tokens = await fetchAlchemyTokenBalances(badAddr, { alchemyApiKey: apiKey });
  assert.equal(tokens.available, false);
  assert.ok(tokens.error);

  const scan = await scanBaseWalletTokens({ walletAddress: badAddr }, { alchemyApiKey: apiKey });
  assert.equal(scan.status, "ERROR");
  assert.equal(scan.scanCompletionStatus, "FAILED");
});

test("7. Wrong network handling and validation", async () => {
  const badChainScan = await scanBaseWalletTokens(
    { walletAddress: SAMPLE_WALLET },
    { rpcUrl: "https://sepolia.base.org", alchemyApiKey: false }
  );
  // Scan always targets Base Mainnet 8453
  assert.equal(badChainScan.chainId, BASE_CHAIN_ID);
});

test("8. API failures and rate limits fallback gracefully", async () => {
  const failingFetch = async (url) => {
    if (url.includes("alchemy.com")) {
      return { status: 429, ok: false, text: async () => "Rate limited", json: async () => ({}) };
    }
    if (url.includes("blockscout.com")) {
      return { status: 403, ok: false, text: async () => "Forbidden", json: async () => ({}) };
    }
    if (url.includes("mainnet.base.org")) {
      return {
        ok: true,
        status: 200,
        text: async () => "",
        json: async () => ({ jsonrpc: "2.0", id: 1, result: "0x0" })
      };
    }
    if (url.includes("gopluslabs.io")) {
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ code: 1, result: {} }),
        json: async () => ({})
      };
    }
    throw new Error(`Unexpected mock URL: ${url}`);
  };

  const scan = await scanBaseWalletTokens(
    { walletAddress: SAMPLE_WALLET },
    { fetchImpl: failingFetch, alchemyApiKey: "bad_key" }
  );
  assert.equal(scan.status, "SUCCESS");
  assert.equal(scan.scanCompletionStatus, "PARTIAL");
  assert.equal(scan.dataProvider, "Base RPC Registry + GoPlus Security");
  assert.ok(scan.tokens.length >= 7);
});

test("9. Pagination traversing pageKey correctly", async () => {
  const result = await fetchAlchemyTokenBalances(VITALIK_ETH, { alchemyApiKey: apiKey, maxPages: 2 });
  assert.ok(result.pageCount >= 2, "Should have requested at least 2 pages");
  assert.ok(result.totalDiscovered >= 80, "Should have discovered 80+ tokens across 2 pages");
});

test("10. MCP tool get_token_balance returns balances for ETH and ERC-20", async () => {
  const ethBalRes = await plugin.invokeTool("get_token_balance", {
    walletAddress: VITALIK_ETH,
    tokenAddress: "ETH"
  });
  assert.equal(ethBalRes.status, "SUCCESS");
  assert.equal(ethBalRes.symbol, "ETH");
  assert.ok(parseFloat(ethBalRes.balanceFormatted) > 0);

  const usdcBalRes = await plugin.invokeTool("get_token_balance", {
    walletAddress: VITALIK_ETH,
    tokenAddress: USDC_BASE
  });
  assert.equal(usdcBalRes.status, "SUCCESS");
  assert.equal(usdcBalRes.symbol, "USDC");
});

test("11. MCP tool get_wallet_portfolio returns complete asset breakdown", async () => {
  const portfolioRes = await plugin.invokeTool("get_wallet_portfolio", {
    walletAddress: VITALIK_ETH
  });
  assert.equal(portfolioRes.status, "SUCCESS");
  assert.ok(portfolioRes.tokens.length > 0);
  assert.ok(portfolioRes.nativeEth);
  assert.ok(parseFloat(portfolioRes.nativeEth.balanceEth) > 0);
});

test("12. MCP tool scan_wallet_holdings audits holdings with security screening", { timeout: 45000 }, async () => {
  const holdingsRes = await plugin.invokeTool("scan_wallet_holdings", {
    walletAddress: SAMPLE_WALLET
  });
  assert.equal(holdingsRes.status, "SUCCESS");
  assert.equal(holdingsRes.chainId, "8453");
  assert.ok(holdingsRes.nativeEth);
});

test("13. MCP tool verify_wallet_scan verifies scan validity and safety", async () => {
  const mockScan = {
    walletAddress: SAMPLE_WALLET,
    scanCompletionStatus: "COMPLETE",
    summary: { totalTokensScanned: 7, highRiskCount: 0, suspiciousCount: 0, cleanCount: 7, unverifiedCount: 0 },
    tokens: [
      {
        symbol: "USDC",
        contractAddress: USDC_BASE,
        securityStatus: "NO KNOWN ISSUES FOUND"
      }
    ]
  };

  const verifyRes = await plugin.invokeTool("verify_wallet_scan", {
    walletAddress: SAMPLE_WALLET,
    scanResult: mockScan
  });
  assert.equal(verifyRes.status, "SUCCESS");
  assert.equal(verifyRes.verified, true);
  assert.equal(verifyRes.isSafeForTransactions, true);
  assert.equal(verifyRes.integrityCheck, "VERIFIED_VALID");
});
