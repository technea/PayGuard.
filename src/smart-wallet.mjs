/**
 * PayGuard Base Smart Wallet Integration Module
 *
 * Provides a standardized client adapter for Base Smart Wallet connectivity
 * using the official @coinbase/wallet-sdk (Coinbase Developer Platform / Base).
 *
 * Architectural Boundary:
 * PayGuard is a policy validation engine and security sentinel, not a wallet or
 * payment executor. Connecting a Base Smart Wallet allows viewing connected account
 * addresses and active chain state, but does not grant transaction signing authority
 * or alter pre-flight policy evaluation.
 */

import { CoinbaseWalletSDK, createCoinbaseWalletSDK } from "@coinbase/wallet-sdk";
import { inspectCalldata } from "./calldata-inspector.mjs";

export const BASE_MAINNET_CHAIN_ID = 8453;
export const BASE_SEPOLIA_CHAIN_ID = 84532;
export const BASE_SEPOLIA_CHAIN_ID_HEX = "0x14a34";
export const BASE_SEPOLIA_RPC_URL = "https://sepolia.base.org";
export const BASE_MAINNET_RPC_URL = "https://mainnet.base.org";

/**
 * Creates and configures a Base Smart Wallet SDK instance and provider.
 *
 * @param {Object} options Configuration options
 * @param {string} [options.appName='PayGuard Policy Sentinel'] Application name displayed in passkey popup
 * @param {string} [options.appLogoUrl] Optional application logo URL
 * @param {string} [options.preference='smartWalletOnly'] Wallet preference ('smartWalletOnly' | 'all' | 'eoaOnly')
 * @returns {Object} Configured client with provider and utility helpers
 */
export function createBaseSmartWalletClient(options = {}) {
  const {
    appName = "PayGuard Policy Sentinel",
    appLogoUrl = "https://payguard.dev/logo.png",
    preference = "smartWalletOnly"
  } = options;

  let sdkInstance = null;
  let providerInstance = null;

  try {
    if (typeof createCoinbaseWalletSDK === "function") {
      sdkInstance = createCoinbaseWalletSDK({
        appName,
        appLogoUrl,
        preference: { options: preference }
      });
      if (sdkInstance && typeof sdkInstance.getProvider === "function") {
        providerInstance = sdkInstance.getProvider();
      }
    }
  } catch (err) {
    // In environments without browser globals (like unit test runners without mock DOM),
    // fallback gracefully to class constructor or expose factory error
    sdkInstance = null;
    providerInstance = null;
  }

  return {
    appName,
    preference,
    sdk: sdkInstance,
    provider: providerInstance,

    /**
     * Connects to Base Smart Wallet via standard EIP-1193 eth_requestAccounts.
     * Never requests private keys or seed phrases.
     *
     * @param {Object} [customProvider] Optional mock/injected provider for testing
     * @returns {Promise<{ address: string, chainId: string }>}
     */
    async connect(customProvider = providerInstance) {
      const activeProvider = customProvider || providerInstance;
      if (!activeProvider || typeof activeProvider.request !== "function") {
        throw new Error("No compatible Base Smart Wallet provider available in this environment.");
      }

      const accounts = await activeProvider.request({ method: "eth_requestAccounts" });
      if (!Array.isArray(accounts) || accounts.length === 0) {
        throw new Error("No accounts returned from Base Smart Wallet.");
      }

      let chainId = null;
      try {
        chainId = await activeProvider.request({ method: "eth_chainId" });
      } catch {
        chainId = null;
      }

      return {
        address: accounts[0],
        chainId
      };
    },

    /**
     * Requests network switch to Base Sepolia (testnet) or Base Mainnet.
     *
     * @param {number|string} targetChainId Target chain ID (84532 or '0x14a34' for Base Sepolia)
     * @param {Object} [customProvider] Optional provider instance
     */
    async switchChain(targetChainId = BASE_SEPOLIA_CHAIN_ID_HEX, customProvider = providerInstance) {
      const activeProvider = customProvider || providerInstance;
      if (!activeProvider || typeof activeProvider.request !== "function") {
        throw new Error("Provider not initialized.");
      }

      const hexChainId = typeof targetChainId === "number"
        ? "0x" + targetChainId.toString(16)
        : targetChainId;

      try {
        await activeProvider.request({
          method: "wallet_switchEthereumChain",
          params: [{ chainId: hexChainId }]
        });
      } catch (switchError) {
        // If chain is not added (error 4902), request to add it
        if (switchError?.code === 4902 && (hexChainId === BASE_SEPOLIA_CHAIN_ID_HEX || targetChainId === BASE_SEPOLIA_CHAIN_ID)) {
          await activeProvider.request({
            method: "wallet_addEthereumChain",
            params: [{
              chainId: BASE_SEPOLIA_CHAIN_ID_HEX,
              chainName: "Base Sepolia",
              nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
              rpcUrls: [BASE_SEPOLIA_RPC_URL],
              blockExplorerUrls: ["https://sepolia.basescan.org"]
            }]
          });
        } else {
          throw switchError;
        }
      }
    },

    /**
     * Inspects a candidate transaction before initiating a wallet signing request.
     * Enforces that non-PASS verdicts (REVIEW, BLOCK) are returned with full findings.
     *
     * @param {Object} tx Candidate transaction object ({ to, value, data })
     * @param {Object} [policy={}] Optional inspection policy constraints
     * @returns {Object} Inspection result from inspectCalldata
     */
    inspectCandidate(tx, policy = {}) {
      return inspectCalldata(tx, policy);
    },

    /**
     * Securely prepares and initiates a transaction request through the connected wallet provider.
     *
     * Security Boundary:
     * Executes inspectCalldata() BEFORE calling activeProvider.request({ method: 'eth_sendTransaction' }).
     * If the inspection verdict is BLOCK or REVIEW, the signing request is aborted, returning
     * { aborted: true, verdict, riskLevel, reasons, checks, details }.
     * Only transactions with a clean PASS verdict proceed to the wallet approval prompt.
     *
     * @param {Object} tx Transaction candidate object ({ to, value, data })
     * @param {Object} [options={}] Options including policy constraints and custom provider
     * @param {Object} [options.policy] Security policy allowlists and caps
     * @param {Object} [options.provider] Custom provider instance (e.g. for testing)
     * @returns {Promise<Object>} Result object with status, inspection, and txHash (if approved)
     */
    async requestTransaction(tx, options = {}) {
      const { policy = {}, provider: customProvider = null } = options;
      const activeProvider = customProvider || providerInstance;

      // 1. Pre-signing security inspection step
      const inspection = this.inspectCandidate(tx, policy);

      // 2. Strict enforcement: Abort on non-PASS verdicts (BLOCK or REVIEW)
      if (inspection.verdict !== "PASS") {
        return {
          aborted: true,
          verdict: inspection.verdict,
          riskLevel: inspection.riskLevel,
          operation: inspection.operation,
          reasons: inspection.reasons,
          checks: inspection.checks,
          details: inspection.details,
          txHash: null
        };
      }

      // 3. Ensure a connected provider exists before requesting wallet action
      if (!activeProvider || typeof activeProvider.request !== "function") {
        throw new Error("No connected wallet provider available for transaction signing.");
      }

      // 4. Request user approval in the connected wallet
      try {
        const txHash = await activeProvider.request({
          method: "eth_sendTransaction",
          params: [tx]
        });

        return {
          aborted: false,
          verdict: "PASS",
          riskLevel: "LOW",
          operation: inspection.operation,
          reasons: [],
          checks: inspection.checks,
          details: inspection.details,
          txHash
        };
      } catch (err) {
        // User rejection (code 4001) or provider error
        const isRejection = err?.code === 4001 || /rejected/i.test(err?.message);
        return {
          aborted: true,
          verdict: "REJECTED_BY_USER",
          riskLevel: isRejection ? "LOW" : "HIGH",
          operation: inspection.operation,
          reasons: [err?.message || "User rejected the transaction request in wallet."],
          errorCode: err?.code,
          checks: inspection.checks,
          details: inspection.details,
          txHash: null
        };
      }
    },

    /**
     * Cleans up provider sessions if supported by the provider.
     */
    async disconnect(customProvider = providerInstance) {
      const activeProvider = customProvider || providerInstance;
      if (activeProvider && typeof activeProvider.disconnect === "function") {
        try {
          await activeProvider.disconnect();
        } catch {
          // Disconnect is best-effort in standard EIP-1193
        }
      }
    }
  };
}

export default createBaseSmartWalletClient;
