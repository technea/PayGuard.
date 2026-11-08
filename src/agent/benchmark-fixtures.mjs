/**
 * @module agent/benchmark-fixtures
 * @section Offline synthetic benchmark fixtures
 * Hand-authored, non-live examples for deterministic regression checks.
 * These fixtures are not a representative real-world threat dataset.
 */

export const SYNTHETIC_BENCHMARK_VERSION = "1.0.0";

export const SYNTHETIC_ADDRESSES = Object.freeze({
  token: "0x1111111111111111111111111111111111111111",
  trustedRecipient: "0x2222222222222222222222222222222222222222",
  alternateRecipient: "0x3333333333333333333333333333333333333333",
  spender: "0x4444444444444444444444444444444444444444",
  wallet: "0x5555555555555555555555555555555555555555"
});

export const SYNTHETIC_PAYMENT_POLICY = Object.freeze({
  expectedResourceUrl: "https://merchant.example/pay",
  maxAmountAtomic: "5000000",
  allowedNetworks: ["eip155:8453"],
  allowedAssets: [SYNTHETIC_ADDRESSES.token],
  allowedPayTo: [SYNTHETIC_ADDRESSES.trustedRecipient],
  allowedSchemes: ["exact"],
  maxTimeoutSeconds: 300
});

export const SYNTHETIC_PAYMENT_REQUIREMENTS = Object.freeze({
  resource: "https://merchant.example/pay",
  accepts: [{
    scheme: "exact",
    network: "eip155:8453",
    asset: SYNTHETIC_ADDRESSES.token,
    payTo: SYNTHETIC_ADDRESSES.trustedRecipient,
    amount: "5000000",
    maxTimeoutSeconds: 120
  }]
});
