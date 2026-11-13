/**
 * Canonical and trusted NEAR accounts, official domains, and phishing indicators.
 */

export const NEAR_CANONICAL_ACCOUNTS = Object.freeze([
  "near",
  "aurora",
  "wrap.near",
  "usdt.tether-token.near",
  "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1", // Native USDC
  "v2.ref-finance.near",
  "ref-finance.near",
  "contract.main.burrow.near",
  "burrow.near",
  "x.paras.near",
  "paras.near",
  "linear-protocol.near",
  "meta-pool.near",
  "sweat_welcome.near",
  "token.sweat",
  "pyth-oracle.near",
  "priceoracle.near",
  "app.nearcrowd.near"
]);

export const NEAR_OFFICIAL_DOMAINS = Object.freeze([
  "near.org",
  "wallet.near.org",
  "mynearwallet.com",
  "meteorwallet.app",
  "senderwallet.io",
  "herewallet.app",
  "ref.finance",
  "burrow.finance",
  "paras.id",
  "nearblocks.io",
  "pikespeak.ai",
  "aurora.dev",
  "fastnear.com"
]);

export const SUSPICIOUS_NEAR_KEYWORDS = Object.freeze([
  "airdrop",
  "claim",
  "reward",
  "bonus",
  "free-near",
  "verify-account",
  "support-team",
  "official-near",
  "giveaway",
  "drain",
  "security-update",
  "migration-claim",
  "gift-near",
  "stealth"
]);

export const KNOWN_TRUSTED_CONTRACT_HASHES = Object.freeze({
  "wrap.near": {
    name: "wNEAR (Wrapped NEAR)",
    category: "canonical-token",
    verified: true
  },
  "v2.ref-finance.near": {
    name: "Ref Finance AMM Core",
    category: "dex",
    verified: true
  },
  "contract.main.burrow.near": {
    name: "Burrow Lending Protocol",
    category: "lending",
    verified: true
  }
});

