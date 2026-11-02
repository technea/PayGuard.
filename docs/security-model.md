# PayGuard Security Model

## Overview

PayGuard is a **free, Base-first ecosystem security platform and advisory sentinel**, not a custodial wallet or transaction execution gateway. Its core mission is **"Verify Before You Trust."**

This document formalizes PayGuard's security perimeter, foundational assumptions, threat model, privacy guarantees, and non-negotiable boundaries.

---

## Foundational Web3 Truths

Traditional web security assumptions break down in Web3 environments. PayGuard is engineered around three non-negotiable realities:

1. **HTTPS does not prove a website is legitimate.**
   An HTTPS padlock only indicates an encrypted TLS connection. Any threat actor can register a phishing domain (such as `bases.org` or `claim-base.xyz`) and issue a free SSL certificate within seconds. HTTPS provides zero verification of business legitimacy or project authenticity.

2. **Verified contract source code does not prove a token is official.**
   "Verification" on Basescan or Etherscan merely confirms that the compiled bytecode corresponds to the submitted source text. Honeypot creators, rug-pull deployers, and fake token issuers regularly verify their Solidity code to trick visual inspectors. Verified code can still contain owner balance modification privileges, 100% sell taxes, or hidden mint backdoors.

3. **A token name or symbol alone cannot establish authenticity.**
   On EVM blockchains, token names and symbols are non-unique metadata strings. Anyone can deploy an ERC-20 contract named "USD Coin" with the symbol "USDC". Authenticity can only be established through cryptographic verification of the exact, immutable contract address against authoritative ecosystem registries.

---

## Core Security Principles

### 1. Inspect, Never Act
PayGuard never:
- Signs or broadcasts transactions (except in the opt-in `BaseSmartWalletClient` wrapper when explicitly requested by user code).
- Requests, handles, or stores private keys, seed phrases, or mnemonics.
- Executes payments or initiates transfers.
- Opens, fetches, or pings user-supplied URLs (100% anti-SSRF).
- Freezes, burns, or quarantines on-chain assets (it has zero administrative privileges).

### 2. Fail Closed
Every external API integration (GoPlus, Blockscout, Base RPC) fails closed:
- An upstream HTTP 500, 429 rate limit, network timeout, or unindexed asset returns `UNVERIFIED` — **never `PASS`**.
- Missing data is never treated as proof of safety. Absence of evidence is not evidence of absence.

### 3. Minimal External Surface & Zero SSRF
- **In-Memory URL Parsing:** URL Sentinel uses the WHATWG URL parser locally. No outbound connection is ever made to the inspected host.
- **Fixed Upstream Providers:** External network requests are restricted to hardcoded endpoints:
  - GoPlus Security API (`api.gopluslabs.io`)
  - Base Mainnet Public RPC (`mainnet.base.org`)
  - Blockscout Base API v2 (`base.blockscout.com`)
  - Google Web Risk API (`webrisk.googleapis.com` — opt-in only)
- **Credential Redaction:** Sensitive query strings (passwords, tokens, bearer secrets) are redacted before any external reputation lookup.

### 4. Credential Isolation
- Server-side API keys (`GOPLUS_API_KEY`, `GOOGLE_WEB_RISK_API_KEY`) remain strictly on the backend.
- API keys are never exposed in JSON responses, MCP tool outputs, or client-side bundles.

---

## Threat Model

### In Scope

| Threat | Attack Vector | PayGuard Mitigation |
|--------|--------------|---------------------|
| **Base Phishing Domains** | Lookalikes like `bases.org` or `pаybox.sh` | Levenshtein distance check, Punycode deobfuscation, and NFKC confusable matching |
| **Bidi Unicode Attacks** | Invisible right-to-left override characters (U+202E) hiding extensions | Pre-parser Unicode bidirectional control scan (fails closed with `BLOCK`) |
| **Punycode Deception** | `xn--` IDN labels spoofing Latin characters | Punycode label identification and raw script validation |
| **Unlimited Token Approvals** | dApps requesting `approve(spender, 2^256 - 1)` | Calldata inspector decodes allowance; flags `uint256.max` as `UNLIMITED_ALLOWANCE` |
| **Honeypot Tokens** | Contract allowing buys but blocking sells | GoPlus `is_honeypot` and `cannot_sell_all` evaluation |
| **Arbitrary Balance Modification** | Owner can arbitrarily edit holder balances | GoPlus `owner_change_balance` evaluation (flags `BLOCK / CRITICAL`) |
| **Excessive Trading Taxes** | Hidden 50% or 99% buy/sell tax traps | GoPlus buy/sell tax threshold evaluation |
| **Token Impersonation** | Lookalike contract copying canonical symbols (`USDC`, `VIRTUAL`) | `checkTokenImpersonation` compares contract address against Base canonical registry |
| **Suspicious Counterparties** | Transfers to sanctioned or phishing addresses | GoPlus Address Security screening (flags `BLOCK / CRITICAL`) |
| **x402 Intent Manipulation** | Rogue merchant demanding excess payment or unapproved assets | Strict pre-payment comparison against user-defined intent policy |
| **SSRF Attacks** | Attacker supplying `http://169.254.169.254` or internal LAN IPs | URL Sentinel runs 100% in-memory; zero outbound network fetch |
| **DoS via Giant Payloads** | Massive calldata or oversized API responses | 64 KB hard request ceiling and 3-second network timeouts |

### Out of Scope

| Threat | Why Out of Scope |
|--------|------------------|
| **Zero-Day Unindexed Scams** | Newly deployed contracts not yet in threat feeds return `UNVERIFIED`, not detected |
| **EIP-712 Permit Signatures** | Offline permit signatures (`eth_signTypedData_v4`) not currently decoded |
| **Cross-Chain Attacks** | GoPlus and RPC checks currently target Base Mainnet (Chain ID 8453) only |
| **MEV & Sandwich Exploits** | Mempool transaction ordering and slippage attacks are out of scope |
| **External Wallet Enforcement** | PayGuard cannot prevent a user from manually signing inside MetaMask or other third-party wallets |
| **On-Chain State Freezing** | PayGuard cannot modify blockchain state, freeze tokens, or quarantine wallets |

---

## Wallet Token Scanner Security Model

The Base Wallet Token Scanner (`payguard_scan_wallet_tokens`) is designed with explicit transparency regarding discovery coverage:

### Two-Tier Discovery Architecture

1. **Tier 1 — Full Indexer (`FULL_INDEXER`):**
   Calls the public Blockscout API v2. When accessible, it discovers all arbitrary ERC-20 tokens held by the address.
2. **Tier 2 — RPC Multicall Fallback (`REGISTRY_AND_CUSTOM_PARTIAL`):**
   In automated environments where indexers trigger Cloudflare bot protection, PayGuard falls back to on-chain `eth_call` queries on Base Mainnet (`https://mainnet.base.org`).
   **Boundary:** The fallback inspects the 7 curated Base canonical tokens (WETH, USDC, cbETH, VIRTUAL, DAI, USDbC, AERO) plus any caller-specified `customTokenAddresses`. It **cannot** discover arbitrary unsolicited tokens without an external indexer or explicit contract addresses.

The API response explicitly includes `discoveryMode` and an `advisoryNotice` so users and AI agents always know whether discovery was comprehensive or partial.

---

## Disclosure Statement

PayGuard is an **advisory intelligence sentinel**. It delivers structured evidence to empower human users and autonomous AI agents to make informed decisions before interacting with smart contracts or visiting Web3 links.

PayGuard does **not** guarantee that an asset is risk-free, does **not** replace a comprehensive smart contract audit, and does **not** possess administrative custody over user funds.
