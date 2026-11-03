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
- Opens, fetches, or pings user-supplied URLs. The current tools analyze URL text only.
- Freezes, burns, or quarantines on-chain assets (it has zero administrative privileges).

### 2. Fail Closed
Every external API integration (GoPlus, Blockscout, Base RPC) fails closed:
- An upstream HTTP 500, 429 rate limit, network timeout, or unindexed asset returns `UNVERIFIED` — **never `PASS`**.
- Missing data is never treated as proof of safety. Absence of evidence is not evidence of absence.

### 3. Minimal External Surface and No User-Directed Fetching
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
| **SSRF Attacks** | Attacker supplying `http://169.254.169.254` or internal LAN IPs | The URL Sentinel parses text only and never fetches the submitted URL. Outbound calls go only to fixed provider endpoints |
| **DoS via Giant Payloads** | Massive calldata or oversized API responses | 64 KB hard request ceiling and 3-second network timeouts |

### Out of Scope

| Threat | Why Out of Scope |
|--------|------------------|
| **Zero-Day Unindexed Scams** | Newly deployed contracts not yet in threat feeds return `UNVERIFIED`, not detected |
| **EIP-712, Permit and Permit2 Signatures** | Offline signatures (`eth_signTypedData_v4`) are not currently decoded |
| **EIP-7702 Delegation** | Account delegation authorizations are not inspected |
| **Multicall and Batched Calls** | Return advisory `REVIEW`; inner calls are not decoded |
| **Prompt Injection of Agents** | Detecting hostile instructions needs reputation data and an investigation layer (planned) |
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

---

## Trust Boundaries

| Boundary | Trusted | Untrusted or limited |
|----------|---------|----------------------|
| Caller input (URL, calldata, addresses) | Validated against schemas and size limits | Content is attacker-controlled and treated as data |
| x402 policy | Supplied by the user or developer in advance | A payment request is never used to define its own policy |
| GoPlus, Blockscout, Base RPC, Google Web Risk | Fixed endpoints chosen by the operator | Provider accuracy and availability are not verified by PayGuard |
| PayGuard server | Holds optional provider API keys server-side | No authentication; spoofable per-IP rate limit if not behind a trusted proxy |
| External wallet | Outside PayGuard | PayGuard cannot stop a user from signing there |

---

## Data Handling and Privacy

| Data | Where it goes | Notes |
|------|---------------|-------|
| Submitted URL | Processed in memory | Not fetched. With `checkReputation: true`, a redacted URL goes to Google Web Risk: path segments redacted, query parameters withheld |
| Token or wallet address | GoPlus, Blockscout and Base RPC | These providers can see the address you query |
| Calldata and x402 policy | Processed in memory | No outbound calls for these two checks |
| Provider results | Process memory, 10 minute TTL | Cleared on restart; no database |
| Threat reports | Returned to the caller | Draft only; not transmitted anywhere |
| Metrics | In-memory Prometheus counters | Counts and verdict labels only, no submitted values |
| Provider API keys | Environment variables on the server | Not returned in responses |

The code reviewed for this page does not write submitted inputs to disk. Operators who log requests at a proxy or platform layer are responsible for that data.

---

## Operational Controls and Gaps

| Control | Current behavior |
|---------|------------------|
| Request body limit | 64 KB |
| Concurrency cap | 100 in-flight requests by default |
| Rate limit | 120 requests per 60 seconds per client IP by default; the address is read from `x-forwarded-for` or `x-real-ip` |
| Upstream timeout | 3 seconds for GoPlus calls; 64 KB response cap |
| Authentication and quotas | None. Planned |
| CORS | `*` |
| Errors | Internal details hidden unless `NODE_ENV=development` |

---

## Status Labels

Documentation across this site labels capabilities as **Implemented**, **Partially Supported** or **Planned**. The AI Security Agent is **Planned**; see [AI Security Agent](ai-security-agent.md). Provider reputation results are not an independent smart-contract audit.
