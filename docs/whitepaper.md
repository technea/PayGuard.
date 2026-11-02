# PayGuard Technical Whitepaper

**A Base-First Ecosystem Security Platform: Pre-Signing Verification for Humans and Autonomous AI Agents**

**Version 1.0.0 | November 2026**
*Mission: Verify Before You Trust*
*Repository: https://github.com/technea/PayGuard | Branch: main*

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Problem: Web3 Impersonation and Security Risks](#2-the-problem-web3-impersonation-and-security-risks)
3. [PayGuard's Mission and Vision](#3-payguards-mission-and-vision)
4. [Why HTTPS Does Not Mean a Website Is Legitimate](#4-why-https-does-not-mean-a-website-is-legitimate)
5. [Why Verified Smart Contract Source Does Not Prove Authenticity](#5-why-verified-smart-contract-source-does-not-prove-authenticity)
6. [Why Token Names and Symbols Cannot Establish Identity](#6-why-token-names-and-symbols-cannot-establish-identity)
7. [PayGuard Security Architecture](#7-payguard-security-architecture)
8. [URL and Domain Authenticity Verification](#8-url-and-domain-authenticity-verification)
9. [Token and Smart Contract Security](#9-token-and-smart-contract-security)
10. [Wallet Security and Transaction Inspection](#10-wallet-security-and-transaction-inspection)
11. [Base Ecosystem Integration](#11-base-ecosystem-integration)
12. [AI Agent and MCP Integration (Secondary Capability)](#12-ai-agent-and-mcp-integration-secondary-capability)
13. [Technical Architecture & Module Flow](#13-technical-architecture--module-flow)
14. [Threat Model & Security Boundaries](#14-threat-model--security-boundaries)
15. [Current Capabilities and Limitations](#15-current-capabilities-and-limitations)
16. [Future Roadmap](#16-future-roadmap)

---

## 1. Executive Summary

As the Base blockchain ecosystem experiences explosive growth in on-chain finance, decentralized consumer applications, and autonomous AI agents, it confronts a severe crisis of digital impersonation. Fraudulent web domains mimic official Base infrastructure (e.g., `base.org` vs. `bases.org`), lookalike ERC-20 tokens copy canonical tickers to sell worthless assets, verified smart contracts conceal lethal honeypot logic, and obfuscated transaction calldata manipulates users and AI agents into granting unlimited token allowances (`2^256 - 1`).

PayGuard is a free, Base-first ecosystem security platform engineered around one core operational directive: **Verify Before You Trust.**

PayGuard provides deterministic, pre-signing security intelligence across web domains, ERC-20 token contracts, wallet holdings, and transaction payloads. It delivers actionable verdicts (`PASS`, `REVIEW`, `BLOCK`, `UNVERIFIED`) through an interactive dark-theme security console, a lightweight HTTP REST API, and seven Model Context Protocol (MCP) tools for autonomous agents.

PayGuard operates strictly out-of-band:
- **Zero Custody:** Never requests, stores, or handles private keys, seed phrases, or credentials.
- **Zero SSRF:** Parses target URLs 100% in-memory using static lexical algorithms without making outbound network requests to inspected targets.
- **Fail-Closed Operations:** Upstream outages, timeouts, or unindexed contracts return `UNVERIFIED` — never a false `PASS`.
- **Authoritative Identity Matching:** Replaces visual guesswork with cryptographic verification against canonical Base asset registries.

---

## 2. The Problem: Web3 Impersonation and Security Risks

Decentralized networks eliminate custodial intermediaries, but this shift grants full finality to every transaction. Once an EVM transaction is confirmed on Base, execution is irreversible. Attackers exploit this irreversibility by exploiting the cognitive and programmatic gap between visual appearance and blockchain reality.

### 2.1 The Scope of Attack Vectors

| Attack Vector | Mechanism | Impact |
| :--- | :--- | :--- |
| **Domain Typosquatting & Homoglyphs** | Lookalike hostnames (`bases.org`, `bаse.org` with Cyrillic 'а') | Users and agents connect wallets to drainer contracts |
| **Token Lookalike Impersonation** | Deploying malicious ERC-20 contracts using symbols like `USDC` or `VIRTUAL` | Victims buy counterfeit tokens with zero liquidity |
| **Honeypot Logic** | Code permitting `buy()` while reverting or taxing `sell()` at 100% | Total loss of invested capital |
| **Owner Balance Alteration** | Privileged minting or direct modification of holder balances | Creator drains liquidity pools or wipes user tokens |
| **Unlimited Allowance Traps** | dApps requesting `approve(spender, 2^256 - 1)` | Spender contract drains user tokens at any future date |
| **Counterparty Infection** | Interacting with addresses linked to sanctions or cybercrime | Tainted wallet reputation and legal compliance risk |

---

## 3. PayGuard's Mission and Vision

### 3.1 Mission: Verify Before You Trust

The founding mission of PayGuard is to establish an accessible, open, and objective security standard for the Base ecosystem. Rather than requiring users to trust an opaque third party, PayGuard gathers deterministic on-chain data, lexical evidence, and threat intelligence to enable human traders, developers, and autonomous software agents to independently verify authenticity before taking action.

### 3.2 Strategic Vision

PayGuard envisions an ecosystem where:
1. Every web dApp link is vetted for homoglyphic and typosquatting signals before wallet connection.
2. Every token contract address is cryptographically validated against canonical registries before swapping.
3. Every transaction payload is decoded to expose hidden approval traps before signing.
4. Autonomous AI agents run native MCP security checks before invoking financial tools.

---

## 4. Why HTTPS Does Not Mean a Website Is Legitimate

A pervasive misconception among Web3 users is that an HTTPS padlock icon in the browser signifies that a website is genuine, trustworthy, or safe.

### 4.1 The Technical Reality of TLS/HTTPS

- **Encryption vs. Authenticity:** Transport Layer Security (TLS/HTTPS) guarantees only that the communication channel between the client browser and the destination server is encrypted against eavesdropping. It provides zero guarantees regarding the moral character, identity, or legitimacy of the entity operating that server.
- **Automated Free Certificates:** Domain-validated (DV) SSL certificates are issued automatically and free of charge by Certificate Authorities (e.g., Let's Encrypt, ZeroSSL, Cloudflare) within seconds via automated ACME challenges.
- **Prevalence in Phishing:** Over 90% of active Web3 phishing websites operate over HTTPS with valid, error-free certificates.

PayGuard completely disregards the HTTPS padlock when evaluating domain authenticity. Instead, it inspects lexical edit distances, Internationalized Domain Name (IDN) Punycode labels, subdomains, and authoritative project registries.

---

## 5. Why Verified Smart Contract Source Does Not Prove Authenticity

Block explorers like Basescan provide a "Contract Source Code Verified" badge (often represented as a green checkmark). Users frequently misinterpret this badge as an endorsement of contract safety.

### 5.1 What Source Verification Actually Means

- **Compiler Bytecode Matching:** Source verification proves only that the submitted high-level Solidity source code compiles down to the exact bytecode deployed at that contract address.
- **Weaponized Verification:** Scam deployers intentionally verify their contracts on Basescan. A verified contract makes the honeypot appear transparent and professional.
- **Concealed Malice:** A verified contract can still contain:
  - `owner_change_balance` functions permitting the owner to set any holder's balance to zero.
  - Hidden 99% sell taxes routed to a developer wallet.
  - Blacklists blocking specific transfer recipients.
  - Pausable trading functions locking buyer liquidity indefinitely.

PayGuard evaluates smart contracts dynamically via GoPlus intelligence parameters and byte-level calldata checks rather than relying on explorer verification checkmarks.

---

## 6. Why Token Names and Symbols Cannot Establish Identity

On Ethereum and Base, the ERC-20 standard defines `name()` and `symbol()` as arbitrary, optional metadata strings stored within contract storage.

### 6.1 The Non-Uniqueness of Token Symbols

- **Permissionless Deployment:** Any developer can deploy a contract with `name = "USD Coin"` and `symbol = "USDC"` for a few cents in gas.
- **Explorer Listing Confusion:** Decentralized exchanges (DEXs) index any contract deployed on-chain. When a user searches for "VIRTUAL" or "AERO", dozens of lookalike tokens appear in the search results.
- **Immutable Contract Addresses:** The **only** immutable, cryptographically authoritative identifier for an on-chain asset is its 20-byte contract address (e.g., native USDC on Base is `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`).

PayGuard enforces exact contract address matching against its curated Base Canonical Asset Registry. If an unverified contract presents a canonical ticker symbol, PayGuard immediately classifies it as `HIGH RISK / TOKEN_LOOKALIKE_IMPERSONATION`.

---

## 7. PayGuard Security Architecture

PayGuard is constructed around three fundamental architectural invariants:

```
[ Inbound Target: URL / Calldata / Token / Wallet ]
                       |
                       v
+-------------------------------------------------------------+
|             Pure In-Memory Static Lexical Parser            |
|       - Zero Outbound Fetch (Anti-SSRF Guaranteed)          |
|       - Unicode Bidirectional Control Extraction            |
|       - NFKC Hostname Normalization & Punycode Deobfuscation|
+-------------------------------------------------------------+
                       |
         +-------------+-------------+
         |                           |
         v                           v
+------------------+       +-------------------+
|  Local Invariant |       | Upstream Intel    |
|  Evaluator       |       | (Opt-In / Cached) |
|  - Selectors     |       | - GoPlus 8453     |
|  - uint256.max   |       | - Base RPC Batch  |
|  - Canonical Reg |       | - Web Risk API    |
+------------------+       +-------------------+
         |                           |
         +-------------+-------------+
                       |
                       v
[ Deterministic Security Verdict: PASS | REVIEW | BLOCK | UNVERIFIED ]
```

### 7.1 Key Invariants

1. **Non-Custodial Read-Only Guarantee:** PayGuard never asks for, accepts, stores, or transmits private keys, seed phrases, or transaction signatures.
2. **SSRF-Proof In-Memory Parsing:** Target URLs are parsed strictly using local in-memory algorithms. PayGuard never opens or pings target hosts, eliminating Server-Side Request Forgery vulnerabilities.
3. **Fail-Closed Threat Boundary:** When upstream APIs encounter network errors, rate limits, or missing data, the outcome is marked `UNVERIFIED`. PayGuard never defaults to `PASS` in the absence of evidence.

---

## 8. URL and Domain Authenticity Verification

The URL Sentinel module (`src/plugin.mjs`) evaluates web links before a user connects a wallet or an autonomous agent follows an instruction.

### 8.1 Lexical & Cryptographic Domain Checks

1. **Unicode Bidirectional (Bidi) Scan:** Detects invisible formatting controls (U+061C, U+200E, U+200F, U+202A–202E, U+2066–2069). These controls visually reverse file extensions or domain paths.
2. **NFKC Normalization & Homoglyph Detection:** Converts hostnames to Unicode Normalization Form KC to expose full-width characters, Cyrillic lookalikes (`bаse.org`), and Greek confusable letters.
3. **Punycode Deobfuscation:** Detects `xn--` Internationalized Domain Name labels and evaluates raw underlying character sets.
4. **Levenshtein Edit Distance:** Measures character substitutions, insertions, and deletions against official Base ecosystem domains (e.g., detecting `bases.org` or `base-org.xyz`).
5. **Credential & Sensitive Path Redaction:** Automatically strips userinfo credentials (`user:pass@host`) and high-entropy authentication tokens from query parameters before analysis.

---

## 9. Token and Smart Contract Security

The Token Security module (`src/token-security.mjs` and `src/wallet-token-scanner.mjs`) performs deep inspection of Base Mainnet (Chain ID 8453) assets using on-chain RPC multicall queries and GoPlus Security feeds.

### 9.1 Evaluated Indicators

| Parameter | Evaluated Threshold | Severity / Verdict |
| :--- | :--- | :--- |
| **`is_honeypot`** | Equals `1` (token cannot be sold) | `CRITICAL / BLOCK` |
| **`owner_change_balance`** | Equals `1` (owner can edit balances) | `CRITICAL / BLOCK` |
| **`cannot_sell_all`** | Equals `1` (liquidity exit restrictions) | `CRITICAL / BLOCK` |
| **`buy_tax` / `sell_tax`** | Exceeds `10%` | `HIGH / BLOCK` or `REVIEW` |
| **`transfer_pausable`** | Equals `1` (transfers can be frozen) | `MEDIUM / REVIEW` |
| **`is_airdrop_scam`** | Equals `1` (unsolicited phishing airdrop) | `HIGH / BLOCK` |
| **`is_open_source`** | Equals `0` (unverified bytecode) | `MEDIUM / REVIEW` |
| **`is_impersonation`** | Canonical symbol with mismatched address | `HIGH / BLOCK` |

---

## 10. Wallet Security and Transaction Inspection

### 10.1 Calldata Inspector (`src/calldata-inspector.mjs`)
The Calldata Inspector performs static, pre-signing inspection of EVM transaction data:
- **Selector Decoding:** Decodes standard ERC-20 methods: `approve(address,uint256)` (`0x095ea7b3`), `transfer(address,uint256)` (`0xa9059cbb`), and `transferFrom(address,address,uint256)` (`0x23b872dd`).
- **Unlimited Allowance Trap:** Identifies when an approval requests `2^256 - 1` (`0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`) and issues an explicit `UNLIMITED_ALLOWANCE` warning.
- **Spender & Recipient Policy Enforcement:** Validates target addresses against user-defined allowlists.

### 10.2 Base Wallet Token Scanner (`src/wallet-token-scanner.mjs`)
Scans a Base wallet's token holdings using a resilient two-tier discovery architecture:
- **Tier 1 (Blockscout API v2):** Queries the public indexer for all ERC-20 balances.
- **Tier 2 (RPC Multicall Fallback):** When indexers encounter Cloudflare bot protection in automated runtimes, PayGuard falls back to on-chain `eth_call` queries on Base Mainnet (`https://mainnet.base.org`). The fallback inspects the 7 canonical Base registry tokens plus optional user-specified custom contracts, labeling the scan honestly as `REGISTRY_AND_CUSTOM_PARTIAL`.

---

## 11. Base Ecosystem Integration

PayGuard is designed specifically for Base:
- **Base Canonical Registry:** Authoritative mappings for canonical WETH (`0x4200000000000000000000000000000000000006`), native USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`), cbETH (`0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22`), VIRTUAL (`0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b`), DAI (`0x50c5725949a6F0c72E6C4a641F24049A917DB0Cb`), USDbC (`0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA`), and AERO (`0x940181a94A35A4569E4529A3CDfB74e38FD98631`).
- **Base Smart Wallet Client:** Integrates `@coinbase/wallet-sdk@4.4.0` with pre-signing calldata inspection hooks.
- **Browser Wallet Connection:** Supports standard EIP-1193 injected providers (Coinbase Wallet, MetaMask) with automatic Base Mainnet (8453) chain detection and switching.

---

## 12. AI Agent and MCP Integration (Secondary Capability)

Autonomous AI agents operate without visual human inspection. PayGuard exposes seven Model Context Protocol (MCP) tools over JSON-RPC 2.0 stdio, allowing models like Claude Desktop, Cursor, or autonomous agent frameworks to call security inspections natively:

1. `payguard_check_payment_intent`: Validates x402 payment requirements against user policies.
2. `payguard_analyze_url`: In-memory phishing, Bidi, and lookalike detection.
3. `payguard_prepare_threat_report`: Privacy-conscious draft incident report generator.
4. `payguard_inspect_calldata`: EVM calldata inspection and unlimited approval guard.
5. `payguard_check_token_security`: GoPlus honeypot and contract parameter audit (Base 8453).
6. `payguard_check_address_security`: GoPlus address reputation screening (phishing, sanctions, mixers).
7. `payguard_scan_wallet_tokens`: Base wallet token holdings scan with impersonation detection.

---

## 13. Technical Architecture & Module Flow

```
+-----------------------------------------------------------------------------------+
|                                 Consumer Layer                                    |
|   Interactive Dashboard (HTML5)  |  HTTP REST API (/api/*)  |  MCP Stdio Server   |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                            Security Engine (ESM)                                  |
|   src/plugin.mjs              |  src/wallet-token-scanner.mjs                     |
|   src/calldata-inspector.mjs  |  src/token-security.mjs / address-security.mjs    |
+-----------------------------------------------------------------------------------+
        |                                 |                                 |
        v                                 v                                 v
+-------------------+             +-------------------+             +---------------+
| Base Mainnet RPC  |             | Blockscout Base   |             | GoPlus API    |
| (eth_call batch)  |             | (API v2 Indexer)  |             | (Threat Data) |
+-------------------+             +-------------------+             +---------------+
```

---

## 14. Threat Model & Security Boundaries

### 14.1 Attacker Capabilities Mitigated
- **Invisible Bidi Characters:** Mitigated by pre-parser regex control range scanning.
- **Unicode Confusable Hosts:** Mitigated by NFKC normalization and script checking.
- **Deceptive Suffix Domains:** Mitigated by parent-domain extraction and allowlist comparison.
- **Unlimited Approvals:** Mitigated by parsing EVM parameters and checking `uint256.max`.
- **Honeypot Traps:** Mitigated by GoPlus dynamic buy/sell simulation flags.
- **Counterparty Sanctions:** Mitigated by GoPlus address screening.

### 14.2 Out-of-Scope Risks
- **Zero-Day Unindexed Scams:** Brand-new contracts deployed minutes prior may not be indexed; PayGuard fails closed as `UNVERIFIED`.
- **Arbitrary External Transactions:** PayGuard cannot block transactions signed directly inside third-party browser extensions outside PayGuard-controlled paths.
- **Off-Chain Social Engineering:** Physical coercion or off-chain credential compromise is out of scope.

---

## 15. Current Capabilities and Limitations

### 15.1 Implemented Capabilities
- 7 fully registered, callable Model Context Protocol (MCP) tools.
- Complete in-memory URL analysis with zero outbound network calls to targets.
- Pre-signing ERC-20 calldata inspection for `approve`, `transfer`, and `transferFrom`.
- GoPlus Base Mainnet token and address security evaluation with 10-minute in-memory caching.
- Base wallet token scanner with two-tier discovery and lookalike token impersonation detection.
- Interactive dark-theme security console with live REST endpoints and read-only wallet connection.
- 154 passing automated tests with zero external HTTP dependencies.

### 15.2 Current Limitations
- **Base Mainnet Only:** GoPlus threat feeds and canonical token registries apply to Base Mainnet (8453). Base Sepolia (84532) returns `UNVERIFIED / UNSUPPORTED_CHAIN`.
- **Partial Wallet Discovery on Fallback:** When public indexers present bot challenges, the scanner checks the 7 canonical Base assets plus user-specified addresses rather than the entire universe of unsolicited tokens.
- **Calldata Scope:** Evaluates ERC-20 standard selectors. Complex DEX aggregation or multicalls return advisory `REVIEW`.

---

## 16. Future Roadmap

### Near-Term Planned Enhancements
- **EIP-712 Permit Inspection:** Decode `eth_signTypedData_v4` payloads to flag offline permit signatures.
- **Expanded DEX Selector Library:** Add decoders for Uniswap V3 swap methods and Aerodrome router calls.
- **Dedicated Indexer RPC Support:** Optional user configuration for Alchemy or QuickNode endpoints for complete token history scanning.
- **Persistent Cache Backend:** Optional Redis or SQLite persistence for enterprise multi-process deployments.

### Explicit Non-Goals
- Mandatory paid subscriptions or trial paywalls (PayGuard remains a free community utility).
- Private key custody or transaction broadcasting.
- On-chain state freezing, token burning, or wallet quarantine.

---

*PayGuard is an open-source security intelligence project developed for the Base and Web3 communities. Published under the MIT License.*
