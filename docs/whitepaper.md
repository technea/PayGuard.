# PayGuard Technical Whitepaper

**A Free, Base-First Ecosystem Security Platform for Humans and Autonomous AI Agents**

**Version 0.1.0 | November 2026**
*Mission: Verify Before You Trust*
*Branch: main | Repository: https://github.com/technea/PayGuard*

---

## Abstract

As the Base blockchain ecosystem experiences rapid expansion in decentralized finance, autonomous AI agents, and consumer dApps, it faces an escalating crisis of digital impersonation. Deceptive websites mimic official infrastructure (e.g. `base.org` vs `bases.org`), lookalike ERC-20 tokens impersonate canonical assets, verified smart contracts conceal honeypot traps, and malicious transaction calldata tricks wallets into granting unlimited approvals (`2^256 - 1`).

PayGuard is a free, Base-first ecosystem security platform and advisory sentinel designed to protect both human Web3 users and autonomous AI agents. Guided by the core principle **"Verify Before You Trust,"** PayGuard provides structured, deterministic security intelligence across seven Model Context Protocol (MCP) tools and interactive web interfaces. PayGuard operates strictly out-of-band: it possesses zero private keys, enforces zero custody, executes zero unauthorized transactions, and relies on 100% in-memory lexical parsing to eliminate Server-Side Request Forgery (SSRF).

This paper formalizes the threat landscape, security methodology, two-tier discovery architecture, fail-closed design principles, and empirical evaluation of the PayGuard platform.

---

## 1. Problem Statement & The Threat of Ecosystem Impersonation

### 1.1 The Decentralized Deception Problem

In permissionless blockchain networks, immutability is both a feature and a vulnerability. Once a user signs an EVM transaction or connects a wallet to a malicious smart contract, transactions cannot be reversed or refunded. Attackers exploit this finality by weaponizing the gap between human/machine assumptions and blockchain mechanics.

Three dangerous misconceptions dominate Web3 interactions:

1. **"The site has an HTTPS padlock, so it must be official."**
   Transport Layer Security (TLS) encrypts traffic in transit, but provides zero verification of business legitimacy. Threat actors routinely register lookalike domains (e.g. `bases.org` or `airdrop-base.foundation`) and obtain free certificates from Let's Encrypt within seconds.
2. **"The contract source code is verified on Basescan, so it must be safe."**
   "Source verification" on block explorers simply proves that the submitted Solidity code matches the deployed bytecode. Attackers intentionally verify their contracts to project legitimacy while embedding honeypot traps, arbitrary balance modification functions, or transfer-pausing backdoors.
3. **"The token symbol is USDC, so it must be the real stablecoin."**
   Token names and symbols are arbitrary, non-unique strings on EVM blockchains. Anyone can deploy an ERC-20 token named "USD Coin" with ticker "USDC". Without authoritative address matching, users and automated agents are easily duped into purchasing counterfeit assets.

---

### 1.2 The Autonomous AI Agent Attack Surface

The emergence of autonomous AI agents interacting with Web3 protocols introduces an urgent new vulnerability vector. Modern LLM-driven agents are empowered to read web pages, evaluate payment challenges (e.g. x402 protocols), authorize transactions, and manage smart wallets.

However, AI agents lack the human intuition, visual skepticism, and contextual memory required to spot deception:
- An AI agent cannot see the browser address bar or detect visual subtleties.
- An AI agent parses URLs lexically, making it susceptible to Unicode bidirectional (Bidi) override attacks and Punycode confusable characters.
- An AI agent executing an ERC-20 transaction will blindly approve `uint256.max` if requested by a malicious DeFi interface.
- An AI agent instructed to purchase an asset on Base will match on the symbol string rather than verifying the immutable contract address.

Without an automated, deterministic security layer, autonomous agents become high-value targets for wallet draining.

---

## 2. Platform Mission & Target Audience

### 2.1 Core Mission: Verify Before You Trust

PayGuard was created to establish a transparent, objective, and accessible security baseline for the Base ecosystem. PayGuard does not ask users to trust its authority blindly; rather, it gathers deterministic on-chain data, lexical evidence, and threat intelligence to empower users and agents to **verify before they trust**.

### 2.2 Target Users

1. **Human Web3 Users & Traders:** Individuals seeking an independent second opinion before connecting their wallets to unfamiliar websites, swapping new tokens, or approving smart contract spending.
2. **Autonomous AI Agents:** LLM-based autonomous workers (Claude, Cursor, AutoGPT, LangChain agents) requiring structured, machine-readable JSON security verdicts before invoking transaction tools.
3. **dApp & Smart Wallet Developers:** Builders integrating pre-signing security checks into their applications via the PayGuard SDK or HTTP API.
4. **x402 Micropayment Integrators:** Systems enforcing client-side intent compliance before generating crypto payment proofs.

---

## 3. Threat Model & Security Principles

### 3.1 Assets Protected

- User wallet assets and token balances (against drainers and unlimited approvals).
- Autonomous agent operational integrity (against prompt-injected URLs and deceptive payment requests).
- Infrastructure privacy (against credential leakage and SSRF exploits).

### 3.2 Non-Negotiable Architectural Principles

| Principle | Architectural Implementation |
|-----------|------------------------------|
| **Inspect First, Never Act** | PayGuard delivers advisory intelligence. It never holds keys, initiates transfers, or signs transactions. |
| **Fail-Closed Operations** | Missing data, network timeouts, rate limits, or unindexed tokens return `UNVERIFIED` — never `PASS`. |
| **Zero SSRF (In-Memory Only)** | URL Sentinel parses targets purely in-memory using standard WHATWG libraries; it never opens, pings, or resolves target URLs. |
| **Credential Redaction** | High-entropy path segments, reset tokens, and query credentials are automatically scrubbed before any external lookup. |
| **Base-First Canonical Verification** | Canonical asset registries enforce exact contract address matching for major Base tokens. |

---

## 4. System Architecture & Seven MCP Tools

PayGuard is implemented in native Node.js ESM with zero runtime HTTP dependencies. It exposes seven Model Context Protocol (MCP) tools compatible with the official MCP specification:

```
+-------------------------------------------------------------------+
|                        Consumers & Clients                        |
|  AI Agents (MCP Stdio) | Web Dashboard | HTTP REST | Smart Wallet |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                    PayGuard Security Core (ESM)                   |
|                                                                   |
|  1. payguard_check_payment_intent  (x402 Intent Guard)            |
|  2. payguard_analyze_url           (In-Memory Anti-Phishing)      |
|  3. payguard_prepare_threat_report (Privacy-Redacted Drafts)      |
|  4. payguard_inspect_calldata      (Pre-Signing Calldata Audit)   |
|  5. payguard_check_token_security  (GoPlus Base Token Security)   |
|  6. payguard_check_address_security(GoPlus Base Address Screening)|
|  7. payguard_scan_wallet_tokens    (Two-Tier Wallet Scanner)      |
+-------------------------------------------------------------------+
          |                      |                       |
          v                      v                       v
+------------------+   +-------------------+   +--------------------+
| Base Mainnet RPC |   | Blockscout Base v2|   | GoPlus Security API|
|  (Multicall3)    |   | (Token Holdings)  |   | (Threat Intel Feed)|
+------------------+   +-------------------+   +--------------------+
```

### Tool Suite Overview

1. **`payguard_check_payment_intent`:** Compares proposed x402 payment requirements against an explicit user intent policy (asset, network, recipient, maxAmountAtomic, expiration).
2. **`payguard_analyze_url`:** Scans URLs for Unicode Bidi overrides (U+202E), Punycode homoglyphs (`xn--`), lookalike domains (Levenshtein distance), and embedded credentials.
3. **`payguard_prepare_threat_report`:** Sanitizes suspicious URLs and formats structured incident drafts without broadcasting sensitive parameters.
4. **`payguard_inspect_calldata`:** Decodes EVM calldata (`approve`, `transfer`, `transferFrom`), flags unlimited approvals (`uint256.max`), and compares spenders against allowlists.
5. **`payguard_check_token_security`:** Evaluates Base Mainnet ERC-20 tokens for honeypot traps, excessive buy/sell taxes, arbitrary owner balance privileges, and proxy implementation risks.
6. **`payguard_check_address_security`:** Screens Base addresses for associations with phishing campaigns, cybercrime, sanctions lists, and mixer usage.
7. **`payguard_scan_wallet_tokens`:** Audits token holdings within a specified Base wallet for honeypots, balance-drain vulnerabilities, and canonical token impersonation.

---

## 5. Wallet Token Scanner: Two-Tier Discovery Engine

The Base Wallet Token Scanner (`src/wallet-token-scanner.mjs`) implements a resilient two-tier discovery mechanism:

### Tier 1 — Full Indexer (`FULL_INDEXER`)
The scanner queries the Blockscout Base API v2 (`GET https://base.blockscout.com/api/v2/addresses/{address}/tokens?type=ERC-20`). When accessible, it indexes all arbitrary ERC-20 tokens held by the wallet.

### Tier 2 — On-Chain RPC Multicall Fallback (`REGISTRY_AND_CUSTOM_PARTIAL`)
In automated CI/CD pipelines, serverless runtimes, or environments where public indexers present Cloudflare bot challenges, PayGuard fails gracefully to direct on-chain `eth_call` queries on Base Mainnet (`https://mainnet.base.org`).

The fallback queries:
1. The **Canonical Base Registry:** Curated addresses for WETH, USDC, cbETH, VIRTUAL, DAI, USDbC, and AERO.
2. **User-Specified Custom Tokens:** Any additional contract addresses supplied in `customTokenAddresses`.

Every holding with a non-zero balance is processed through the GoPlus Token Security engine and evaluated for lookalike token impersonation. The response includes an explicit `discoveryMode` and `advisoryNotice` ensuring users know the exact scope of the scan.

---

## 6. Empirical Evaluation & Verification

The PayGuard implementation is continuously validated through an exhaustive automated test suite:

- **Test Suite Status:** **154 passing tests, 0 failures.**
- **Code Coverage:** Comprehensive coverage across URL parsing, Bidi overrides, calldata decoding, GoPlus error paths, rate limiting, and wallet discovery.
- **MCP Conformance:** Validated stdio JSON-RPC 2.0 communication supporting both line-delimited and Content-Length framed protocols.
- **Production Build:** Generates unified ESM, CommonJS, TypeScript DTS declarations, and stdio server bundles with zero external runtime dependencies.

---

## 7. Security Boundaries & Current Limitations

In adherence to technical honesty, PayGuard outlines its explicit boundaries:

1. **Advisory Nature:** Outside the opt-in `BaseSmartWalletClient` wrapper, PayGuard cannot forcibly block external wallet extensions.
2. **Base Mainnet Focus:** Threat intelligence feeds (GoPlus) are active on Base Mainnet (8453). Base Sepolia (84532) returns `UNVERIFIED / UNSUPPORTED_CHAIN`.
3. **Calldata Scope:** The calldata inspector supports core ERC-20 selectors. Complex aggregator multicalls return advisory `REVIEW`.
4. **No On-Chain Simulation:** PayGuard analyzes static code indicators rather than running forked state execution traces.
5. **No State Freezing:** PayGuard possesses no administrative keys or contract backdoors. It cannot burn, freeze, or quarantine on-chain assets.

---

## 8. Business Model & Future Roadmap

### 8.1 Free Community Utility
PayGuard is free to use:
- No mandatory subscriptions, paywalls, or trial limits.
- The interactive web dashboard, REST API, and MCP tools are freely available.
- Voluntary community donations may be accepted to fund RPC infrastructure and threat feed licensing, but all core capabilities remain free.

### 8.2 Future Roadmap (Exploratory)
- **EIP-712 Typed Data Inspection:** Decoding offline permit signatures before signing.
- **Expanded Selector Library:** Decoding Uniswap V3, Aerodrome, and ERC-721/1155 approval patterns.
- **Persistent Cache Layer:** Redis or SQLite storage for multi-process deployments.
- **Browser Extension:** Inline dApp interaction alerts for human web navigation.

---

## 9. Conclusion

Decentralized finance cannot achieve mainstream adoption or autonomous agent scalability without dependable pre-signing security. By establishing a rigorous, read-only, Base-first advisory perimeter, PayGuard provides the crucial missing defense layer: empowering humans and AI agents to **Verify Before You Trust**.
