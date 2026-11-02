# PayGuard Architecture

## Overview

PayGuard is a free, Base-first ecosystem security platform and advisory sentinel built with native Node.js ESM. It provides seven Model Context Protocol (MCP) tools for AI agents, developers, and human Web3 users to inspect transactions, URLs, token honeypots, address reputation, and wallet assets before any signing or transfer action occurs.

The architecture follows a strict layering principle: **inspect first, never act**. No module possesses private keys, executes payments, or signs transactions outside explicit user-authorized client instances.

---

## High-Level System Diagram

```mermaid
flowchart TD
    subgraph Clients["Clients & Consumers"]
        A1["AI Agent / Claude / Cursor"]
        A2["Interactive Web Dashboard"]
        A3["HTTP REST API Client"]
        A4["x402 Payment Client"]
    end

    subgraph MCP["MCP Layer — src/plugin.mjs"]
        B1["JSON-RPC 2.0 stdio server<br/>(startMcpServer)"]
        B2["Tool Registry<br/>(7 MCP tools)"]
        B3["plugin.invokeTool()"]
    end

    subgraph Security["Security Modules — src/*.mjs"]
        C1["URL Sentinel<br/>analyzeUrlSecurity()"]
        C2["Calldata Inspector<br/>inspectCalldata()"]
        C3["Token Security<br/>checkTokenSecurity()"]
        C4["Address Security<br/>checkAddressSecurity()"]
        C5["Wallet Token Scanner<br/>scanBaseWalletTokens()"]
        C6["Payment Guard<br/>evaluatePaymentIntent()"]
        C7["Threat Report<br/>prepareThreatReport()"]
    end

    subgraph External["External Providers & Data Sources"]
        D1["GoPlus Security API<br/>api.gopluslabs.io"]
        D2["Google Web Risk API<br/>(Optional Reputation)"]
        D3["Blockscout Base API v2<br/>(Token Holdings Discovery)"]
        D4["Base Mainnet Public RPC<br/>mainnet.base.org (Multicall)"]
    end

    subgraph SmartWallet["Smart Wallet Integration"]
        E1["createBaseSmartWalletClient()<br/>src/smart-wallet.mjs"]
        E2["inspectCandidate() → inspectCalldata()"]
        E3["requestTransaction()<br/>aborts on non-PASS"]
        E4["Coinbase Base Smart Wallet<br/>eth_sendTransaction"]
    end

    A1 -->|"stdin JSON-RPC"| B1
    A2 -->|"HTTP GET / POST"| Security
    A3 -->|"HTTP REST API"| Security
    A4 -->|"onBeforePaymentCreation hook"| C6

    B1 --> B3
    B2 --> B3
    B3 --> C1
    B3 --> C2
    B3 --> C3
    B3 --> C4
    B3 --> C5
    B3 --> C6
    B3 --> C7

    C3 -->|"GET /v1/token_security/8453"| D1
    C4 -->|"GET /v1/address_security/{addr}"| D1
    C1 -->|"Optional: GET /v1/uris:search"| D2
    C5 -->|"Tier 1: GET /api/v2/addresses/{addr}/tokens"| D3
    C5 -->|"Tier 2 Fallback: eth_call (balanceOf)"| D4
    C5 -->|"Honeypot Evaluation"| C3
    C7 --> C1

    E1 --> E2
    E2 --> C2
    E1 --> E3
    E3 -->|"PASS only"| E4

    style Clients fill:#0b1329,stroke:#00f0ff,color:#f8fafc
    style MCP fill:#1e1b4b,stroke:#818cf8,color:#f8fafc
    style Security fill:#064e3b,stroke:#10b981,color:#f8fafc
    style External fill:#3b0764,stroke:#d946ef,color:#f8fafc
    style SmartWallet fill:#1e293b,stroke:#94a3b8,color:#f8fafc
```

---

## Module Descriptions

### `src/plugin.mjs` — MCP Plugin and Tool Registry

The central orchestrator and MCP server. Exports:
- `plugin` — the MCP plugin manifest (`id: "payguard-paybox-plugin"`, version, tools array).
- `tools` — frozen array of 7 tool descriptors with JSON Schema input schemas:
  1. `payguard_check_payment_intent`
  2. `payguard_analyze_url`
  3. `payguard_prepare_threat_report`
  4. `payguard_inspect_calldata`
  5. `payguard_check_token_security`
  6. `payguard_check_address_security`
  7. `payguard_scan_wallet_tokens`
- `startMcpServer()` — JSON-RPC 2.0 stdio server handling `initialize`, `tools/list`, `tools/call`, and `ping`.
- Individual tool dispatchers routing parameters to domain-specific modules.

The stdio server auto-starts when `src/plugin.mjs` is executed directly or when `MCP_STDIO=1` is set in the environment.

---

### `src/wallet-token-scanner.mjs` — Base Wallet Token Scanner

Discovers and screens ERC-20 token holdings in any Base Mainnet (Chain ID 8453) wallet.

**Key Architecture Components:**
1. **Two-Tier Discovery:**
   - **Tier 1 (Blockscout API v2):** Attempts to fetch token holdings from `https://base.blockscout.com/api/v2/addresses/{address}/tokens?type=ERC-20`. When accessible, returns all arbitrary tokens.
   - **Tier 2 (RPC Multicall Fallback):** When indexers encounter rate limits or Cloudflare bot challenges, falls back to direct on-chain `eth_call` queries (`balanceOf(address)`) on `https://mainnet.base.org`. This fallback evaluates the 7 curated Base canonical tokens plus any caller-specified `customTokenAddresses`.
2. **Canonical Token Registry:** Authoritative mapping of official Base assets (WETH, USDC, cbETH, VIRTUAL, DAI, USDbC, AERO) with known contract addresses.
3. **Impersonation Detector (`checkTokenImpersonation`):** Identifies lookalike tokens that reuse well-known symbols while pointing to unauthorized contract addresses.
4. **GoPlus Security Bridge:** Evaluates honeypot flags, buy/sell taxes, and owner balance alteration privileges for every holding with non-zero balance.

---

### `src/calldata-inspector.mjs` — EVM Calldata Inspector

Pure, deterministic, synchronous EVM calldata analyzer with zero network dependencies.
- **Decodes Selectors:** `approve(address,uint256)`, `transfer(address,uint256)`, `transferFrom(address,address,uint256)`.
- **Unlimited Allowance Trap:** Flags `approve()` calls where amount equals `2^256 - 1` (`0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`).
- **Policy Enforcement:** Compares target spenders and recipients against caller-specified allowlists.
- **Fail-Closed:** Truncated calldata, invalid hex, or unknown selectors return structured `BLOCK` or `REVIEW` verdicts.

---

### `src/token-security.mjs` — GoPlus Token Security Integration

Interrogates the GoPlus Token Security API for Base Mainnet (Chain ID 8453):
- **Contract Risk Analysis:** Evaluates honeypots (`is_honeypot`), balance alteration (`owner_change_balance`), buy/sell taxes, pausable transfers, and unverified source code.
- **In-Memory Cache:** Caches successful responses for 10 minutes to protect upstream rate limits.
- **Fail-Closed Error Handling:** Network timeouts (3000ms), 429 rate limits, or malformed JSON return `UNVERIFIED` — never defaulting to `PASS`.

---

### `src/address-security.mjs` — GoPlus Address Security Integration

Interrogates the GoPlus Address Security API for Base Mainnet (Chain ID 8453):
- **Entity Screening:** Flags sanctioned addresses, phishing records, cybercrime involvement, mixer usage, and malicious contract creators.
- **Cache & Resilience:** In-memory caching and strict response payload size ceiling (64 KB).

---

### `src/smart-wallet.mjs` — Base Smart Wallet Pre-Signing Client

Wraps `@coinbase/wallet-sdk@4.4.0` with PayGuard's pre-signing security perimeter:
- Intercepts proposed transactions before `eth_sendTransaction` is called.
- Decodes candidate calldata using `inspectCalldata()`.
- Aborts automatically with `TransactionBlockedError` if the verdict is `BLOCK` or `REVIEW`.

---

### `server.mjs` — Operator Dashboard & HTTP REST Gateway

HTTP/1.1 microservice running with native Node.js ESM and zero external HTTP frameworks:
- **Routes Exposed:**
  - `GET /` — Service JSON manifest and endpoint directory (or interactive landing page for browser requests).
  - `GET /dashboard` — Interactive dark-theme operator security console (`public/index.html`).
  - `GET /docs` & `GET /whitepaper` & `GET /faq` — Lightweight documentation view.
  - `POST /api/analyze-url` — URL Sentinel scanner.
  - `POST /api/check-payment` — x402 payment intent policy evaluator.
  - `POST /api/threat-report` — Privacy-conscious threat report generator.
  - `POST /api/inspect-calldata` — Pre-signing calldata inspector.
  - `POST /api/token-security` — GoPlus Base token security auditor.
  - `POST /api/address-security` — GoPlus Base address security auditor.
  - `POST /api/scan-wallet-tokens` — Base wallet token scanner.
  - `GET /api/capabilities` — Service feature & provider status manifest.
  - `GET /health` — Read-only health probe.
  - `GET /metrics` — Prometheus metrics export.
  - `GET /.well-known/x402-bazaar.json` — PayBox Bazaar discovery metadata.
- **Security Protections:** In-memory sliding-window rate limiting (120 req/min/IP), 64 KB maximum request body ceiling, strict CORS headers, and anti-SSRF protections.
