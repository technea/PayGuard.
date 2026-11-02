# PayGuard Architecture

## Overview

PayGuard is a read-only, advisory Web3 security platform built with native Node.js ESM. It provides six MCP tools for AI agents and developers to inspect transactions, URLs, and token/address reputation before any signing action occurs.

The architecture follows a strict layering principle: **inspect first, never act**. No module contacts a blockchain, signs data, or broadcasts transactions.

---

## High-Level System Diagram

```mermaid
flowchart TD
    subgraph Clients["Clients"]
        A1["AI Agent / Claude / Cursor"]
        A2["Node.js Application"]
        A3["HTTP API Client"]
        A4["x402 Payment Client"]
    end

    subgraph MCP["MCP Layer — src/plugin.mjs"]
        B1["JSON-RPC 2.0 stdio server<br/>(startMcpServer)"]
        B2["Tool Registry<br/>(6 tools)"]
        B3["plugin.invokeTool()"]
    end

    subgraph Security["Security Engine — src/*.mjs"]
        C1["URL Sentinel<br/>analyzeUrlSecurity()"]
        C2["Calldata Inspector<br/>inspectCalldata()"]
        C3["Token Security<br/>checkTokenSecurity()"]
        C4["Address Security<br/>checkAddressSecurity()"]
        C5["Payment Intent<br/>evaluatePaymentIntent()"]
        C6["Threat Report<br/>prepareThreatReport()"]
    end

    subgraph External["External Providers (opt-in)"]
        D1["GoPlus Security API<br/>api.gopluslabs.io"]
        D2["Google Web Risk API<br/>webrisk.googleapis.com"]
    end

    subgraph SmartWallet["Smart Wallet Integration"]
        E1["createBaseSmartWalletClient()<br/>src/smart-wallet.mjs"]
        E2["inspectCandidate() → inspectCalldata()"]
        E3["requestTransaction()<br/>aborts on non-PASS"]
        E4["Coinbase Base Smart Wallet<br/>eth_sendTransaction"]
    end

    A1 -->|"stdin JSON-RPC"| B1
    A2 -->|"import plugin"| B2
    A3 -->|"HTTP POST"| B2
    A4 -->|"onBeforePaymentCreation hook"| C5

    B1 --> B3
    B2 --> B3
    B3 --> C1
    B3 --> C2
    B3 --> C3
    B3 --> C4
    B3 --> C5
    B3 --> C6

    C3 -->|"GET /token_security/chainId?contract_addresses=addr"| D1
    C4 -->|"GET /address_security/addr?chain_id=chainId"| D1
    C1 -->|"optional: GET /v1/uris:search"| D2
    C6 --> C1

    E1 --> E2
    E2 --> C2
    E1 --> E3
    E3 -->|"PASS only"| E4

    style Clients fill:#e8f4fd,stroke:#2196F3
    style MCP fill:#fff3e0,stroke:#FF9800
    style Security fill:#e8f5e9,stroke:#4CAF50
    style External fill:#fce4ec,stroke:#E91E63
    style SmartWallet fill:#f3e5f5,stroke:#9C27B0
```

---

## Module Descriptions

### `src/plugin.mjs` — MCP Plugin and Tool Registry

The central orchestrator. Exports:
- `plugin` — the MCP plugin manifest (id, name, version, tools array)
- `tools` — frozen array of 6 tool descriptors with JSON Schema input schemas
- `startMcpServer()` — JSON-RPC 2.0 stdio server handling `initialize`, `tools/list`, `tools/call`, and `ping`
- Individual tool handlers: `evaluatePaymentIntent`, `analyzeUrlSecurity`, `prepareThreatReport`, `payGuardInspectCalldata`, `payGuardCheckTokenSecurity`, `payGuardCheckAddressSecurity`

The stdio server is auto-started when the file is executed directly or when `MCP_STDIO=1` is set.

### `src/calldata-inspector.mjs` — EVM Calldata Inspector

Pure, deterministic, synchronous analysis. No network calls. Exports:
- `inspectCalldata(tx, policy)` — decodes EVM transaction calldata and evaluates it
- `SELECTORS` — ERC-20 selector constants (`approve`, `transfer`, `transferFrom`)
- `UINT256_MAX` — bigint constant for unlimited allowance detection

Supported operations: `ERC20_APPROVE`, `ERC20_TRANSFER`, `ERC20_TRANSFER_FROM`, `NATIVE_TRANSFER`, `UNKNOWN_OPERATION`.

### `src/token-security.mjs` — GoPlus Token Security

Async, network-touching. Base Mainnet (8453) only. Exports:
- `checkTokenSecurity({ chainId, contractAddress, fetchImpl, timeoutMs, apiKey })`
- `evaluateTokenSecurityData(rawToken, chainId, contractAddress)` — pure evaluation function
- Cache helpers: `clearTokenCache()`, `getTokenCacheSize()`

**Endpoint:** `GET https://api.gopluslabs.io/api/v1/token_security/{chainId}?contract_addresses={address}`

### `src/address-security.mjs` — GoPlus Address Security

Async, network-touching. Base Mainnet (8453) only. Exports:
- `checkAddressSecurity({ chainId, address, fetchImpl, timeoutMs, apiKey })`
- `evaluateAddressSecurityData(rawResult, chainId, address)` — pure evaluation function
- Cache helpers: `clearAddressCache()`, `getAddressCacheSize()`

**Endpoint:** `GET https://api.gopluslabs.io/api/v1/address_security/{address}?chain_id={chainId}`

> [!NOTE]
> The URL structure differs from Token Security: the **address is a path segment** in Address Security, while **chainId is a path segment** in Token Security.

### `src/smart-wallet.mjs` — Base Smart Wallet Integration

Exports `createBaseSmartWalletClient(options)` which returns a client object with:
- `connect(provider)` — EIP-1193 `eth_requestAccounts` (no keys)
- `switchChain(chainId, provider)` — `wallet_switchEthereumChain`
- `inspectCandidate(tx, policy)` — delegates to `inspectCalldata()`
- `requestTransaction(tx, options)` — inspects, aborts on non-PASS, then calls `eth_sendTransaction`
- `disconnect(provider)` — best-effort cleanup

### `server.mjs` — Local HTTP API Server

An HTTP wrapper for local development. Implements:
- Request concurrency limits
- Sliding-window rate limiting
- Prometheus metrics (`/metrics`)
- Routes for each security tool

Does not execute payments or contact blockchains.

---

## Data Flow: URL Sentinel

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant Plugin as plugin.mjs
    participant Sentinel as analyzeUrlSecurity()
    participant WebRisk as Google Web Risk (opt-in)

    Agent->>Plugin: tools/call payguard_analyze_url { url, expectedDomain }
    Plugin->>Sentinel: analyzeUrlSecurity(input)

    Note over Sentinel: 1. Bidi control char scan (raw URL, before parser)
    Note over Sentinel: 2. WHATWG URL parse
    Note over Sentinel: 3. Credential, port, IP, IDN checks
    Note over Sentinel: 4. Hostname vs trustedDomains match
    Note over Sentinel: 5. Full-width/NFKC confusable check
    Note over Sentinel: 6. Wallet-secret language scan

    alt checkReputation: true AND GOOGLE_WEB_RISK_API_KEY set
        Sentinel->>WebRisk: GET /v1/uris:search (no query params)
        WebRisk-->>Sentinel: threat match or no-match
    end

    Sentinel-->>Plugin: { verdict, riskLevel, checks, hostname, ... }
    Plugin-->>Agent: JSON-RPC result
```

---

## Data Flow: Pre-Signing Transaction Inspection

```mermaid
sequenceDiagram
    participant Agent as AI Agent / dApp
    participant SW as smart-wallet.mjs
    participant Inspector as calldata-inspector.mjs
    participant Wallet as Base Smart Wallet

    Agent->>SW: requestTransaction(tx, { policy })
    SW->>Inspector: inspectCalldata(tx, policy)
    Inspector-->>SW: { verdict, riskLevel, operation, checks, ... }

    alt verdict === "PASS"
        SW->>Wallet: eth_sendTransaction
        Wallet-->>SW: txHash
        SW-->>Agent: { aborted: false, txHash }
    else verdict === "REVIEW" or "BLOCK"
        SW-->>Agent: { aborted: true, verdict, reasons, checks }
        Note over SW: Never reaches wallet
    end
```

---

## Data Flow: GoPlus Token/Address Security

```mermaid
sequenceDiagram
    participant Tool as MCP Tool
    participant Module as token-security.mjs
    participant Cache as In-memory Cache
    participant GoPlus as GoPlus API

    Tool->>Module: checkTokenSecurity({ chainId, contractAddress })
    Module->>Module: Validate chain (8453 only) + address format
    Module->>Cache: Cache lookup (10-min TTL)

    alt Cache hit
        Cache-->>Tool: cached result (cached: true)
    else Cache miss
        Module->>GoPlus: GET /token_security/8453?contract_addresses=addr
        Note over GoPlus: 3s timeout, 64KB limit
        GoPlus-->>Module: JSON response
        Module->>Module: evaluateTokenSecurityData()
        Module->>Cache: Store result (errors NOT cached)
        Module-->>Tool: evaluated result
    end
```

---

## Build Pipeline

```mermaid
flowchart LR
    S1["src/plugin.mjs"] --> B["scripts/build.mjs"]
    S2["src/calldata-inspector.mjs"] --> B
    S3["src/token-security.mjs"] --> B
    S4["src/address-security.mjs"] --> B

    B --> D1["dist/plugin.mjs (ESM)"]
    B --> D2["dist/plugin.cjs (CJS)"]
    B --> D3["dist/plugin.js (UMD)"]
    B --> D4["dist/index.mjs / .cjs / .js"]
    B --> D5["dist/index.d.ts (TypeScript)"]
    B --> D6["dist/calldata-inspector.mjs/.cjs"]
    B --> D7["dist/token-security.mjs/.cjs"]
    B --> D8["dist/address-security.mjs/.cjs"]

    B --> V["Verify: 6 tools exposed"]
```

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Node.js 20+ (native ESM) |
| Test runner | `node --test` (built-in) |
| Network | Native `fetch` + `AbortController` |
| EVM address handling | Native JavaScript BigInt + regex |
| Smart Wallet SDK | `@coinbase/wallet-sdk` 4.4.0 |
| x402 hook | `@x402/core` 2.29.0 (devDependency) |
| Containerization | Docker + docker-compose |
| Observability | Prometheus + Grafana + k6 |
| CI | GitHub Actions |

**Zero external runtime dependencies** in the core security analysis modules (calldata inspector, URL sentinel, payment intent, threat report).

---

## Security Architecture Properties

1. **Fail-closed**: GoPlus errors → `UNVERIFIED`, never `PASS`
2. **No outbound requests in core**: URL Sentinel, calldata inspector, and payment intent guard make no network calls
3. **Injectable fetch**: `fetchImpl` parameter allows deterministic offline testing without mocking globals
4. **Fixed endpoints**: GoPlus and Web Risk URLs are hardcoded constants — never user-controlled
5. **Input size limits**: 64,000 chars max for URL input; 64 KB max for GoPlus API response bodies
6. **Cache isolation**: Successful GoPlus results cached 10 min; errors never cached (avoids stale false PASSes)
7. **API keys**: Server-side env vars only; never in tool output, logs, or client bundles
8. **Pre-signing abort**: `requestTransaction()` aborts before `eth_sendTransaction` for any non-PASS verdict
