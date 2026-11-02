# PayGuard Technical Whitepaper

**Version 0.1.0 | November 2026**
*Branch: feat/base-smart-wallet-sdk | Repository: github.com/technea/PayGuard*

---

## Abstract

PayGuard is a read-only, advisory Web3 security platform designed for AI agents and developers operating on the Base blockchain ecosystem. It provides structured security intelligence — not enforcement — through six Model Context Protocol (MCP) tools covering URL phishing analysis, EVM transaction calldata inspection, x402 payment policy validation, privacy-conscious threat reporting, and on-chain reputation via the GoPlus Security API. All analysis is deterministic and performed without signing, broadcasting, or requesting private keys. This paper describes the architecture, threat model, implementation, security boundaries, and evaluation of the current system.

---

## 1. Problem Statement

The proliferation of AI agents with financial autonomy over EVM wallets creates a new, underexplored attack surface. An AI agent capable of authorizing payments, approving token allowances, or interacting with DeFi protocols requires the same security protections as a human user — but lacks the visual inspection, skepticism, and institutional knowledge that an experienced human brings.

Existing phishing, token risk, and transaction analysis tools are built for browser-based human users. They rely on visual inspection, browser extensions, and manual verification steps. They are not designed for machine-readable integration with AI agent frameworks.

The result is a gap: AI agents can be manipulated by the same threats that harm human users, with fewer available mitigations and no intuitive judgment.

### 1.1 Concrete Attack Scenarios

**Scenario A — URL Manipulation:**
An agent is instructed to visit a payment page at `https://paybox.com/checkout`. The instruction actually contains `https://pa‌y‌b‌o‌x‌.‌com/checkout` with embedded Unicode Bidi control characters (U+200C, U+202E) that make the URL appear identical to a human but resolve to a malicious domain.

**Scenario B — Unlimited Token Approval:**
A DeFi protocol requests an ERC-20 `approve(spender, 2^256 - 1)` from an agent. The agent cannot see that "unlimited approval" is being granted to an address it has never interacted with. The agent signs without question.

**Scenario C — Honeypot Token:**
An agent is instructed to purchase a token. The token contract allows buying but uses contract logic to prevent selling. The agent cannot detect this from the transaction calldata alone without external intelligence.

**Scenario D — Payment Manipulation:**
An x402 payment challenge offers multiple payment alternatives. One has a trusted recipient; others route funds to attacker-controlled addresses. An insufficiently validated agent selects the wrong alternative.

---

## 2. Motivation and Target Users

### Primary Users

1. **AI agents** (Claude, Cursor, autonomous agents) that need machine-readable security verdicts before signing transactions or following payment instructions
2. **dApp developers** building Base-native applications who need a programmable security layer before wallet interactions
3. **x402 payment integrators** who need policy validation before payment creation
4. **Security-conscious users** who want a structured second opinion on URLs, token contracts, or counterparty addresses

### Design Motivation

- Existing security tools are not MCP-native
- No single tool covers URL, calldata, token, and address intelligence together
- The industry lacks clear patterns for AI agent security in financial contexts
- x402 is an emerging standard requiring new client-side safety tooling

---

## 3. Threat Model

### 3.1 Assets Protected

- User token balances (via pre-signing calldata inspection)
- User payment amounts, recipients, and networks (via x402 policy validation)
- Agent decision quality (via structured security findings)

### 3.2 Trusted Boundary

PayGuard trusts:
- The Node.js runtime and its standard library
- The GoPlus Security API (external intelligence provider)
- The Google Web Risk API (optional reputation lookup)

PayGuard does **not** trust:
- The URL submitted by the user or agent
- The EVM calldata submitted for inspection
- The x402 payment requirement payload
- GoPlus data as ground truth (it is one data source, not an authoritative oracle)

### 3.3 Attacker Capabilities Considered

| Capability | Mitigated? |
|-----------|-----------|
| Supply a URL with invisible Unicode Bidi controls | ✅ (Bidi scan before parser) |
| Supply a URL with full-width confusable characters | ✅ (NFKC normalization check) |
| Supply a URL with lookalike domain name | ✅ (Levenshtein distance check) |
| Supply malformed or oversized URL | ✅ (input validation + size limits) |
| Supply calldata for unlimited ERC-20 approval | ✅ (uint256.max detection) |
| Supply truncated or malformed calldata | ✅ (structured BLOCK/REVIEW with reason) |
| Supply an x402 payload with wrong recipient | ✅ (allowedPayTo policy) |
| Supply an x402 payload with excessive amount | ✅ (maxAmountAtomic policy) |
| Deploy a honeypot token contract | ✅ (GoPlus intelligence, advisory) |
| Use a sanctioned/phishing address as a counterparty | ✅ (GoPlus intelligence, advisory) |
| Cause GoPlus to return malformed JSON | ✅ (UNVERIFIED, never PASS) |
| Flood the GoPlus endpoint to cause timeouts | ✅ (UNVERIFIED, caching) |
| Cause oversized GoPlus response | ✅ (64 KB hard limit) |

### 3.4 Out of Scope

- EIP-712 typed-data and permit attacks
- MEV, sandwich, and front-running attacks
- Social engineering beyond URL signal detection
- Contract formal verification
- On-chain transaction simulation
- Key management or wallet security

---

## 4. Design Principles and Non-Goals

### 4.1 Design Principles

**Inspect, Never Act**
PayGuard's security modules perform zero writes, zero signing, and zero network requests to the target system. They observe and report.

**Fail Closed**
Every error, unavailability, or partial data condition resolves to `UNVERIFIED` — never to `PASS`. An agent receiving `UNVERIFIED` knows the system could not establish safety, not that safety was established.

**Minimal External Surface**
The only outbound calls are to three fixed, well-known external APIs (GoPlus Token, GoPlus Address, Google Web Risk). All endpoints are hardcoded constants; no user-supplied URL is used as a fetch target.

**Deterministic Evaluation**
Security evaluation logic (`evaluateTokenSecurityData`, `evaluateAddressSecurityData`, `inspectCalldata`) is pure — same inputs produce same outputs. This enables deterministic test coverage without live API calls.

**Separation of Analysis from Distribution**
The source analysis modules (`src/*.mjs`) have zero external runtime dependencies. External intelligence (GoPlus) is layered on top via injectable fetch implementations.

**Advisory Transparency**
Every tool response explicitly communicates:
- What was checked
- What was not checked
- That the verdict is advisory, not proof of safety

### 4.2 Non-Goals

PayGuard explicitly does not:
- Sign, broadcast, or authorize transactions
- Store private keys, seed phrases, or mnemonics
- Provide financial advice
- Replace smart contract audits or formal verification
- Guarantee that a `PASS` verdict means an interaction is safe
- Provide a complete security solution in isolation

---

## 5. PayGuard Architecture

### 5.1 Module Overview

```
src/
  plugin.mjs            MCP plugin manifest, tool registry, stdio server
  calldata-inspector.mjs Pure EVM calldata decoder and risk evaluator
  token-security.mjs    GoPlus Token Security client (Base Mainnet)
  address-security.mjs  GoPlus Address Security client (Base Mainnet)
  smart-wallet.mjs      Coinbase Base Smart Wallet adapter + pre-signing hook
```

### 5.2 MCP Layer

The MCP layer (`src/plugin.mjs`) implements JSON-RPC 2.0 protocol version 2024-11-05 over stdin/stdout. It supports both newline-delimited and Content-Length framed message formats for compatibility with different hosts.

The server handles:
- `initialize` — capability negotiation and server identification
- `tools/list` — returns all 6 tool descriptors with JSON Schema input schemas
- `tools/call` — dispatches to the appropriate tool handler
- `ping` — health check

MCP errors are returned as structured JSON-RPC error responses. Tool-level errors are returned as `isError: true` content responses — the server never crashes on malformed input.

### 5.3 Distribution Format

The build pipeline (`scripts/build.mjs`) produces:

| Artifact | Format | Use Case |
|----------|--------|----------|
| `dist/plugin.mjs` | ESM | MCP host import, Node.js ESM |
| `dist/plugin.cjs` | CommonJS | Legacy Node.js `require()` |
| `dist/plugin.js` | UMD | Broad compatibility |
| `dist/index.mjs/.cjs/.js` | ESM/CJS/UMD | SDK index |
| `dist/index.d.ts` | TypeScript | Type checking |
| `dist/calldata-inspector.mjs/.cjs` | ESM/CJS | Standalone use |
| `dist/token-security.mjs/.cjs` | ESM/CJS | Standalone use |
| `dist/address-security.mjs/.cjs` | ESM/CJS | Standalone use |

---

## 6. Security Modules and Workflow

### 6.1 URL Sentinel

The URL Sentinel performs a multi-stage, local analysis of a user-supplied URL without fetching it.

**Stage 1: Bidi Control Scan (pre-parser)**
The raw URL string is scanned for Unicode bidirectional formatting controls before any parsing. Detected ranges:
- U+061C (Arabic Letter Mark)
- U+200E, U+200F (LTR/RTL Marks)
- U+202A–202E (Embedding/Override controls)
- U+2066–2069 (Isolate/Pop controls)

This stage runs before the WHATWG URL parser so that Bidi characters which cause parse failure are still detected and reported.

**Stage 2: WHATWG URL Parsing**
The URL is parsed using the platform's URL API. Failure returns `SUSPICIOUS` with the Bidi findings already accumulated.

**Stage 3: Structural Checks**
- Embedded credentials (user:pass@host)
- Non-HTTPS scheme
- Non-standard ports
- IP-literal hosts
- Punycode IDN labels
- URL shortener domains
- Local/internal hostnames

**Stage 4: Domain Intelligence**
- Trusted domain matching (exact hostname or subdomain)
- Levenshtein distance from trusted domains (detects one-character substitutions)
- PayBox brand impersonation detection

**Stage 5: Unicode Normalization**
NFKC normalization is applied to the raw hostname. If normalization changes the hostname (indicating full-width or compatibility confusable characters), a HIGH severity finding is generated.

**Stage 6: Content Signals**
URL path and query string are scanned for wallet-secret terminology and external redirect parameters.

**Stage 7: Optional Reputation Lookup**
If `checkReputation: true` and `GOOGLE_WEB_RISK_API_KEY` is configured, a query is made to Google Web Risk with the normalized origin + path (without query parameters).

### 6.2 EVM Calldata Inspector

The calldata inspector is a pure, synchronous function requiring no network access and no private keys.

**Input validation:**
1. `to` must be a valid 20-byte EVM address
2. `value` must be parseable as a non-negative BigInt
3. `data` must be a valid 0x-prefixed hex string

**Calldata analysis:**
1. Empty data (`0x`) → `NATIVE_TRANSFER`
2. Data < 4 bytes → `TRUNCATED_CALLDATA` (REVIEW)
3. Known selector → specific decoding (approve, transfer, transferFrom)
4. Unknown selector → `UNKNOWN_OPERATION` (REVIEW, advisory)

**ERC-20 `approve()` analysis:**
- ABI-decodes spender (address) and amount (uint256)
- `uint256.max` (2^256 - 1) → `UNLIMITED_ALLOWANCE_UINT256_MAX` (REVIEW)
- Amount > 2^255 → `UNUSUALLY_LARGE_ALLOWANCE` (REVIEW)
- Spender not in `allowedSpenders` → `SPENDER_NOT_IN_ALLOWLIST` (BLOCK)
- Amount > `maxAllowance` → `ALLOWANCE_EXCEEDS_POLICY_MAX` (BLOCK)

**ERC-20 `transfer()` / `transferFrom()` analysis:**
- ABI-decodes recipient and amount
- Recipient not in `allowedRecipients` → `RECIPIENT_NOT_IN_ALLOWLIST` (BLOCK)
- Amount > `maxTransferAmount` → `TRANSFER_EXCEEDS_POLICY_MAX` (BLOCK)

### 6.3 GoPlus Token Security

The token security module queries the GoPlus API and translates the response into PayGuard's verdict model.

**Request flow:**
1. Validate chain ID (8453 only)
2. Validate contract address format
3. Check in-memory cache (10-min TTL)
4. Build request URL (fixed base endpoint + URI-encoded inputs)
5. Execute with 3s timeout and abort controller
6. Validate HTTP status (429 → RATE_LIMITED; 401/403 → AUTH_FAILED; 5xx → UPSTREAM_ERROR)
7. Limit response to 64 KB
8. Parse JSON
9. Extract token data from result map
10. Evaluate using `evaluateTokenSecurityData()`
11. Cache successful result

**Verdict derivation:**
- Any critical finding → BLOCK / CRITICAL
- Any high finding → BLOCK / HIGH
- Medium findings only → REVIEW / MEDIUM
- No findings → PASS / LOW

### 6.4 GoPlus Address Security

Similar to Token Security but with a different endpoint structure:

```
GET https://api.gopluslabs.io/api/v1/address_security/{address}?chain_id={chainId}
```

The address is a path parameter; chain_id is a query parameter. The response `result` object is a flat dictionary of risk flags (not a nested map by address).

Evaluated categories:
- Critical: phishing, theft, sanctions, malicious contract deployment (≥3)
- High: blacklist, honeypot affiliation, fake tokens, cybercrime, money laundering, financial crime, blackmail, malicious contracts (1–2)
- Medium: darkweb transactions, mixer usage, fake KYC, gas abuse, malicious mining

### 6.5 x402 Payment Intent Guard

The payment guard validates an x402 payment requirement against a user-supplied intent policy:

1. Parse and canonicalize the intent (HTTPS URL normalization, lowercase addresses, integer amount parsing)
2. For each `accepts` candidate: check network, asset, payTo, amount, scheme, timeout
3. PASS requires at least one fully clean candidate and no partially-matching dangerous candidate
4. Conflicting `amount`/`maxAmountRequired` fields → BLOCK
5. Incomplete policy → REVIEW

### 6.6 Pre-Signing Integration (Base Smart Wallet)

`requestTransaction()` in `src/smart-wallet.mjs` enforces inspection before signing:

```javascript
// Pseudocode representation of the signing flow
async function requestTransaction(tx, options) {
  const inspection = inspectCalldata(tx, options.policy);

  if (inspection.verdict !== "PASS") {
    return { aborted: true, verdict: inspection.verdict, ... };
    // eth_sendTransaction is NEVER called
  }

  const txHash = await provider.request({
    method: "eth_sendTransaction",
    params: [tx]
  });

  return { aborted: false, txHash, ... };
}
```

User wallet rejection (error code 4001) after a PASS inspection is handled gracefully as `REJECTED_BY_USER` with `riskLevel: LOW`.

---

## 7. Risk Evaluation and Verdict Model

### 7.1 Verdict Semantics

| Verdict | Source | Meaning |
|---------|--------|---------|
| `PASS` | All modules | All configured checks passed. Not a safety guarantee. |
| `REVIEW` | All modules | Risk signals present. Agent/user must decide. |
| `BLOCK` | Calldata, Token, Address | High or critical risk. PayGuard signing paths abort. |
| `UNVERIFIED` | Token, Address, URL (error) | Insufficient data. Treat as unknown risk. |
| `SUSPICIOUS` | URL Sentinel | Significant heuristic warnings. |
| `CAUTION` | URL Sentinel | Moderate signals; exercise caution. |
| `KNOWN_MALICIOUS` | URL Sentinel | Threat intelligence match confirmed. |
| `EXPECTED_DOMAIN_MATCH` | URL Sentinel | Matched user-supplied trusted domain. |
| `NO_KNOWN_THREAT` | URL Sentinel | No threat match found (not proof of safety). |

### 7.2 Risk Level Matrix

| Severity | Meaning |
|----------|---------|
| `CRITICAL` | Confirmed severe threat (honeypot, sanctions, phishing match, malicious contracts) |
| `HIGH` | Significant risk (unauthorized spender, money laundering, blacklist, excessive tax) |
| `MEDIUM` | Advisory concern (unlimited allowance, mixer usage, darkweb interaction) |
| `LOW` | No significant signals |
| `UNKNOWN` | Cannot assess (data unavailable, unsupported chain) |

### 7.3 Error Code Taxonomy (GoPlus)

| Code | Trigger |
|------|---------|
| `UNSUPPORTED_CHAIN` | Chain ID ≠ 8453 |
| `INVALID_CONTRACT_ADDRESS` / `INVALID_ADDRESS` | Format validation failure |
| `REQUEST_TIMEOUT` | 3s timeout exceeded |
| `NETWORK_ERROR` | Connection failure |
| `RATE_LIMITED` | HTTP 429 |
| `AUTH_FAILED` | HTTP 401/403 |
| `UPSTREAM_ERROR` | HTTP 5xx |
| `MALFORMED_JSON` | JSON parse failure |
| `OVERSIZED_RESPONSE` | > 64 KB |
| `UNINDEXED_TOKEN` / `EMPTY_RESULT` | Not in GoPlus database |
| `PROVIDER_ERROR_CODE` | GoPlus API-level error code |
| `FETCH_UNAVAILABLE` | No fetch implementation available |

All codes produce `UNVERIFIED` verdict.

---

## 8. Base Ecosystem Integration

### 8.1 Base Mainnet Support

GoPlus intelligence is verified for Base Mainnet (chain ID 8453). Both Token Security and Address Security endpoints have been tested against this chain. The GoPlus API supports keyless free-tier access for chain ID 8453.

### 8.2 Base Sepolia Exclusion

Base Sepolia (chain ID 84532) is not indexed by GoPlus. All requests for this testnet return `UNSUPPORTED_CHAIN`. This is a GoPlus database limitation, not a PayGuard implementation choice. Testnet tokens do not have real economic risk, making this an acceptable limitation.

### 8.3 Coinbase Base Smart Wallet Integration

`src/smart-wallet.mjs` wraps `@coinbase/wallet-sdk` v4.4.0 (Coinbase Developer Platform). The integration:
- Implements `eth_requestAccounts` for connection (no keys)
- Implements `wallet_switchEthereumChain` / `wallet_addEthereumChain` for Base Sepolia
- Adds `inspectCandidate()` and `requestTransaction()` as security-aware wrappers
- Gracefully handles environments without browser globals (Node.js unit testing)

### 8.4 x402 Protocol Integration

PayGuard integrates with `@x402/core` v2.29.0 via the `onBeforePaymentCreation` hook. The integration:
- Evaluates the selected payment requirement against the user's intent policy
- Aborts payment creation for both BLOCK and REVIEW verdicts
- Accepts policy values only from trusted configuration sources

---

## 9. Security Boundaries and Privacy

### 9.1 No Signing, No Broadcasting

PayGuard contains no private key material, no signing logic, and no broadcasting code. The `eth_sendTransaction` call in `requestTransaction()` is a request to the user's wallet provider — the wallet controls signing.

### 9.2 API Credential Isolation

All API credentials are:
- Server-side environment variables only
- Never in tool input schemas
- Never in tool output fields
- Never in client-side bundles (verified by static analysis of dist files)

### 9.3 URL Privacy

- The submitted URL is never fetched
- Query parameters are removed before any reputation lookup
- Credentials embedded in URLs are removed before display
- The privacy metadata block in every URL response explicitly declares what was and was not shared externally

### 9.4 No Persistent Storage

PayGuard stores nothing to disk. The GoPlus in-memory cache holds successful evaluation results for 10 minutes within the process lifetime and resets on restart. No user data, URLs, addresses, or verdicts are persisted.

### 9.5 SSRF Prevention

User-supplied URLs are never used as outbound fetch targets. External API URLs are hardcoded constants built from validated, URI-encoded inputs:

```javascript
// Token Security — chainId is URI-encoded path segment, address is URI-encoded query
const url = `${ENDPOINT}/${encodeURIComponent(normChain)}?contract_addresses=${encodeURIComponent(normAddress)}`;

// Address Security — address is URI-encoded path segment, chainId is URI-encoded query
const url = `${ENDPOINT}/${encodeURIComponent(normAddress)}?chain_id=${encodeURIComponent(normChain)}`;
```

Neither `normChain` nor `normAddress` can contain path traversal sequences because they are validated against strict regex patterns (`/^[0-9]+$/` for chain IDs, `/^0x[0-9a-fA-F]{40}$/` for addresses) before URL construction.

---

## 10. Testing and Evaluation Evidence

### 10.1 Test Suite Summary

| Module | Test File | Tests | Coverage |
|--------|-----------|-------|---------|
| x402 payment guard | `test/paybox.test.mjs` | ~28 | x402 validation, MCP dispatch, tool count |
| URL Sentinel | `test/plugin.test.mjs` | ~50 | Phishing, IDN, Bidi, NFKC, calldata tool, GoPlus tools |
| Calldata Inspector | `test/calldata-inspector.test.mjs` | 9 | ERC-20 ops, malformed inputs, policy enforcement |
| Base Smart Wallet | `test/smart-wallet.test.mjs` | ~37 | Connection, pre-signing flow, wallet rejection |
| Token Security | `test/token-security.test.mjs` | 19 | GoPlus responses, error codes, cache behavior |
| Address Security | `test/address-security.test.mjs` | 17 | Risk flags, error codes, endpoint format, cache |
| **Total** | | **143** | **143 passing, 0 failing** |

### 10.2 Adversarial Test Coverage

The test suite covers the following adversarial scenarios (verified by running `npm test`):

**URL Sentinel adversarial:**
- U+202E Right-to-Left Override in raw URL → detected before parser
- U+2069 Pop Directional Isolate in hostname → detected
- Mixed Bidi controls (U+200F + U+202A) → detected
- Valid RTL domains (Arabic, Hebrew character sequences) → not false-positived
- Full-width confusable `ｐａｙｂｏｘ.sh` vs `paybox.sh` → NFKC check catches

**Calldata inspector adversarial:**
- `approve()` with `uint256.max` → REVIEW
- `approve()` with bounded allowance → PASS
- Truncated calldata (< 4 bytes) → REVIEW
- Malformed hex data → BLOCK
- Invalid `to` address → BLOCK
- Unapproved spender → BLOCK
- Amount exceeding policy max → BLOCK
- Unknown selector → REVIEW (advisory)

**GoPlus adversarial:**
- Empty result → UNVERIFIED (fail-closed)
- Timeout → UNVERIFIED / REQUEST_TIMEOUT
- Network error → UNVERIFIED / NETWORK_ERROR
- HTTP 429 → UNVERIFIED / RATE_LIMITED
- HTTP 500 → UNVERIFIED / UPSTREAM_ERROR
- Malformed JSON → UNVERIFIED / MALFORMED_JSON
- Response > 64 KB → UNVERIFIED / OVERSIZED_RESPONSE
- Invalid address format → UNVERIFIED / INVALID_ADDRESS
- Unsupported chain → UNVERIFIED / UNSUPPORTED_CHAIN
- Cache hit avoids repeat fetch; error responses not cached

### 10.3 Build Verification

```
npm run build
→ Verified dist/plugin.mjs (6 tools exposed).
→ Build completed successfully: bundled ESM, CJS, DTS, and stdio MCP server.
```

### 10.4 Security Boundary Verification

Verified during final phase testing:
- `analyzeUrlSecurity({ url: 'http://localhost/steal' })` → `paymentExecuted: false` (SSRF protection)
- `GOPLUS_API_KEY` appears only as `process.env.GOPLUS_API_KEY` in dist files (no hardcoding)
- No signing, broadcasting, or key-handling code in any source module

---

## 11. Limitations

See `docs/limitations-roadmap.md` for the complete list. Key limitations:

1. GoPlus supports Base Mainnet only (8453); testnet not indexed
2. Calldata inspector recognizes 3 ERC-20 selectors; unknown selectors yield advisory REVIEW
3. No EIP-712 typed-data, permit, or multicall inspection
4. No on-chain simulation or state-dependent analysis
5. GoPlus data quality not independently verified
6. Pre-signing enforcement applies only to `requestTransaction()` in PayGuard's Smart Wallet client
7. In-memory cache resets on process restart

---

## 12. Future Roadmap

Potential directions (not commitments):

**Near-term:**
- EIP-712 typed-data and permit inspection
- Expanded calldata selector library (swap, NFT approvals)
- Persistent GoPlus cache backend

**Medium-term:**
- Multi-chain GoPlus support
- On-chain simulation integration
- Structured audit log
- Browser extension

**Deferred:**
- Non-EVM chain support (NEAR, etc.)
- Production custody or signing
- Paid credit/billing systems
- Mainnet payment enforcement

---

## 13. Conclusion

PayGuard provides a focused, honest, and testable layer of advisory security intelligence for AI agents and developers operating in the Base Web3 ecosystem. Its architecture prioritizes correctness over completeness: it is better to return `UNVERIFIED` than to return a false `PASS`. Its six MCP tools cover the most common attack surfaces in the current Base agent payment workflow. Its 143-test suite, zero-dependency core, fail-closed error handling, and clear security boundaries make it a reliable advisory component in a multi-layer security architecture.

PayGuard is not a complete security solution. It is one well-defined, trustworthy layer.

---

## Appendix: Key Technical Constants

| Constant | Value | Source |
|----------|-------|--------|
| GoPlus Token Security endpoint | `https://api.gopluslabs.io/api/v1/token_security` | `src/token-security.mjs:17` |
| GoPlus Address Security endpoint | `https://api.gopluslabs.io/api/v1/address_security` | `src/address-security.mjs:19` |
| Supported chain ID | `8453` (Base Mainnet) | Both GoPlus modules |
| GoPlus request timeout | 3,000 ms | Both GoPlus modules |
| GoPlus response size limit | 65,536 bytes (64 KB) | Both GoPlus modules |
| GoPlus cache TTL | 600,000 ms (10 min) | Both GoPlus modules |
| URL input limit | 2,048 characters | `src/plugin.mjs` |
| Payment input limit | 64,000 characters | `src/plugin.mjs` |
| ERC-20 approve selector | `0x095ea7b3` | `src/calldata-inspector.mjs:18` |
| ERC-20 transfer selector | `0xa9059cbb` | `src/calldata-inspector.mjs:19` |
| ERC-20 transferFrom selector | `0x23b872dd` | `src/calldata-inspector.mjs:20` |
| uint256.max | `2^256 - 1` | `src/calldata-inspector.mjs:14` |
| MCP protocol version | `2024-11-05` | `src/plugin.mjs:1191` |
| x402 core version (dev) | `2.29.0` | `package.json` |
| Coinbase Wallet SDK version | `4.4.0` | `package.json` |
