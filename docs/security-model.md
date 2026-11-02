# PayGuard Security Model

## Overview

PayGuard is designed as a **read-only advisory sentinel**, not a transaction executor or policy enforcement gateway. This document defines the security boundaries, threat model, privacy guarantees, and known limitations of the system.

---

## Core Security Principles

### 1. Inspect, Never Act
PayGuard never:
- Signs or broadcasts transactions
- Requests or stores private keys, seed phrases, or mnemonics
- Executes payments or transfers
- Opens, fetches, or contacts the URL being analyzed
- Stores sensitive user data beyond the in-process request lifecycle

### 2. Fail Closed
Every error path in GoPlus integration returns `UNVERIFIED` — never `PASS`. A missing, unavailable, rate-limited, or malformed API response does **not** default to clearing an address or token as safe.

### 3. Minimal External Surface
The only outbound network calls PayGuard makes are:
- GoPlus Token Security API (opt-in, when `payguard_check_token_security` is called)
- GoPlus Address Security API (opt-in, when `payguard_check_address_security` is called)
- Google Web Risk API (opt-in, only when `checkReputation: true` is passed to URL Sentinel and `GOOGLE_WEB_RISK_API_KEY` is set)

All endpoints are fixed constants — no user-provided URLs are used for outbound API calls.

### 4. Credential Isolation
API keys (`GOOGLE_WEB_RISK_API_KEY`, `GOPLUS_API_KEY`) are:
- Loaded from server-side environment variables only
- Never included in tool output, JSON responses, or client-side bundles
- Never accepted as tool input parameters
- Sent as HTTP headers to fixed, trusted API endpoints only

---

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|-----------|
| Phishing URLs with homoglyph/lookalike domains | URL Sentinel Levenshtein + NFKC normalization checks |
| Bidi control characters hiding malicious URLs | Bidi scan runs **before** WHATWG URL parser |
| Full-width Unicode confusables in hostnames | NFKC normalization check on raw hostname |
| Punycode IDN label spoofing | `xn--` label detection |
| Embedded credentials in URLs (`user:pass@host`) | Credential check + redaction from displayed URL |
| ERC-20 unlimited approval attacks (`uint256.max`) | `approve()` calldata decode + `UNLIMITED_ALLOWANCE` risk factor |
| ERC-20 approval to unauthorized spender | `allowedSpenders` policy enforcement |
| Transfer to unauthorized recipient | `allowedRecipients` policy enforcement |
| Unknown/obfuscated EVM calldata | Unknown selectors return advisory `REVIEW` |
| Honeypot token contracts | GoPlus `is_honeypot` evaluation → `BLOCK` |
| High trading taxes / seller restrictions | GoPlus buy/sell tax evaluation |
| Sanctioned or criminally flagged addresses | GoPlus `sanctioned`, `phishing_activities`, `cybercrime` → `BLOCK` |
| x402 payment requirement manipulation | Intent policy comparison before signing |
| Payment amount exceeding user intent | `maxAmountAtomic` policy check |
| Payment to unauthorized recipient | `allowedPayTo` policy check |
| Wrong network or token | `allowedNetworks`, `allowedAssets` policy checks |
| Oversized API responses (potential DoS) | 64 KB hard limit on GoPlus responses |
| API request hangs | 3-second hard timeout on all GoPlus requests |
| GoPlus stale-cache false positives | Errors never cached; successful results cached 10 min |

### Out of Scope

| Threat | Why |
|--------|-----|
| EIP-712 typed-data manipulation | Not yet implemented |
| MEV / sandwich attacks | Chain-level analysis not performed |
| Bytecode-level proxy upgrade risk | Only `is_proxy` flag evaluated, not slot analysis |
| Social engineering beyond URL signals | No document or message content analysis |
| Wallet compromise | PayGuard does not control key management |
| Cross-chain replay attacks | Only Base Mainnet (8453) analyzed |
| On-chain transaction simulation | Not performed |
| Smart contract formal verification | Not in scope |

---

## URL Sentinel Privacy

The URL Sentinel performs analysis **entirely locally**:

- The submitted URL is parsed in-memory using the WHATWG URL API
- The target host is **never contacted**
- Query parameters, credentials, and fragments are **redacted** before any reputation check
- If Google Web Risk is configured and `checkReputation: true` is passed, only the normalized origin + path (without query parameters) is sent to Google's fixed API endpoint

```json
// Privacy metadata returned with every URL analysis
"privacy": {
  "urlOpened": false,
  "externalLookupPerformed": false,
  "queryParametersSentToReputationProvider": false,
  "pathSegmentsRedactedForReputationProvider": true
}
```

> [!WARNING]
> Even with path redaction, URL paths may still contain user-identifiable information (session tokens, IDs). Enable `checkReputation: true` only when sharing the URL path with Google is appropriate for the context.

---

## Pre-Signing Security Boundary

`requestTransaction()` in `src/smart-wallet.mjs` enforces a hard abort before `eth_sendTransaction` for any non-PASS verdict:

```
Transaction candidate
       ↓
inspectCalldata(tx, policy)
       ↓
verdict === "PASS"? ──No──→ { aborted: true, verdict, reasons }
       ↓ Yes                  ← Never reaches wallet
eth_sendTransaction (wallet prompt)
       ↓
User approves/rejects in wallet UI
```

This boundary applies only to transactions initiated through `requestTransaction()`. It does not restrict:
- Direct wallet calls from other code
- Other EIP-1193 providers not connected through PayGuard
- Transactions initiated outside PayGuard's scope

---

## GoPlus Intelligence Limitations

GoPlus intelligence is **advisory**, not authoritative:

1. **Database coverage**: Not all tokens and addresses are indexed. Absence of a record returns `UNVERIFIED`, not `PASS`.
2. **Indexing lag**: New scam tokens may not appear immediately in the GoPlus database.
3. **Base Sepolia excluded**: Testnet (84532) is not supported. All testnet checks return `UNSUPPORTED_CHAIN`.
4. **Free tier rate limits**: Without `GOPLUS_API_KEY`, requests are rate-limited. A `RATE_LIMITED` response returns `UNVERIFIED`.
5. **Third-party dependency**: PayGuard does not control GoPlus data quality or availability. The security posture of the application must not depend solely on this intelligence.
6. **Trust level**: GoPlus findings are one data point. They do not replace contract audits, formal verification, or community due diligence.

---

## Input Validation

All tools perform strict input validation before any processing:

| Module | Validation |
|--------|-----------|
| `payguard_analyze_url` | Max 2048-char URL; rejects non-string, empty, or oversized input |
| `payguard_check_payment_intent` | Max 64,000-char total input; strict JSON schema; integer-only amounts |
| `payguard_inspect_calldata` | `to` must match `/^0x[0-9a-fA-F]{40}$/`; `data` must be valid hex; value must be parseable as BigInt |
| `payguard_check_token_security` | Chain ID must be `8453`; contract address must match EVM format |
| `payguard_check_address_security` | Chain ID must be `8453`; address must match EVM format |

Malformed inputs return structured error responses — they never crash the MCP server.

---

## SSRF Protection

The URL Sentinel never opens submitted URLs. The only outbound calls are to fixed API endpoints:
- `https://webrisk.googleapis.com/v1/uris:search` (Web Risk, opt-in)
- `https://api.gopluslabs.io/api/v1/token_security/{chainId}` (GoPlus Token)
- `https://api.gopluslabs.io/api/v1/address_security/{address}` (GoPlus Address)

User-supplied URLs are **never used as fetch targets**. GoPlus endpoints are constructed from validated, normalized inputs using `encodeURIComponent()` — the user-supplied address or chain ID cannot alter the base endpoint.

---

## Advisory Nature of Verdicts

Every tool includes explicit communication that verdicts are advisory:

- `PASS` = policy checks matched. It does not authenticate the merchant, verify contract bytecode, or guarantee a payment is safe.
- `REVIEW` = suspicious signals. The calling agent or user must decide.
- `BLOCK` = high or critical risk. Within PayGuard-controlled paths (`requestTransaction()`), this aborts signing automatically. Outside those paths, enforcement is the caller's responsibility.
- `UNVERIFIED` = insufficient intelligence. Treat as unknown risk; do not proceed as if safe.

> [!CAUTION]
> Never treat a `PASS` verdict as a guarantee. PayGuard cannot verify merchant identity, contract bytecode correctness, or that a payment destination is legitimate.

---

## API Key Security

| Requirement | Implementation |
|-------------|---------------|
| Never hardcoded | All keys sourced from `process.env` only |
| Never in dist bundles | Verified by `Select-String` on dist files |
| Never in tool output | All tool response objects exclude key fields |
| Never accepted as input | No tool schema includes an API key parameter |
| Server-side only | Web Risk key read via `readWebRiskKey()` from env; GoPlus key from `process.env.GOPLUS_API_KEY` |
| Sent over TLS only | All external API calls use HTTPS |

---

## Rate Limiting and Resource Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| GoPlus request timeout | 3,000 ms | Prevent request hangs |
| GoPlus response size | 64 KB | Prevent memory exhaustion from oversized payloads |
| GoPlus cache TTL | 10 minutes | Reduce API load; balanced with freshness needs |
| URL input length | 2,048 chars | Prevent memory/parse exhaustion |
| Payment input size | 64,000 chars | Limit JSON parsing scope |
| Payment alternatives | 32 maximum | Bounded policy iteration |
| Trusted domains | 30 maximum | Bounded hostname comparison |

The HTTP server (`server.mjs`) additionally implements:
- Per-connection concurrency limits
- Sliding-window rate limiting per IP
- Prometheus metrics for observability
