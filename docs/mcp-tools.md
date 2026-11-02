# PayGuard MCP Tools Reference

PayGuard exposes six Model Context Protocol (MCP) tools. All tools return structured JSON with a **verdict**, **riskLevel**, and **findings** or **checks** array. All tools are advisory — they do not execute payments, sign transactions, or block wallet operations outside of PayGuard-controlled paths.

---

## Verdict and Risk Level Reference

### Verdicts

| Verdict | Description |
|---------|-------------|
| `PASS` | All configured checks passed. Advisory only — does not guarantee safety. |
| `REVIEW` | Risk signals detected. Human or agent review required before proceeding. |
| `BLOCK` | High or critical risk. PayGuard-controlled signing paths abort automatically. |
| `UNVERIFIED` | Insufficient data or provider unavailable. Treat as unknown risk — never as safe. |
| `SUSPICIOUS` | URL Sentinel: significant heuristic warning signals. |
| `CAUTION` | URL Sentinel: moderate signals; exercise caution. |
| `KNOWN_MALICIOUS` | URL Sentinel: Google Web Risk returned a threat match. |
| `EXPECTED_DOMAIN_MATCH` | URL Sentinel: hostname matched a user-supplied trusted domain. |
| `NO_KNOWN_THREAT` | URL Sentinel: Web Risk found no match (absence ≠ safety). |

### Risk Levels

| Level | Meaning |
|-------|---------|
| `CRITICAL` | Severe threat (honeypot, sanctions, phishing confirmed) |
| `HIGH` | Significant risk requiring immediate attention |
| `MEDIUM` | Moderate signals; manual review advised |
| `LOW` | No significant risk signals detected |
| `UNKNOWN` | Risk cannot be assessed (unavailable data) |

---

## 1. `payguard_check_payment_intent`

Validates an x402 payment requirement against an explicit user-supplied intent policy. Returns PASS, REVIEW, or BLOCK with per-check explanations.

> [!NOTE]
> This tool never executes payments. It only compares caller-supplied data.

### Input Schema

```json
{
  "intent": {
    "expectedResourceUrl": "https://api.example.com/report",
    "maxAmountAtomic": "2000",
    "allowedNetworks": ["eip155:8453"],
    "allowedAssets": ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    "allowedPayTo": ["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    "allowedSchemes": ["exact"],
    "maxTimeoutSeconds": 300
  },
  "paymentRequirements": {
    "resource": "https://api.example.com/report",
    "accepts": [
      {
        "scheme": "exact",
        "network": "eip155:8453",
        "asset": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "payTo": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "maxAmountRequired": "1000",
        "amount": "1000",
        "timeout": 120
      }
    ]
  }
}
```

**Key rules:**
- `maxAmountAtomic` must be a non-negative integer string (no floating point)
- Policy values must come from a **trusted configuration source**, never from the 402 response itself
- Conflicting `amount` / `maxAmountRequired` fields fail closed
- Mixed acceptable/unacceptable alternatives do not receive an overall PASS

### Example Response

```json
{
  "verdict": "PASS",
  "riskLevel": "LOW",
  "checks": [
    { "id": "resource_url", "status": "PASS", "detail": "Resource URL matches policy" },
    { "id": "network", "status": "PASS", "detail": "Network eip155:8453 is allowed" },
    { "id": "asset", "status": "PASS", "detail": "Asset matches allowedAssets" },
    { "id": "pay_to", "status": "PASS", "detail": "Recipient matches allowedPayTo" },
    { "id": "amount", "status": "PASS", "detail": "Amount 1000 ≤ maxAmountAtomic 2000" }
  ],
  "summary": "All policy checks passed for selected payment candidate.",
  "acceptedCandidate": { ... }
}
```

---

## 2. `payguard_analyze_url`

Analyzes a URL for phishing signals, Unicode/Bidi deception, homoglyph attacks, credential embedding, dangerous ports, and more. Never fetches or opens the URL.

### Input Schema

```json
{
  "url": "https://payb0x-support.xyz/wallet-recovery?seed=...",
  "expectedDomain": "paybox.com",
  "trustedDomains": ["paybox.com", "app.paybox.com"],
  "checkReputation": false
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string (required) | URL or hostname to analyze (max 2048 chars) |
| `expectedDomain` | string | User-known legitimate domain for comparison |
| `trustedDomains` | string[] | Additional trusted domains (max 30) |
| `checkReputation` | boolean | If `true` and `GOOGLE_WEB_RISK_API_KEY` is set, performs a Web Risk lookup |

### Checks Performed

| Check ID | Severity | What it detects |
|----------|----------|-----------------|
| `unicode_bidi_override` | HIGH | U+061C, U+200E/F, U+202A–E, U+2066–9 in raw URL |
| `embedded_credentials` | HIGH | `user:pass@host` URL pattern |
| `trusted_domain_mismatch` | HIGH | Hostname doesn't match any trusted domain |
| `possible_lookalike_domain` | HIGH | Edit distance ≤1 from a trusted domain |
| `possible_paybox_impersonation` | HIGH | "paybox" in hostname but not official domain |
| `unicode_compatibility_confusable` | HIGH | NFKC normalization changes hostname |
| `wallet_secret_language` | HIGH | Seed/recovery/private-key terms in URL path |
| `idn_punycode` | MEDIUM | `xn--` internationalized labels |
| `unencrypted_http` | MEDIUM | Non-HTTPS scheme |
| `nonstandard_port` | MEDIUM | Port ≠ 80/443 |
| `ip_literal_host` | MEDIUM | IP address as hostname |
| `shortened_url` | MEDIUM | URL shortening service domain |
| `local_or_internal_hostname` | MEDIUM | localhost, .local, .internal |
| `external_redirect_parameter` | LOW | External URL in query parameters |
| `threat_intelligence_match` | CRITICAL | Google Web Risk threat confirmed |

> [!IMPORTANT]
> Bidi control character detection runs **before** the WHATWG URL parser. This ensures that characters which cause the parser to reject the URL (making it unparseable) are still caught and reported.

### Example Response

```json
{
  "verdict": "SUSPICIOUS",
  "riskLevel": "HIGH",
  "hostname": "payb0x-support.xyz",
  "displayedUrl": "https://payb0x-support.xyz/wallet-recovery",
  "summary": "One or more warning signs were detected.",
  "recommendation": "Do not connect a wallet, sign, pay, or enter secrets until verified independently.",
  "checks": [
    {
      "id": "trusted_domain_mismatch",
      "severity": "high",
      "status": "warning",
      "detail": "The hostname does not match any independently supplied trusted domain."
    },
    {
      "id": "possible_lookalike_domain",
      "severity": "high",
      "status": "warning",
      "detail": "The hostname is one character away from trusted domain paybox.com."
    },
    {
      "id": "wallet_secret_language",
      "severity": "high",
      "status": "warning",
      "detail": "The URL contains terms often associated with wallet recovery..."
    }
  ],
  "reputation": { "status": "NOT_REQUESTED", "threatTypes": [] },
  "privacy": {
    "urlOpened": false,
    "externalLookupPerformed": false,
    "queryParametersSentToReputationProvider": false,
    "pathSegmentsRedactedForReputationProvider": true
  },
  "paymentExecuted": false,
  "limitations": [...]
}
```

---

## 3. `payguard_prepare_threat_report`

Generates a privacy-conscious, redacted JSON draft threat report. Does not submit the report or notify any party automatically.

### Input Schema

Same as `payguard_analyze_url` (runs the URL Sentinel analysis internally).

### Example Response

```json
{
  "schemaVersion": "payguard-threat-report-v1",
  "reportStatus": "DRAFT_NOT_SUBMITTED",
  "createdAt": "2026-11-01T17:00:00.000Z",
  "subject": {
    "hostname": "payb0x-support.xyz",
    "url": "https://payb0x-support.xyz/wallet-recovery"
  },
  "verdict": "SUSPICIOUS",
  "riskLevel": "HIGH",
  "summary": "One or more warning signs were detected.",
  "findings": [...],
  "reputation": { "status": "NOT_REQUESTED", "threatTypes": [] },
  "submission": {
    "status": "NOT_SUBMITTED",
    "reason": "No verified PayBox threat-reporting endpoint is configured...",
    "automaticNotificationSent": false
  },
  "safetyNotes": [
    "URL query parameter values and embedded credentials are redacted.",
    "Free-form notes are excluded to reduce accidental secret disclosure.",
    "A report is an allegation, not proof of malicious intent."
  ]
}
```

> [!NOTE]
> Free-form user notes are intentionally excluded. Automated redaction cannot reliably detect all seed phrase and credential formats.

---

## 4. `payguard_inspect_calldata`

Decodes EVM transaction calldata and evaluates it for risk. Purely read-only — no network calls, no private keys.

### Input Schema

```json
{
  "to": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
  "value": "0",
  "data": "0x095ea7b3000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeefffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "policy": {
    "allowedTargets": ["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"],
    "allowedSpenders": ["0xknownspender..."],
    "allowedRecipients": ["0xrecipient..."],
    "maxAllowance": "1000000000",
    "maxTransferAmount": "500000000",
    "maxNativeValue": "0"
  }
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `to` | string (required) | Target contract address (0x hex, 20 bytes) |
| `value` | string/number | Native ETH value in wei |
| `data` | string | 0x-prefixed calldata hex |
| `policy` | object | Optional security policy constraints |

### Supported ERC-20 Operations

| Selector | Function | Decoded Fields |
|----------|----------|---------------|
| `0x095ea7b3` | `approve(address spender, uint256 amount)` | spender, rawAmount, isUnlimited |
| `0xa9059cbb` | `transfer(address recipient, uint256 amount)` | recipient, amount |
| `0x23b872dd` | `transferFrom(address from, address to, uint256 amount)` | from, to, amount |
| `0x` (empty) | Native ETH transfer | nativeValue |
| Any other | Unknown selector | advisory REVIEW |

### Risk Factors

| Code | Trigger | Verdict |
|------|---------|---------|
| `UNLIMITED_ALLOWANCE_UINT256_MAX` | `approve` with `2^256 - 1` | REVIEW |
| `UNUSUALLY_LARGE_ALLOWANCE` | allowance > `2^255` | REVIEW |
| `SPENDER_NOT_IN_ALLOWLIST` | spender not in `allowedSpenders` | BLOCK |
| `RECIPIENT_NOT_IN_ALLOWLIST` | recipient not in `allowedRecipients` | BLOCK |
| `TARGET_NOT_IN_ALLOWLIST` | `to` not in `allowedTargets` | BLOCK |
| `ALLOWANCE_EXCEEDS_POLICY_MAX` | amount > `maxAllowance` | BLOCK |
| `TRANSFER_EXCEEDS_POLICY_MAX` | amount > `maxTransferAmount` | BLOCK |
| `NATIVE_VALUE_EXCEEDS_POLICY` | value > `maxNativeValue` | BLOCK |

### Example Response (Unlimited Approval)

```json
{
  "verdict": "REVIEW",
  "riskLevel": "MEDIUM",
  "operation": "ERC20_APPROVE",
  "reasons": ["UNLIMITED_ALLOWANCE_UINT256_MAX"],
  "checks": [
    { "id": "target_address", "status": "PASS", "detail": "0xa0b8...6eb48" },
    { "id": "native_value", "status": "PASS", "detail": "0" },
    { "id": "allowance_size", "status": "WARN", "detail": "Spender is granted maximum possible token allowance (2^256 - 1)" }
  ],
  "details": {
    "tokenContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "spender": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "rawAmount": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    "isUnlimited": true,
    "isUnusuallyLarge": true
  }
}
```

---

## 5. `payguard_check_token_security`

Queries GoPlus Token Security API for Base Mainnet token risk intelligence. Evaluates honeypot status, trading taxes, transfer restrictions, supply controls, and contract verification.

> [!IMPORTANT]
> Only Base Mainnet (chain ID 8453) is supported. Base Sepolia (84532) returns `UNVERIFIED / UNSUPPORTED_CHAIN`.

### Input Schema

```json
{
  "chainId": 8453,
  "contractAddress": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `chainId` | number/string | Chain ID — only `8453` / `"eip155:8453"` supported |
| `contractAddress` | string | 0x-prefixed 20-byte token contract address |

### Evaluated Risk Indicators

| GoPlus Field | Finding Code | Severity |
|-------------|-------------|----------|
| `is_honeypot` | `HONEYPOT_DETECTED` | critical |
| `owner_change_balance` | `OWNER_CAN_CHANGE_BALANCE` | critical |
| `cannot_buy` | `CANNOT_BUY` | high |
| `cannot_sell_all` | `CANNOT_SELL_ALL` | high |
| `buy_tax ≥ 25%` | `EXCESSIVE_BUY_TAX` | high |
| `sell_tax ≥ 25%` | `EXCESSIVE_SELL_TAX` | high |
| `buy_tax 5–25%` | `HIGH_BUY_TAX` | medium |
| `sell_tax 5–25%` | `HIGH_SELL_TAX` | medium |
| `slippage_modifiable` | `SLIPPAGE_MODIFIABLE` | medium |
| `transfer_pausable` | `TRANSFER_PAUSABLE` | medium |
| `is_mintable` | `MINTABLE_TOKEN` | medium |
| `is_proxy` | `UPGRADEABLE_PROXY` | info |
| `is_open_source = 0` | `CLOSED_SOURCE_BYTECODE` | medium |
| `trust_list = 1` | `RECOGNIZED_TRUST_LIST` | info |

### Error Codes

| Code | Cause |
|------|-------|
| `UNSUPPORTED_CHAIN` | Chain ID ≠ 8453 |
| `INVALID_CONTRACT_ADDRESS` | Address format invalid |
| `REQUEST_TIMEOUT` | Exceeded 3s timeout |
| `NETWORK_ERROR` | Network failure |
| `RATE_LIMITED` | HTTP 429 |
| `AUTH_FAILED` | HTTP 401/403 |
| `UPSTREAM_ERROR` | HTTP 5xx |
| `MALFORMED_JSON` | Unparseable response |
| `OVERSIZED_RESPONSE` | Response > 64 KB |
| `UNINDEXED_TOKEN` | Token not in GoPlus database |

All errors return `UNVERIFIED` — never `PASS`.

### Example Response

```json
{
  "verdict": "BLOCK",
  "riskLevel": "CRITICAL",
  "chainId": "8453",
  "contractAddress": "0xdeadbeef...",
  "tokenName": "FakeToken",
  "tokenSymbol": "FAKE",
  "findings": [
    {
      "code": "HONEYPOT_DETECTED",
      "severity": "critical",
      "message": "Token is identified as a honeypot; users cannot sell their tokens."
    }
  ],
  "reasonCodes": ["HONEYPOT_DETECTED"],
  "provider": "goplus",
  "timestamp": 1730486400000,
  "dataStatus": "AVAILABLE"
}
```

---

## 6. `payguard_check_address_security`

Queries GoPlus Address Security API to check whether an EVM address is linked to phishing, theft, sanctions, money laundering, cybercrime, or other malicious activity.

> [!IMPORTANT]
> Only Base Mainnet (chain ID 8453) is supported. Base Sepolia (84532) returns `UNVERIFIED / UNSUPPORTED_CHAIN`.

### Input Schema

```json
{
  "chainId": 8453,
  "address": "0x1234567890abcdef1234567890abcdef12345678"
}
```

### Endpoint Format

```
GET https://api.gopluslabs.io/api/v1/address_security/{address}?chain_id={chainId}
```

Note: the address is a **path segment**; chain_id is a **query parameter**. This differs from the Token Security endpoint.

### Evaluated Risk Indicators

| GoPlus Field | Finding Code | Severity |
|-------------|-------------|----------|
| `phishing_activities` | `PHISHING_ACTIVITIES` | critical |
| `stealing_attack` | `STEALING_ATTACK` | critical |
| `sanctioned` | `SANCTIONED_ADDRESS` | critical |
| `number_of_malicious_contracts_created ≥ 3` | `MALICIOUS_CONTRACTS_CREATED` | critical |
| `blacklist_doubt` | `BLACKLIST_SUSPICION` | high |
| `honeypot_related_address` | `HONEYPOT_AFFILIATE` | high |
| `fake_token` | `FAKE_TOKEN_ISSUER` | high |
| `cybercrime` | `CYBERCRIME_INVOLVEMENT` | high |
| `money_laundering` | `MONEY_LAUNDERING` | high |
| `financial_crime` | `FINANCIAL_CRIME` | high |
| `blackmail_activities` | `BLACKMAIL_ACTIVITIES` | high |
| `number_of_malicious_contracts_created 1–2` | `MALICIOUS_CONTRACTS_CREATED` | high |
| `darkweb_transactions` | `DARKWEB_TRANSACTIONS` | medium |
| `mixer` | `MIXER_USAGE` | medium |
| `fake_kyc` | `FAKE_KYC` | medium |
| `gas_abuse` | `GAS_ABUSE` | medium |
| `malicious_mining_activities` | `MALICIOUS_MINING` | medium |

### Example Response

```json
{
  "verdict": "BLOCK",
  "riskLevel": "CRITICAL",
  "chainId": "8453",
  "address": "0xdeadbeef...",
  "findings": [
    {
      "code": "PHISHING_ACTIVITIES",
      "severity": "critical",
      "message": "Address is flagged for involvement in phishing attacks."
    },
    {
      "code": "SANCTIONED_ADDRESS",
      "severity": "critical",
      "message": "Address is present on government or regulatory sanctions lists."
    }
  ],
  "reasonCodes": ["PHISHING_ACTIVITIES", "SANCTIONED_ADDRESS"],
  "provider": "goplus",
  "timestamp": 1730486400000,
  "dataStatus": "AVAILABLE"
}
```

---

## Caching Behavior (Tools 5 & 6)

| Behavior | Detail |
|----------|--------|
| Cache TTL | 10 minutes in-memory |
| Cache key | `{chainId}:{normalizedAddress}` |
| Cached | Successful evaluations only |
| Not cached | Errors, timeouts, rate limits, invalid inputs |
| Cache indicator | `cached: true` field in response |

Errors are never cached. A transient network failure will trigger a fresh request on the next call.

---

## MCP Protocol Details

PayGuard implements [MCP protocol version 2024-11-05](https://spec.modelcontextprotocol.io/specification/).

**Supported methods:**
- `initialize` — returns server info and capabilities
- `tools/list` — returns all 6 tool descriptors with JSON Schema input schemas
- `tools/call` — invokes a tool by name with arguments
- `ping` — health check

**Both framing modes supported:**
- Newline-delimited JSON (one message per line)
- Content-Length framed JSON-RPC (standard MCP framing)

**Error handling:** Tool errors return an MCP result with `isError: true` and a text description — the server never crashes on bad input.
