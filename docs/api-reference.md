# API Reference

PayGuard's HTTP API is served by `server.mjs`. Every example below was run against the local server (`PORT=18080 node server.mjs`). Responses are trimmed with `...` for length; field names and values are real. Provider-backed endpoints (token, address, wallet) were run in an environment without access to GoPlus, Blockscout or Base RPC, so their examples show the fail-closed `UNVERIFIED` behavior rather than live data.

Related: [MCP Tools](mcp-tools.md) (same checks as agent tools), [Architecture](architecture.md), [Security Model](security-model.md), [Getting Started](getting-started.md).

---

## Conventions

| Item | Behavior |
| :--- | :--- |
| Base URL | `http://localhost:8080` by default (`PORT`, `HOST` configurable) |
| Method | `POST` with `Content-Type: application/json` for `/api/*` check endpoints; `GET` for the others |
| Body limit | 64 KB; larger bodies return an error |
| Rate limit | Per client IP, default 120 requests per 60 seconds (`MAX_REQUESTS_PER_WINDOW`) |
| Concurrency | Default cap 100 in-flight requests (`MAX_CONCURRENT_REQUESTS`); above it returns 429 |
| Authentication | None. See Security Model for the consequences |
| CORS | `Access-Control-Allow-Origin: *`; `OPTIONS` returns 204 |
| Response headers | `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` |
| Network | Base Mainnet (chain ID 8453) for provider-backed checks |

### Error responses

| Status | Body | Cause |
| :--- | :--- | :--- |
| 400 | `{"error":"Request body must contain valid JSON."}` | Malformed JSON |
| 404 | `{"error":"Not found."}` | Unknown route or wrong method |
| 429 | `{"error":"Rate limit exceeded. Try again later."}` | Rate limit |
| 429 | `{"error":"Server busy: maximum concurrency limit reached."}` | Concurrency cap |
| 402 | Payment challenge | Only when `PAYGUARD_REQUIRE_X402=true` and no valid payment is supplied |
| 500 | `{"error":"Internal error. Check server logs."}` | Unexpected error; details hidden unless `NODE_ENV=development` |

Invalid input to a check is usually reported inside a normal 200 response as a failing verdict (for example `UNVERIFIED` with `MALFORMED_INPUT`), not as an HTTP error.

---

## Endpoint summary

| Method and path | Purpose | MCP tool |
| :--- | :--- | :--- |
| `POST /api/analyze-url` | URL phishing and impersonation signals | `payguard_analyze_url` |
| `POST /api/check-payment` | x402 payment requirement vs. policy | `payguard_check_payment_intent` |
| `POST /api/threat-report` | Draft report for a suspicious URL | `payguard_prepare_threat_report` |
| `POST /api/inspect-calldata` | ERC-20 calldata inspection | `payguard_inspect_calldata` |
| `POST /api/token-security` | Token risk via GoPlus | `payguard_check_token_security` |
| `POST /api/address-security` | Address reputation via GoPlus | `payguard_check_address_security` |
| `POST /api/scan-wallet-tokens` | Wallet token scan | `payguard_scan_wallet_tokens` |
| `GET /api/capabilities` | Service and provider configuration | none |
| `GET /health` | Liveness | none |
| `GET /metrics` | Prometheus metrics | none |
| `GET /.well-known/x402-bazaar.json` and `GET /api/bazaar` | x402 discovery metadata | none |
| `GET /`, `/dashboard`, `/docs`, `/whitepaper`, `/faq` | Pages | none |

---

## POST /api/analyze-url

Request fields: `url` (required string), `expectedDomain` (string), `trustedDomains` (array of strings), `checkReputation` (boolean; needs `GOOGLE_WEB_RISK_API_KEY`).

```bash
curl -X POST http://localhost:8080/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://bases.org/login","expectedDomain":"base.org"}'
```

Response (trimmed):

```json
{
  "verdict": "SUSPICIOUS",
  "riskLevel": "HIGH",
  "statusCategory": "HIGH RISK",
  "isOfficialBaseProject": false,
  "isBaseImpersonation": true,
  "hostname": "bases.org",
  "checks": [
    { "id": "trusted_domain_mismatch", "severity": "high", "status": "warning" },
    { "id": "possible_lookalike_domain", "severity": "high", "status": "warning" },
    { "id": "base_ecosystem_impersonation", "severity": "high", "status": "fail" }
  ],
  "reputation": { "status": "NOT_REQUESTED", "threatTypes": [] },
  "privacy": {
    "urlOpened": false,
    "externalLookupPerformed": false,
    "queryParametersSentToReputationProvider": false,
    "pathSegmentsRedactedForReputationProvider": true
  },
  "paymentExecuted": false,
  "limitations": ["This analyzer never opens, visits, or downloads content from the submitted URL.", "..."]
}
```

Verdict values in the code: `KNOWN_MALICIOUS`, `SUSPICIOUS`, `CAUTION`, `NO_KNOWN_THREAT`, `EXPECTED_DOMAIN_MATCH`, `UNVERIFIED`. `KNOWN_MALICIOUS` requires a reputation-provider match. Heuristic signals alone yield `SUSPICIOUS` or `CAUTION`.

---

## POST /api/check-payment

Request fields: `intent` (object, required) and `paymentRequirements` (object with `accepts` array, required).

Intent fields: `expectedResourceUrl`, `maxAmountAtomic` (integer string), `allowedNetworks`, `allowedAssets`, `allowedPayTo`, `allowedSchemes`, `maxTimeoutSeconds` (1 to 86400).

Response field is `status` (PASS, REVIEW or BLOCK), not `verdict`.

Violating request:

```bash
curl -X POST http://localhost:8080/api/check-payment \
  -H "Content-Type: application/json" \
  -d '{
    "intent": {
      "expectedResourceUrl": "https://example.com/r",
      "maxAmountAtomic": "1000",
      "allowedNetworks": ["eip155:8453"],
      "allowedAssets": ["0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"],
      "allowedPayTo": ["0x20556F0cfA3f93F0206faeb5452d2745e1423469"],
      "allowedSchemes": ["exact"],
      "maxTimeoutSeconds": 300
    },
    "paymentRequirements": {
      "resource": "https://example.com/r",
      "accepts": [{
        "scheme": "exact", "network": "eip155:8453", "amount": "5000",
        "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "payTo": "0x1111111111111111111111111111111111111111",
        "maxTimeoutSeconds": 300
      }]
    }
  }'
```

Response (trimmed):

```json
{
  "status": "BLOCK",
  "summary": "Every offered payment option violates at least one explicit policy check.",
  "paymentExecuted": false,
  "checks": [
    { "id": "recipient", "status": "fail", "detail": "Recipient does not match the trusted allowlist.", "candidateIndex": 0 },
    { "id": "amount", "status": "fail", "detail": "Requested amount exceeds the user's maximum.", "candidateIndex": 0 }
  ],
  "candidateResults": [ { "index": 0, "status": "BLOCK", "checks": ["..."] } ],
  "limitations": ["This checks the supplied request data against supplied policy; it does not authenticate the ...", "..."]
}
```

With a matching recipient and an amount of `500`, the same request returns `"status": "PASS"` and the summary "All offered payment options match the explicit policy checks. This is not a guarantee of merchant legitimacy."

An incomplete policy returns `REVIEW`:

```json
{
  "status": "REVIEW",
  "summary": "Cannot approve a payment without complete, explicit user policy.",
  "checks": [
    { "id": "policy", "status": "unknown", "detail": "Missing or invalid policy field: expectedResourceUrl (valid HTTPS URL without credentials or fragment)." }
  ]
}
```

---

## POST /api/inspect-calldata

Request fields: `to` (required address), `value` (string, native amount), `data` (hex string), `network` (string), `policy` (object: `allowedTargets`, `allowedSpenders`, `allowedRecipients`, `maxAllowance`, `maxNativeValue`).

```bash
curl -X POST http://localhost:8080/api/inspect-calldata \
  -H "Content-Type: application/json" \
  -d '{
    "to": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "value": "0",
    "network": "eip155:8453",
    "data": "0x095ea7b30000000000000000000000001111111111111111111111111111111111111111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  }'
```

Response (trimmed):

```json
{
  "verdict": "REVIEW",
  "riskLevel": "MEDIUM",
  "operation": "ERC20_APPROVE",
  "reasons": ["UNLIMITED_ALLOWANCE_UINT256_MAX"],
  "checks": [
    { "id": "allowance_size", "status": "WARN", "detail": "Spender is granted maximum possible token allowance (2^256 - 1)" }
  ],
  "details": {
    "spender": "0x1111111111111111111111111111111111111111",
    "isUnlimited": true,
    "isUnusuallyLarge": true
  }
}
```

A missing or malformed `to` returns `"verdict": "BLOCK"` with `"operation": "INVALID_TARGET"`. Unrecognized selectors return `REVIEW`.

---

## POST /api/token-security

Request fields: `contractAddress` (required), `chainId` (string or number; only `8453` is supported).

```bash
curl -X POST http://localhost:8080/api/token-security \
  -H "Content-Type: application/json" \
  -d '{"contractAddress":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}'
```

When GoPlus cannot be reached (observed in a sandbox without outbound access):

```json
{
  "verdict": "UNVERIFIED",
  "riskLevel": "UNKNOWN",
  "chainId": "8453",
  "contractAddress": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  "findings": [ { "code": "NETWORK_ERROR", "severity": "high", "message": "Network error connecting to GoPlus API: fetch failed" } ],
  "reasonCodes": ["NETWORK_ERROR"],
  "provider": "goplus",
  "dataStatus": "UNAVAILABLE"
}
```

A malformed address returns `UNVERIFIED` with `INVALID_CONTRACT_ADDRESS` and `dataStatus: MALFORMED_INPUT`. The shape of a successful provider response is described in [MCP Tools](mcp-tools.md).

---

## POST /api/address-security

Request fields: `address` (required), `chainId` (only `8453`). Same fail-closed behavior as the token endpoint: an unreachable provider returns `verdict: UNVERIFIED`, `reasonCodes: ["NETWORK_ERROR"]`, `dataStatus: UNAVAILABLE`.

---

## POST /api/scan-wallet-tokens

Request fields: `walletAddress` (required), `customTokenAddresses` (array of addresses).

```bash
curl -X POST http://localhost:8080/api/scan-wallet-tokens \
  -H "Content-Type: application/json" \
  -d '{"walletAddress":"0x1111111111111111111111111111111111111111"}'
```

Response when the indexer and provider were unreachable (trimmed):

```json
{
  "status": "SUCCESS",
  "walletAddress": "0x1111111111111111111111111111111111111111",
  "chainId": "8453",
  "networkName": "Base Mainnet",
  "discoveryMode": "REGISTRY_AND_CUSTOM_PARTIAL",
  "blockscoutStatus": "fetch failed",
  "summary": { "totalTokensScanned": 7, "highRiskCount": 0, "suspiciousCount": 0, "cleanCount": 0, "unverifiedCount": 7 },
  "tokens": [ { "symbol": "USDC", "balance": "0", "verdict": "UNVERIFIED", "securityStatus": "UNABLE TO VERIFY" } ]
}
```

Read `discoveryMode` before trusting a count. `REGISTRY_AND_CUSTOM_PARTIAL` means only the canonical registry tokens and the supplied custom addresses were checked. A scan with all tokens `UNVERIFIED` and `highRiskCount: 0` means no evidence was available, not that the wallet is safe.

---

## POST /api/threat-report

Request fields match `/api/analyze-url`. The response is a draft that is **not transmitted anywhere**.

```json
{
  "schemaVersion": "payguard-threat-report-v1",
  "reportStatus": "DRAFT_NOT_SUBMITTED",
  "subject": { "hostname": "bases.org", "url": "https://bases.org/login?token=%5BREDACTED%5D" },
  "verdict": "SUSPICIOUS",
  "findings": ["..."],
  "submission": { "status": "NOT_SUBMITTED", "reason": "No verified PayBox threat-report endpoint ..." }
}
```

The example shows the `token` query value redacted in the report.

---

## GET endpoints

`GET /api/capabilities`:

```json
{
  "service": "payguard",
  "version": "0.1.0",
  "mode": "read-only",
  "goPlusConfigured": false,
  "webRiskConfigured": false,
  "supportedChains": ["8453"],
  "modules": ["url-sentinel", "payment-guard", "calldata-inspector", "token-security", "address-security", "wallet-token-scanner", "threat-report"]
}
```

`GET /health` returns `{"ok":true,"service":"payguard","mode":"read-only","paymentExecution":false}`.

`GET /metrics` returns Prometheus text: `payguard_http_requests_total`, `payguard_request_duration_seconds`, `payguard_tool_verdicts_total`, `payguard_in_flight_requests` and `payguard_uptime_seconds`.

`GET /.well-known/x402-bazaar.json` returns discovery metadata for the `analyze-url` and `check-payment` endpoints.

---

## Optional x402 payment gate

Setting `PAYGUARD_REQUIRE_X402=true` makes the POST endpoints return a 402 challenge unless a payment header (`payment-signature` or `x-payment`) is present. When the gate is on, a simulated proof is rejected and only a proof settled through a live facilitator unlocks the route. Defaults in `paybox.mjs` point at Base Sepolia test values (`eip155:84532`) and a public test receiving address; override with `PAYGUARD_NETWORK`, `PAYGUARD_ASSET`, `PAYGUARD_PAY_TO` and `X402_FACILITATOR_URL`. Live settlement is enabled with `X402_LIVE_SETTLEMENT=true`.

> [!NOTE]
> This mode is Partially Supported. The repository's tests cover the 402 challenge format built by `paybox.mjs`. The server-level gate and live facilitator settlement were not exercised in this documentation review.
