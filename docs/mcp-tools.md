# PayGuard MCP Tools Reference

PayGuard exposes seven Model Context Protocol (MCP) tools. All tools return structured JSON with a **verdict**, **riskLevel**, and **findings** or **checks** array. All tools are advisory — they do not execute payments, sign transactions, or block wallet operations outside of PayGuard-controlled paths.

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
  "acceptedCandidate": { "network": "eip155:8453", "asset": "0xaaa...", "amount": "1000" }
}
```

---

## 2. `payguard_analyze_url`

Analyzes a URL for phishing signals, Unicode/Bidi deception, homoglyph attacks, credential embedding, dangerous ports, and more. Never fetches or opens the URL.

### Input Schema

```json
{
  "url": "https://paybox.com/checkout",
  "expectedDomain": "paybox.com",
  "checkReputation": false
}
```

### Analysis Checks Performed

| Check ID | Threat Detected | Risk if Fired |
|----------|----------------|---------------|
| `BIDI_CONTROL_CHARS` | Invisible Unicode direction-override characters hiding true URL path | CRITICAL / BLOCK |
| `FULLWIDTH_CONFUSABLE` | Full-width Unicode characters that look like Latin | HIGH / REVIEW |
| `HOMOGLYPH_DETECTED` | Cyrillic, Greek, or confusable scripts in hostname | HIGH / REVIEW |
| `PUNYCODE_HOST` | IDN label (`xn--...`) | MEDIUM / REVIEW |
| `CREDENTIAL_IN_URL` | Userinfo present (`user:pass@host`) | HIGH / REVIEW |
| `DANGEROUS_PORT` | Non-standard port (e.g. 21, 23, 25, 6667) | HIGH / REVIEW |
| `IP_ADDRESS_HOST` | Raw IP address used as hostname | MEDIUM / REVIEW |
| `LOOKALIKE_DOMAIN` | Hostname close to `expectedDomain` (Levenshtein distance ≤ 2) | HIGH / REVIEW |
| `DOMAIN_MISMATCH` | Hostname does not match `expectedDomain` | MEDIUM / REVIEW |
| `HTTP_NOT_SECURE` | Non-HTTPS protocol | LOW / CAUTION |
| `GOOGLE_WEB_RISK` | Threat match from Google Web Risk (opt-in) | CRITICAL / BLOCK |

---

## 3. `payguard_prepare_threat_report`

Generates a privacy-conscious, redacted threat report draft for a suspicious URL. High-entropy path segments and query credentials are automatically scrubbed.

### Input Schema

```json
{
  "url": "https://phish.example/login?token=SECRET123",
  "expectedDomain": "example.com",
  "userNotes": "Found in phishing email"
}
```

### Output

Returns a report draft marked `DRAFT_NOT_SUBMITTED`. Does not submit to any external endpoint.

---

## 4. `payguard_inspect_calldata`

Decodes EVM transaction calldata for ERC-20 `approve`, `transfer`, and `transferFrom` methods. Evaluates allowances, spenders, and recipients against optional caller policies.

### Input Schema

```json
{
  "to": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "value": "0",
  "data": "0x095ea7b30000000000000000000000001111111254fb6c44bac0bed2854e76f90643097dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "policy": {
    "allowedSpenders": ["0x1111111254fb6c44bac0bed2854e76f90643097d"],
    "allowedRecipients": ["0x2222222222222222222222222222222222222222"],
    "allowUnlimitedApproval": false
  }
}
```

### Findings Evaluated

| Check ID | Severity | Condition |
|----------|----------|-----------|
| `UNLIMITED_ALLOWANCE` | HIGH / REVIEW | `approve` called with `uint256.max` |
| `UNAUTHORIZED_SPENDER` | HIGH / BLOCK | Spender not in `allowedSpenders` list |
| `UNAUTHORIZED_RECIPIENT` | HIGH / BLOCK | Recipient not in `allowedRecipients` list |
| `UNKNOWN_SELECTOR` | MEDIUM / REVIEW | Function selector outside recognized ERC-20 set |
| `TRUNCATED_CALLDATA` | CRITICAL / BLOCK | Byte length shorter than expected parameter count |
| `NON_ZERO_NATIVE_VALUE` | HIGH / REVIEW | Native ETH sent alongside token approval/transfer |

---

## 5. `payguard_check_token_security`

Queries the GoPlus Security API for Base Mainnet (Chain ID 8453) token contract intelligence. Evaluates honeypot mechanics, buy/sell taxes, arbitrary owner balance privileges, and proxy implementation risks.

### Input Schema

```json
{
  "chainId": "8453",
  "contractAddress": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
}
```

### Key Evaluated Indicators

- `is_honeypot` → `BLOCK / CRITICAL`
- `owner_change_balance` → `BLOCK / CRITICAL`
- `cannot_sell_all` → `BLOCK / CRITICAL`
- `buy_tax > 0.10` or `sell_tax > 0.10` → `BLOCK` or `REVIEW`
- `transfer_pausable` → `REVIEW / MEDIUM`
- `is_airdrop_scam` → `BLOCK / HIGH`
- `is_open_source == "0"` → `REVIEW / MEDIUM` (unverified source code)

---

## 6. `payguard_check_address_security`

Queries the GoPlus Address Security API for Base Mainnet (Chain ID 8453) account intelligence. Checks for associations with phishing, sanctions, cybercrime, darkweb marketplaces, or mixer usage.

### Input Schema

```json
{
  "chainId": "8453",
  "address": "0x1234567890123456789012345678901234567890"
}
```

### Key Evaluated Indicators

- `sanctioned` → `BLOCK / CRITICAL`
- `phishing_activities` → `BLOCK / CRITICAL`
- `stealing_attack` → `BLOCK / CRITICAL`
- `cybercrime` / `financial_crime` → `BLOCK / HIGH`
- `darkweb_transactions` → `REVIEW / MEDIUM`
- `mixer` → `REVIEW / MEDIUM`

---

## 7. `payguard_scan_wallet_tokens`

Automatically scans ERC-20 token holdings in a Base Mainnet (Chain ID 8453) wallet for honeypot mechanics, arbitrary balance alteration privileges, high trading taxes, and lookalike token impersonation.

### Input Schema

```json
{
  "walletAddress": "0x4200000000000000000000000000000000000006",
  "customTokenAddresses": [
    "0x50c5725949a6F0c72E6C4a641F24049A917DB0Cb"
  ]
}
```

### Discovery Architecture

The scanner operates in two discovery tiers:
1. **Tier 1 — Full Indexer (`FULL_INDEXER`):** Calls Blockscout Base API v2 (`GET https://base.blockscout.com/api/v2/addresses/{addr}/tokens?type=ERC-20`). If successful, retrieves all arbitrary ERC-20 tokens held by the address.
2. **Tier 2 — On-Chain RPC Multicall Fallback (`REGISTRY_AND_CUSTOM_PARTIAL`):** When automated requests face indexer rate limits or Cloudflare bot challenges, PayGuard falls back to on-chain `eth_call` queries on Base Mainnet. The fallback checks the 7 canonical Base ecosystem tokens (WETH, USDC, cbETH, VIRTUAL, DAI, USDbC, AERO) plus any optional `customTokenAddresses` provided in the request.

### Token Impersonation Detection

The tool verifies whether the contract address matches official canonical deployments. If a contract presents a well-known symbol (e.g. `USDC` or `VIRTUAL`) but its contract address differs from the canonical registry, it is flagged as:
- `isImpersonation: true`
- `securityStatus: "HIGH RISK"`
- `detectedIndicators`: `["TOKEN_LOOKALIKE_IMPERSONATION"]`

### Example Response

```json
{
  "status": "SUCCESS",
  "walletAddress": "0x4200000000000000000000000000000000000006",
  "discoveryMode": "REGISTRY_AND_CUSTOM_PARTIAL",
  "advisoryNotice": "Notice: Token holdings were discovered via on-chain RPC fallback checking 7 curated Base canonical tokens plus custom token addresses. Discovery is partial.",
  "tokensScannedCount": 2,
  "highRiskCount": 1,
  "suspiciousCount": 0,
  "tokens": [
    {
      "contractAddress": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "name": "USD Coin",
      "symbol": "USDC",
      "decimals": 6,
      "balance": "5000000",
      "isVerifiedOfficial": true,
      "isImpersonation": false,
      "securityStatus": "CLEAR",
      "riskScore": 0,
      "recommendedAction": "Normal interaction permitted based on available threat intelligence.",
      "detectedIndicators": []
    },
    {
      "contractAddress": "0x50c5725949a6F0c72E6C4a641F24049A917DB0Cb",
      "name": "Dai Stablecoin",
      "symbol": "DAI",
      "decimals": 18,
      "balance": "1000000000000000000",
      "isVerifiedOfficial": true,
      "isImpersonation": false,
      "securityStatus": "HIGH RISK",
      "riskScore": 85,
      "recommendedAction": "Do not trade, approve, or interact with this token.",
      "detectedIndicators": [
        {
          "label": "Owner can arbitrarily modify balances",
          "severity": "CRITICAL",
          "detail": "The contract owner or privileged address can adjust holder balances directly."
        }
      ]
    }
  ],
  "evaluatedAt": "2026-11-02T10:30:00.000Z"
}
```

---

## Caching Behavior (Tools 5, 6 & 7)

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
- `tools/list` — returns all 7 tool descriptors with JSON Schema input schemas
- `tools/call` — invokes a tool by name with arguments
- `ping` — health check

**Both framing modes supported:**
- Newline-delimited JSON (one message per line)
- Content-Length framed JSON-RPC (standard MCP framing)

**Error handling:** Tool errors return an MCP result with `isError: true` and a text description — the server never crashes on bad input.
