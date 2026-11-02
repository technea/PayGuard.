# PayGuard

**A Base-focused Web3 security platform for AI agents and developers.**

PayGuard provides read-only, advisory security intelligence before wallet signing, token interaction, or payment authorization. It exposes six Model Context Protocol (MCP) tools covering URL phishing detection, EVM calldata inspection, x402 payment policy validation, privacy-conscious threat reporting, and on-chain reputation via the GoPlus Security API.

> [!IMPORTANT]
> PayGuard is an advisory sentinel — it does not sign, authorize, or execute transactions. Verdicts of PASS, REVIEW, BLOCK, or UNVERIFIED are findings for a human or agent to act on, not automated enforcement gates.

---

## Security Boundary

PayGuard does **not**:
- Sign or broadcast transactions
- Request or store private keys or seed phrases
- Expose API credentials in tool output or client-side code
- Fetch the submitted URL or contact the target host

PayGuard **does**:
- Analyze URL structure and content locally without opening the link
- Decode EVM calldata and evaluate it against configurable policy
- Validate x402 payment requirements against a user-supplied intent policy
- Query GoPlus Security API for Base Mainnet token and address intelligence (opt-in)

---

## Six MCP Tools

| Tool | Purpose |
|------|---------|
| `payguard_check_payment_intent` | Validate x402 payment requirements against explicit user intent policy |
| `payguard_analyze_url` | Detect phishing, Bidi control chars, homoglyphs, and URL deceptions |
| `payguard_prepare_threat_report` | Generate a redacted, privacy-safe threat report draft |
| `payguard_inspect_calldata` | Decode and audit EVM transaction calldata before signing |
| `payguard_check_token_security` | GoPlus honeypot, tax, and contract risk assessment (Base Mainnet) |
| `payguard_check_address_security` | GoPlus address reputation check (phishing, sanctions, cybercrime) |

All tools return structured JSON with a **verdict** (`PASS` / `REVIEW` / `BLOCK` / `UNVERIFIED`), **riskLevel**, and detailed **findings**.

---

## Installation

**Requires Node.js 20+.**

```bash
git clone https://github.com/technea/PayGuard.git
cd PayGuard
npm install
```

---

## Commands

```bash
# Run all 143 tests
npm test

# Build ESM, CommonJS, TypeScript declarations, and stdio MCP server
npm run build

# Start the local HTTP API server
npm start

# Run the URL Sentinel demo
npm run demo
```

---

## MCP Integration

The plugin exposes a JSON-RPC 2.0 stdio MCP server compatible with Claude, Cursor, and any MCP-compliant host.

**Run directly as stdio MCP server:**
```bash
node dist/index.js
# or
MCP_STDIO=1 node dist/plugin.mjs
```

**Import as a Node.js module:**
```js
import plugin from 'payguard-paybox-plugin/plugin';

// Inspect a URL
const result = await plugin.invokeTool('payguard_analyze_url', {
  url: 'https://payb0x-support.xyz/wallet-recovery'
});
console.log(result.verdict); // "SUSPICIOUS"

// Inspect EVM calldata
const callResult = await plugin.invokeTool('payguard_inspect_calldata', {
  to: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
  value: '0',
  data: '0x095ea7b3' +
        '000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' +
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
});
console.log(callResult.verdict);   // "REVIEW"
console.log(callResult.operation); // "ERC20_APPROVE"
```

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `GOOGLE_WEB_RISK_API_KEY` | Enables optional Google Web Risk reputation lookup in URL Sentinel |
| `GOPLUS_API_KEY` | Optional bearer token for GoPlus API (higher rate limits) |

Both are **server-side only** and are never included in tool output or client-side bundles.

---

## Verdict Reference

| Verdict | Meaning |
|---------|---------|
| `PASS` | All configured checks passed. Advisory only — not a guarantee of safety. |
| `REVIEW` | Suspicious signals detected. Human or agent review required before proceeding. |
| `BLOCK` | High or critical risk detected. PayGuard-controlled signing paths abort. |
| `UNVERIFIED` | Insufficient data or provider unavailable. Treat as unknown risk. |
| `SUSPICIOUS` | URL Sentinel: heuristic signals present. |
| `KNOWN_MALICIOUS` | URL Sentinel: Web Risk threat intelligence match. |
| `EXPECTED_DOMAIN_MATCH` | URL Sentinel: matches a user-supplied trusted domain. |

---

## x402 Pre-Signing Hook

PayGuard attaches to the x402 client to intercept payment creation before payload signing:

```js
import { x402Client } from '@x402/core/client';
import { registerPayGuardX402 } from 'payguard-paybox-plugin';

const client = new x402Client();

registerPayGuardX402(client, {
  intent: {
    expectedResourceUrl: 'https://api.example.com/report',
    maxAmountAtomic: '2000',
    allowedNetworks: ['eip155:8453'],
    allowedAssets: ['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
    allowedPayTo: ['0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'],
    allowedSchemes: ['exact'],
    maxTimeoutSeconds: 300
  }
});
```

The hook aborts payment creation for both `BLOCK` and `REVIEW` verdicts. Only a clean `PASS` proceeds to the scheme-specific payload step. Policy values must come from a trusted configuration source — never from the 402 response itself.

---

## Base Smart Wallet Integration

PayGuard includes a pre-signing inspection layer for Coinbase Base Smart Wallet (`@coinbase/wallet-sdk`):

```js
import { createBaseSmartWalletClient } from 'payguard-paybox-plugin/smart-wallet';

const client = createBaseSmartWalletClient({ appName: 'My dApp' });

// Inspect before signing — aborts on BLOCK or REVIEW
const result = await client.requestTransaction({
  to:    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
  value: '0',
  data:  '0x095ea7b3...'
}, {
  policy: { allowedSpenders: ['0xknown...'], maxAllowance: '1000000' }
});

if (result.aborted) {
  console.warn('Transaction aborted:', result.verdict, result.reasons);
}
```

Only transactions with a PASS verdict reach the `eth_sendTransaction` wallet prompt.

---

## Local Development & Observability

```bash
# Start Prometheus + Grafana + HTTP API
docker compose up --build -d payguard-api prometheus grafana

# Run k6 load tests
docker compose --profile loadtest run --rm k6 run /scripts/smoke.js
```

Grafana dashboard at `http://127.0.0.1:3000`. Prometheus at `http://127.0.0.1:9090`.

Metrics use low-cardinality labels; submitted URLs are never included in metric labels.

---

## Architecture

```
src/
  plugin.mjs           ← MCP plugin manifest, tool registry, stdio server
  calldata-inspector.mjs ← Pure EVM calldata decoder & risk evaluator
  token-security.mjs   ← GoPlus Token Security API client (Base 8453)
  address-security.mjs ← GoPlus Address Security API client (Base 8453)
  smart-wallet.mjs     ← Coinbase Base Smart Wallet SDK + pre-signing hook
dist/
  plugin.mjs/.cjs      ← Bundled plugin (ESM + CJS)
  index.mjs/.cjs       ← SDK index (ESM + CJS)
  index.d.ts           ← TypeScript declarations
  calldata-inspector.mjs/.cjs
  token-security.mjs/.cjs
  address-security.mjs/.cjs
```

See [`docs/architecture.md`](docs/architecture.md) for a detailed data-flow diagram.

---

## Documentation

| Document | Contents |
|----------|---------|
| [`docs/architecture.md`](docs/architecture.md) | Module architecture and data-flow diagrams |
| [`docs/security-model.md`](docs/security-model.md) | Security boundaries, threat model, privacy guarantees |
| [`docs/getting-started.md`](docs/getting-started.md) | Installation, configuration, and first steps |
| [`docs/mcp-tools.md`](docs/mcp-tools.md) | All six tools: schemas, examples, and verdict semantics |
| [`docs/whitepaper.md`](docs/whitepaper.md) | Full technical whitepaper |
| [`docs/judge-brief.md`](docs/judge-brief.md) | Vibeathon judge brief |
| [`docs/demo-script.md`](docs/demo-script.md) | 3–4 minute demo walkthrough |
| [`docs/limitations-roadmap.md`](docs/limitations-roadmap.md) | Current limitations and future roadmap |

---

## Testing

143 tests across 6 test modules covering adversarial inputs, failure modes, and security boundaries:

```bash
npm test
# tests 143 | pass 143 | fail 0
```

---

## License

MIT
