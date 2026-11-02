# Getting Started with PayGuard

## Prerequisites

- **Node.js 20 or later** — PayGuard uses native ESM, built-in `fetch`, `AbortController`, and the Node.js test runner.
- **npm 9+** — used for dependency management and script execution.
- **Docker** — optional, required only for Prometheus/Grafana observability.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/technea/PayGuard.git
cd PayGuard

# Install dependencies
npm install
```

The only runtime dependency is `@coinbase/wallet-sdk@4.4.0` (Base Smart Wallet integration). All security analysis modules use zero external runtime dependencies.

---

## Verify the Installation

```bash
# Run the complete test suite (143 tests)
npm test

# Build all distribution artifacts
npm run build
```

Expected output from `npm run build`:

```
Verified dist/plugin.mjs (6 tools exposed).
Build completed successfully: bundled ESM, CJS, DTS, and stdio MCP server.
```

---

## Environment Variables

Copy the provided example and configure as needed:

```bash
cp .env.example .env
```

| Variable | Required | Purpose |
|----------|----------|---------|
| `GOOGLE_WEB_RISK_API_KEY` | No | Enables Google Web Risk reputation lookup in URL Sentinel. Set server-side only; never expose to clients. |
| `GOPLUS_API_KEY` | No | GoPlus API bearer token for higher rate limits. Set server-side only. |
| `GRAFANA_ADMIN_PASSWORD` | Only for Docker | Grafana admin password. Use a long, unique random value. |

> [!CAUTION]
> Never commit `.env` to version control. Never put API keys in client-side code, frontend bundles, or MCP tool output.

---

## Usage Options

### Option 1: MCP stdio server (Claude, Cursor, any MCP host)

Run PayGuard as a JSON-RPC 2.0 stdio server that any MCP-compatible host can discover and call:

```bash
node dist/index.js
```

Or explicitly:
```bash
MCP_STDIO=1 node dist/plugin.mjs
```

The server responds to `initialize`, `tools/list`, and `tools/call` messages over stdin/stdout.

**Add to Claude Desktop (`claude_desktop_config.json`):**
```json
{
  "mcpServers": {
    "payguard": {
      "command": "node",
      "args": ["/absolute/path/to/PayGuard/dist/index.js"],
      "env": {
        "GOPLUS_API_KEY": "your-optional-key"
      }
    }
  }
}
```

### Option 2: Node.js module import

```js
import plugin from './dist/plugin.mjs';

// List all tools
console.log(plugin.tools.map(t => t.name));

// Invoke a tool
const result = await plugin.invokeTool('payguard_analyze_url', {
  url: 'https://payb0x-support.xyz/wallet-recovery'
});
```

### Option 3: Local HTTP API server

```bash
npm start
# Server starts at http://localhost:3000
```

### Option 4: Run the URL Sentinel demo

```bash
npm run demo
```

---

## Quick Examples

### Check a URL

```js
import { analyzeUrlSecurity } from './src/plugin.mjs';

const result = await analyzeUrlSecurity({
  url: 'https://paybox-support-wallet.xyz',
  expectedDomain: 'paybox.com'
});

console.log(result.verdict);    // "SUSPICIOUS"
console.log(result.riskLevel);  // "HIGH"
console.log(result.checks);     // Array of individual check findings
```

### Inspect EVM Calldata

```js
import { inspectCalldata } from './src/calldata-inspector.mjs';

// approve(spender, uint256.max) — unlimited ERC-20 allowance
const result = inspectCalldata({
  to:    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
  value: '0',
  data:  '0x095ea7b3' +
         '000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' +
         'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
});

console.log(result.verdict);    // "REVIEW"
console.log(result.operation);  // "ERC20_APPROVE"
console.log(result.details.isUnlimited); // true
```

### Check Token Security

```js
import { checkTokenSecurity } from './src/token-security.mjs';

const result = await checkTokenSecurity({
  chainId: 8453,
  contractAddress: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913' // USDC on Base
});

console.log(result.verdict);    // "PASS" or "REVIEW" or "BLOCK"
console.log(result.findings);   // Array of risk findings
```

### Check Address Security

```js
import { checkAddressSecurity } from './src/address-security.mjs';

const result = await checkAddressSecurity({
  chainId: 8453,
  address: '0x1234567890abcdef1234567890abcdef12345678'
});

console.log(result.verdict);    // "PASS" / "REVIEW" / "BLOCK" / "UNVERIFIED"
console.log(result.findings);   // Array of risk findings with severity
```

---

## GoPlus API Notes

- **No API key required** for the free tier. GoPlus keyless access is rate-limited.
- Set `GOPLUS_API_KEY` to increase limits. The key is sent as `Authorization: Bearer <key>`.
- Base Sepolia (chain ID 84532) is **not supported** by GoPlus. Attempting it returns `UNVERIFIED` / `UNSUPPORTED_CHAIN`.
- GoPlus is only queried when explicitly requested — not on every call automatically.
- All errors (timeouts, network failures, rate limits) fail **closed** to `UNVERIFIED`, never to a false `PASS`.

---

## Docker Observability Stack (Optional)

```bash
# Start API + Prometheus + Grafana
docker compose up --build -d payguard-api prometheus grafana

# Check status
docker compose ps

# Run smoke test (requires services running)
docker compose --profile loadtest run --rm k6 run /scripts/smoke.js

# Run load test
docker compose --profile loadtest run --rm k6 run /scripts/load.js

# Stop and preserve data
docker compose down

# Stop and delete metrics data
docker compose down -v
```

- **Grafana:** http://127.0.0.1:3000 (username: `admin`, password from `.env`)
- **Prometheus:** http://127.0.0.1:9090

---

## Running Tests

```bash
# Full test suite
npm test

# Specific test file
node --test test/calldata-inspector.test.mjs
node --test test/token-security.test.mjs
node --test test/address-security.test.mjs
node --test test/plugin.test.mjs
node --test test/smart-wallet.test.mjs
node --test test/paybox.test.mjs
```

---

## Build Artifacts

After `npm run build`:

| File | Description |
|------|-------------|
| `dist/plugin.mjs` | ESM plugin bundle (MCP entry point) |
| `dist/plugin.cjs` | CommonJS plugin bundle |
| `dist/plugin.js` | UMD-compatible bundle |
| `dist/index.mjs` / `.cjs` / `.js` | SDK index |
| `dist/index.d.ts` | TypeScript declarations |
| `dist/calldata-inspector.mjs` / `.cjs` | Standalone EVM inspector |
| `dist/token-security.mjs` / `.cjs` | Standalone GoPlus Token Security client |
| `dist/address-security.mjs` / `.cjs` | Standalone GoPlus Address Security client |
