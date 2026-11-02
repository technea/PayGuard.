# Getting Started with PayGuard

## Prerequisites

- **Node.js 20 or later** — PayGuard uses native ESM, built-in `fetch`, `AbortController`, and the Node.js test runner.
- **npm 9+** — used for dependency management and script execution.
- **Docker** — optional, required only for Prometheus/Grafana observability.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/technea/PayGuardgit
cd PayGuard

# Install dependencies
npm install
```

The only runtime dependency is `@coinbase/wallet-sdk@4.4.0` (for the Base Smart Wallet integration). All security analysis modules operate with **zero external runtime dependencies**.

---

## Verify the Installation

```bash
# Run the complete test suite (154 tests)
npm test

# Build all distribution artifacts
npm run build
```

Expected output from `npm run build`:

```
Verified dist/plugin.mjs (7 tools exposed).
Build completed successfully: bundled ESM, CJS, DTS, and stdio MCP server.
```

---

## Environment Variables

Copy the provided example and configure optional threat feed keys:

```bash
cp .env.example .env
```

| Variable | Required | Purpose |
|----------|----------|---------|
| `GOPLUS_API_KEY` | No | GoPlus API bearer token for higher rate limits. Set server-side only. |
| `GOOGLE_WEB_RISK_API_KEY` | No | Enables Google Web Risk reputation lookup in URL Sentinel. Set server-side only. |
| `PORT` | No | HTTP server port (defaults to 8080). |
| `GRAFANA_ADMIN_PASSWORD` | Only for Docker | Grafana dashboard admin password. |

> [!CAUTION]
> Never commit `.env` to version control. Never put API keys in client-side code, frontend bundles, or MCP tool output.

---

## Usage Options

### Option 1: Interactive Web Dashboard & Security Console

Start the built-in HTTP server:

```bash
npm start
# Server listens on http://localhost:8080
```

Open your browser:
- **Homepage & Mission Overview:** `http://localhost:8080/`
- **Interactive Security Dashboard:** `http://localhost:8080/dashboard`
- **Documentation & FAQ:** `http://localhost:8080/docs`

---

### Option 2: MCP stdio server (Claude, Cursor, AI Agents)

Run PayGuard as a JSON-RPC 2.0 stdio server that any MCP-compatible host can discover and call:

```bash
node dist/index.js
```

Or explicitly with the environment flag:
```bash
MCP_STDIO=1 node dist/plugin.mjs
```

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

---

### Option 3: Node.js Module Import

Import PayGuard directly into your backend or agent runtime:

```js
import plugin from './dist/plugin.mjs';

// 1. Scan a suspicious URL
const urlResult = await plugin.invokeTool('payguard_analyze_url', {
  url: 'https://bаse.org/claim', // Contains Cyrillic homoglyph
  expectedDomain: 'base.org'
});
console.log(urlResult.verdict); // "SUSPICIOUS"

// 2. Scan a Base wallet for honeypot and impersonating tokens
const walletResult = await plugin.invokeTool('payguard_scan_wallet_tokens', {
  walletAddress: '0x4200000000000000000000000000000000000006'
});
console.log(`Audited ${walletResult.tokensScannedCount} holdings. Status: ${walletResult.status}`);

// 3. Inspect proposed EVM calldata
const calldataResult = await plugin.invokeTool('payguard_inspect_calldata', {
  to: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  value: '0',
  data: '0x095ea7b30000000000000000000000001111111254fb6c44bac0bed2854e76f90643097dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
});
console.log(calldataResult.verdict); // "REVIEW" (unlimited allowance warning)
```

---

### Option 4: HTTP REST API

Call the endpoints via standard HTTP:

```bash
# Analyze a URL
curl -X POST http://localhost:8080/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://bases.org/login","expectedDomain":"base.org"}'

# Scan a Base wallet's token holdings
curl -X POST http://localhost:8080/api/scan-wallet-tokens \
  -H "Content-Type: application/json" \
  -d '{"walletAddress":"0x4200000000000000000000000000000000000006"}'
```
