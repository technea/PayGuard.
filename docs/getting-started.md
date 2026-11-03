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

The only runtime dependency is `@coinbase/wallet-sdk@4.4.0` (for the Base Smart Wallet integration). All security analysis modules operate with **zero external runtime dependencies**.

---

## Verify the Installation

```bash
# Run the complete test suite
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

PayGuard reads configuration from environment variables. The repository does not currently include an `.env.example`; create a `.env` of your own or set the variables in your shell or hosting platform:

| Variable | Required | Purpose |
|----------|----------|---------|
| `GOPLUS_API_KEY` | No | GoPlus API bearer token for higher rate limits. Set server-side only. |
| `GOOGLE_WEB_RISK_API_KEY` | No | Enables Google Web Risk reputation lookup in URL Sentinel. Set server-side only. |
| `PORT` | No | HTTP server port (defaults to 8080). |
| `HOST` | No | Bind address. The Docker Compose file sets `0.0.0.0`. |
| `MAX_REQUESTS_PER_WINDOW` | No | Per-IP requests per 60 seconds (default 120). |
| `MAX_CONCURRENT_REQUESTS` | No | In-flight request cap (default 100). |
| `NODE_ENV` | No | Set to `development` to include error details in 500 responses. |
| `MCP_STDIO` | No | Set to `1` to start the stdio MCP server from `dist/plugin.mjs`. |
| `PAYGUARD_REQUIRE_X402` | No | Set to `true` to require x402 payment on POST endpoints. See [API Reference](api-reference.md). |
| `PAYGUARD_NETWORK`, `PAYGUARD_ASSET`, `PAYGUARD_PAY_TO`, `X402_FACILITATOR_URL`, `X402_LIVE_SETTLEMENT` | No | x402 payment-gate settings. Defaults are Base Sepolia test values. |
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
console.log(`Audited ${walletResult.summary.totalTokensScanned} holdings. Mode: ${walletResult.discoveryMode}`);

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

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js 20 or later, native ES modules, built-in `fetch` and test runner |
| HTTP server | Node `http` module, no web framework (`server.mjs`) |
| Hosting | Docker (`node:22-alpine`), or Vercel through `api/index.mjs` |
| Frontend | Plain HTML, CSS and JavaScript; Tailwind CSS compiled by `npm run build:css` |
| Runtime dependency | `@coinbase/wallet-sdk` 4.4.0 (smart-wallet wrapper) |
| Dev dependency | `@x402/core` 2.29.0 (x402 SDK) |
| Providers | GoPlus, Blockscout, Base public RPC, Google Web Risk (optional) |
| Observability | Prometheus metrics at `/metrics`; Prometheus and Grafana in Docker Compose |

---

## Project Structure

| Path | Contents |
|------|----------|
| `src/plugin.mjs` | MCP plugin, tool registry, URL Sentinel, payment guard, stdio server |
| `src/calldata-inspector.mjs` | Calldata decoding and policy checks |
| `src/token-security.mjs`, `src/address-security.mjs` | GoPlus integrations |
| `src/wallet-token-scanner.mjs` | Wallet scan, canonical registry, impersonation check |
| `src/smart-wallet.mjs` | Opt-in Base smart-wallet wrapper |
| `server.mjs`, `api/index.mjs` | HTTP server and Vercel entry |
| `paybox.mjs` | x402 challenge, Bazaar metadata, payment-proof verification |
| `public/` | Landing page, dashboard, docs template |
| `docs/` | This documentation |
| `scripts/` | `build.mjs`, `build-tailwind.mjs`, `render-docs.mjs` |
| `test/` | Node test-runner suites for each module and the server |
| `k6/`, `observability/` | Load test and Prometheus and Grafana configuration |

---

## Testing and Validation

```bash
npm test
```

This runs `node --test test/*.test.mjs`. The suites need the installed dependencies; the smart-wallet and plugin suites fail if `@coinbase/wallet-sdk` is not installed. Provider-backed tests use mocked fetch implementations, so a passing run does not show that GoPlus, Blockscout or Base RPC behave as expected today. CI runs on every push and pull request. Check the latest CI run for the current result rather than relying on a number in this page.

---

## Deployment

- **Docker:** `docker compose up` builds the image and starts the API on `127.0.0.1:8080`, with Prometheus and Grafana. The image copies `package.json`, `server.mjs` and `src/`; confirm that your deployment also includes `public/`, `docs/` and `paybox.mjs` if you serve the dashboard and docs from it.
- **Vercel:** `vercel.json` routes all requests to `api/index.mjs` and includes `server.mjs`, `paybox.mjs`, `src/` and `public/`. Run `npm run build` so the compiled stylesheet is present. Documentation pages read from `docs/` and `README.md` at runtime.
- **Behind a proxy:** configure the proxy to set a trustworthy `x-forwarded-for`, because the rate limiter relies on it.

---

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Token or address result is `UNVERIFIED` with `NETWORK_ERROR` | Provider unreachable or timed out (3 second limit) | Check outbound access; retry later. This is expected fail-closed behavior |
| Wallet scan shows `REGISTRY_AND_CUSTOM_PARTIAL` | Blockscout indexer unavailable | Supply `customTokenAddresses`, or accept partial coverage |
| `UNSUPPORTED_CHAIN` | Chain other than 8453 requested | Use Base Mainnet |
| HTTP 429 | Rate limit or concurrency cap | Slow down, or raise `MAX_REQUESTS_PER_WINDOW` |
| HTTP 402 | `PAYGUARD_REQUIRE_X402=true` | Supply a payment header or disable the gate |
| `Tailwind stylesheet is not built` at `/assets/css/tailwind.css` | CSS not built | Run `npm run build:css` |
| `npm test` fails in smart-wallet or plugin suites | Dependencies not installed | Run `npm install` |
| `require('./dist/index.cjs')` fails | Known CommonJS build issue | Use the ES module build (`dist/index.mjs`) |
