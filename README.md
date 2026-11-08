# PayGuard — Verify Before You Trust

**A free, Base-first ecosystem security platform for humans and autonomous AI agents.**

PayGuard provides read-only, advisory security intelligence before wallet signing, token interaction, or payment authorization. Guided by the mission **"Verify Before You Trust,"** PayGuard helps users and autonomous agents determine whether a website, token, or project is actually what it claims to be.

```
       +--------------------------------------------------------+
       |             PayGuard — Verify Before You Trust         |
       |  Pre-Signing Security Sentinel for the Base Ecosystem  |
       +--------------------------------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
+-------------------------+                         +-------------------------+
|     For Human Users     |                         |   For Autonomous Agents |
|  - Interactive Web App  |                         |  - 8 Native MCP Tools   |
|  - Phishing URL Scanner |                         |  - In-Memory Anti-SSRF  |
|  - Base Wallet Scanner  |                         |  - Calldata Decoder     |
|  - Honeypot Auditing    |                         |  - GoPlus Threat Feeds  |
+-------------------------+                         +-------------------------+
```

> [!IMPORTANT]
> **Advisory Sentinel Only:** PayGuard does not sign, authorize, or execute transactions outside explicit opt-in client instances. Verdicts of `PASS`, `REVIEW`, `BLOCK`, or `UNVERIFIED` are actionable findings for humans and AI agents, not automated custodial gates.

---

## Three Non-Negotiable Web3 Realities

Traditional web security assumptions fail in Web3. PayGuard is engineered around three fundamental truths:

1. **HTTPS does not prove a website is legitimate.**
   An HTTPS padlock only confirms an encrypted TLS connection. Phishers register lookalike domains (e.g. `bases.org` or `airdrop-base.xyz`) and issue free SSL certificates in seconds.
2. **Verified contract source code does not prove a token is official.**
   "Source verification" on Basescan simply matches compiler output to source text. Honeypot creators routinely verify their Solidity code to appear legitimate while hiding malicious owner balance modification backdoors.
3. **A token name or symbol alone cannot establish authenticity.**
   Anyone can deploy an ERC-20 contract named "USD Coin" with ticker "USDC". Authenticity can only be established by verifying the exact, immutable contract address against canonical ecosystem registries.

---

## The Eight MCP Tools

PayGuard exposes **eight Model Context Protocol (MCP) tools** compatible with Claude Desktop, Cursor, and any MCP-compliant autonomous agent framework:

| Tool | Capability |
|------|------------|
| `payguard_check_payment_intent` | Validate x402 payment requirements against an explicit user intent policy |
| `payguard_analyze_url` | Local anti-phishing analysis (Bidi overrides, Punycode homoglyphs); never fetches the URL |
| `payguard_prepare_threat_report` | Generate privacy-redacted security incident drafts without leaking secrets |
| `payguard_inspect_calldata` | Decode EVM calldata (`approve`, `transfer`) and flag unlimited approvals (`uint256.max`) |
| `payguard_check_token_security` | GoPlus honeypot, tax, and owner balance privilege assessment (Base Mainnet 8453) |
| `payguard_check_address_security` | GoPlus address reputation screening (phishing, sanctions, cybercrime, mixers) |
| `payguard_scan_wallet_tokens` | Two-tier discovery scanning Base wallet holdings for honeypots and impersonators |
| `payguard_run_security_assessment` | Run bounded multi-signal checks and correlate a selected x402 payment option with decoded ERC-20 transfer calldata |

The composite assessment returns a deterministic evidence report with `VERIFIED`, `RISK_DETECTED`, `UNVERIFIED`, `NOT_CHECKED`, and `ERROR` states. It does not call an LLM or perform transactions.

All tools return structured JSON with a **verdict** (`PASS` / `REVIEW` / `BLOCK` / `UNVERIFIED`), **riskLevel**, and detailed **findings**.

---

## Installation & Verification

**Requires Node.js 20 or later.**

```bash
# Clone the repository
git clone https://github.com/technea/PayGuardgit
cd PayGuard

# Install dependencies (only @coinbase/wallet-sdk for smart wallet client)
npm install

# Run the complete test suite
npm test

# Build ESM, CommonJS, TypeScript declarations, and stdio MCP server
npm run build

# Start the interactive web dashboard & API server
npm start
```

When started, access:
- **Homepage & Mission Overview:** `http://localhost:8080/`
- **Interactive Security Console:** `http://localhost:8080/dashboard`
- **Documentation Hub:** `http://localhost:8080/docs`

---

## MCP Agent Integration

Run PayGuard as a JSON-RPC 2.0 stdio server:

```bash
node dist/index.js
# or explicitly:
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

## Node.js Module Usage

```js
import plugin from './dist/plugin.mjs';

// 1. Scan a suspicious lookalike URL
const urlResult = await plugin.invokeTool('payguard_analyze_url', {
  url: 'https://bаse.org/claim', // Contains Cyrillic homoglyph 'а'
  expectedDomain: 'base.org'
});
console.log(urlResult.verdict); // "SUSPICIOUS"

// 2. Scan a Base wallet for suspicious token holdings
const walletResult = await plugin.invokeTool('payguard_scan_wallet_tokens', {
  walletAddress: '0x4200000000000000000000000000000000000006'
});
console.log(`Audited ${walletResult.tokensScannedCount} holdings. Mode: ${walletResult.discoveryMode}`);

// 3. Inspect EVM calldata before signing
const calldataResult = await plugin.invokeTool('payguard_inspect_calldata', {
  to: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  value: '0',
  data: '0x095ea7b3000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef00000000000000000000000000000000000000000000000000000000000f4240'
});
console.log(calldataResult.verdict); // "PASS"
```

---

## Technical Documentation & Resources

- [Architecture Overview](docs/architecture.md)
- [Security Model & Threat Landscape](docs/security-model.md)
- [MCP Tools Reference (7 Tools)](docs/mcp-tools.md)
- [API Reference](docs/api-reference.md)
- [AI Security Agent (planned design)](docs/ai-security-agent.md)
- [Getting Started Guide](docs/getting-started.md)
- [Technical Whitepaper](docs/whitepaper.md)
- [Frequently Asked Questions (FAQ)](docs/faq.md)
- [Limitations & Roadmap](docs/limitations-roadmap.md)
- [Vibeathon Judge Brief](docs/judge-brief.md)
- [Demo Script](docs/demo-script.md)

---

## License & Community

PayGuard is open-source under the MIT License. Built for the Base ecosystem and autonomous AI agent communities.
