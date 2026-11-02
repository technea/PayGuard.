# PayGuard — Vibeathon Judge Brief

## What is PayGuard?

PayGuard is a **Base-focused Web3 security platform** that helps AI agents and developers inspect transactions, URLs, and on-chain addresses for risk *before* any signing or payment action occurs.

It exposes six Model Context Protocol (MCP) tools that any AI agent (Claude, Cursor, or any MCP-compatible host) can call to get structured security intelligence in real time.

---

## Disclosure: Pre-existing Project

> [!IMPORTANT]
> PayGuard existed before the Vibeathon. The original project included x402 payment validation, URL phishing detection, and a threat report generator. These were working features prior to any competition work.

**Work completed during the Vibeathon build phase is documented separately in the section below.**

---

## The Security Problem PayGuard Solves

### The AI Agent Signing Problem

Modern AI agents are being given increasing financial autonomy — they can authorize payments, interact with DeFi protocols, and manage wallets. This creates a dangerous new attack surface:

- An agent browsing the web might encounter a phishing URL disguised with Unicode tricks
- An agent executing a transaction might approve unlimited ERC-20 spending to a malicious contract
- An agent completing a payment might be tricked into paying the wrong recipient, wrong amount, or wrong network
- A token contract might be a honeypot — tokens can be bought but never sold

Without a security layer, AI agents are exposed to the same threats that harm human users, with less intuitive judgment and no visual inspection capability.

### Why Existing Tools Don't Fully Solve This

- Wallet UIs show transaction data but AI agents don't have eyes
- RPC calls are opaque to agents unless decoded
- Existing security APIs are not designed for MCP/AI agent workflows
- No single tool covers URL, calldata, token, and address intelligence together

---

## How PayGuard Works

PayGuard sits *before* signing and *before* payment authorization. It provides structured, machine-readable security verdicts that an AI agent can interpret and act on.

```
AI Agent / dApp
      ↓
PayGuard Security Inspection (MCP)
      ↓
PASS → Proceed to signing
REVIEW → Surface findings to user, await decision
BLOCK → Abort signing request
UNVERIFIED → Insufficient data, advise caution
      ↓
Wallet / x402 Client
```

All analysis is **read-only**. PayGuard never signs, pays, or broadcasts anything.

---

## The Six MCP Tools

| Tool | What it does |
|------|-------------|
| `payguard_check_payment_intent` | Validates an x402 payment against an explicit user policy (network, asset, recipient, amount, scheme) |
| `payguard_analyze_url` | Detects phishing, Unicode/Bidi obfuscation, homoglyphs, lookalike domains, and suspicious URL patterns |
| `payguard_prepare_threat_report` | Generates a privacy-redacted threat report draft for review and submission |
| `payguard_inspect_calldata` | Decodes ERC-20 approve/transfer/transferFrom and checks against configurable allowlists and caps |
| `payguard_check_token_security` | Queries GoPlus for token risk on Base Mainnet: honeypot, taxes, transfer restrictions, owner controls |
| `payguard_check_address_security` | Queries GoPlus for address reputation: phishing, sanctions, money laundering, cybercrime |

All tools return a **verdict** (`PASS` / `REVIEW` / `BLOCK` / `UNVERIFIED`), a **riskLevel**, and detailed **findings** with explanation text.

---

## What is Functional Today

The following is fully implemented, tested (143/143 tests), and built:

✅ x402 payment intent policy validation
✅ URL Sentinel with phishing, IDN, Bidi, full-width Unicode, credential embedding detection
✅ Privacy-conscious threat report drafting
✅ EVM calldata decoder for ERC-20 approve, transfer, transferFrom
✅ Pre-signing abort hook (BLOCK/REVIEW stops before `eth_sendTransaction`)
✅ GoPlus Token Security integration for Base Mainnet (8453)
✅ GoPlus Address Security integration for Base Mainnet (8453)
✅ MCP stdio server (JSON-RPC 2.0, `initialize`, `tools/list`, `tools/call`)
✅ HTTP API server with rate limiting and Prometheus metrics
✅ ESM + CommonJS + TypeScript declarations distribution

---

## Vibeathon Build Phase — New Work Completed

The following features were **implemented during the Vibeathon build phase** and did not exist in the original project:

| Feature | Module | Tests |
|---------|--------|-------|
| EVM Calldata Inspector | `src/calldata-inspector.mjs` | 9 tests |
| `payguard_inspect_calldata` MCP tool | `src/plugin.mjs` | covered in plugin tests |
| Pre-signing transaction inspection in Base Smart Wallet | `src/smart-wallet.mjs` | 6 pre-signing tests |
| Unicode Bidi control character detection (pre-parser) | `src/plugin.mjs` | 5 adversarial tests |
| Full-width/NFKC confusable hostname check | `src/plugin.mjs` | covered in plugin tests |
| GoPlus Token Security integration | `src/token-security.mjs` | 19 tests |
| `payguard_check_token_security` MCP tool | `src/plugin.mjs` | covered in plugin tests |
| GoPlus Address Security integration | `src/address-security.mjs` | 17 tests |
| `payguard_check_address_security` MCP tool | `src/plugin.mjs` | covered in plugin tests |
| Complete technical documentation (9 documents) | `docs/` | — |

**Total new tests added:** 51+ (beyond the original baseline of ~84)
**Final test count:** 143 passing

---

## What Makes the Approach Useful

### For AI Agents
- Tools return structured JSON — no natural language parsing required
- Verdicts are unambiguous: PASS / REVIEW / BLOCK / UNVERIFIED
- Detailed `findings` arrays give agents explainable reasoning, not just a score
- `BLOCK` in the pre-signing path is automatically enforced — agents don't need to re-implement the abort logic

### For Developers
- Zero external runtime dependencies in core security modules
- Injectable `fetchImpl` enables fully deterministic offline tests
- Native Node.js ESM — no build step required for source modules
- MCP-compatible out of the box — any MCP host can discover and call tools

### For Base Ecosystem Users
- Tailored for Base Mainnet — GoPlus chain ID 8453 support verified
- Base Smart Wallet SDK integration built-in
- x402 protocol support for the emerging agent payment standard

---

## Live Demo Walkthrough (3 minutes)

*See `docs/demo-script.md` for the full annotated demo.*

1. **Phishing URL detection** — Submit a lookalike domain with Bidi controls → SUSPICIOUS/BLOCK
2. **Unlimited ERC-20 approval** — Inspect `approve(spender, uint256.max)` calldata → REVIEW with UNLIMITED_ALLOWANCE finding
3. **Honeypot token** — Check a token contract with GoPlus → BLOCK with HONEYPOT_DETECTED
4. **Sanctioned address** — Check a flagged address → BLOCK with SANCTIONED_ADDRESS
5. **Pre-signing abort** — Show `requestTransaction()` with a BLOCK verdict → `{ aborted: true }` before wallet sees it

---

## Known Limitations

1. GoPlus supports Base Mainnet only — Base Sepolia (testnet) is not indexed
2. Only 3 ERC-20 selectors are decoded — other calldata yields advisory REVIEW
3. No EIP-712 typed-data / permit inspection
4. No on-chain simulation
5. Verdicts are advisory — enforcement outside PayGuard's signing path is the caller's responsibility
6. GoPlus data quality and coverage are third-party controlled

*Full limitations documented in `docs/limitations-roadmap.md`.*

---

## Technical Verification

- **Tests:** 143/143 passing (`npm test`)
- **Build:** Clean (`npm run build` → "Verified dist/plugin.mjs (6 tools exposed)")
- **Branch:** `feat/base-smart-wallet-sdk`
- **No private keys, no signing, no transaction broadcasting** in any code path
- **API keys:** Server-side env vars only, verified absent from dist bundles
