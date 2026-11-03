# PayGuard — Vibeathon Judge Brief

## What is PayGuard?

PayGuard is a **free, Base-first ecosystem security platform and advisory sentinel** that helps human users, developers, and autonomous AI agents inspect transactions, URLs, token honeypots, and on-chain addresses for risk *before* any signing or transfer action occurs.

Its core mission is: **Verify Before You Trust.**

PayGuard exposes **seven Model Context Protocol (MCP) tools** that any AI agent (Claude, Cursor, AutoGPT, or custom agent runtime) can invoke to receive structured, machine-readable security verdicts in real time.

---

## Disclosure: Pre-existing Project

> [!IMPORTANT]
> PayGuard originated prior to the Vibeathon build phase. The original baseline focused on x402 payment validation, local URL phishing heuristics, and draft threat reporting.

### Capabilities Expanded During the Vibeathon:

1. **Official Base Smart Wallet Integration:** Integrated `@coinbase/wallet-sdk@4.4.0` with pre-signing advisory guards that abort on `BLOCK` or `REVIEW` verdicts.
2. **GoPlus Token Security (Base Mainnet 8453):** Integrated comprehensive honeypot detection, buy/sell tax auditing, and arbitrary owner balance privileges.
3. **GoPlus Address Security (Base Mainnet 8453):** Integrated entity reputation screening (phishing records, sanctions, cybercrime, mixer usage).
4. **Base Wallet Token Scanner & Impersonation Engine:** Added the 7th MCP tool (`payguard_scan_wallet_tokens`) featuring a two-tier discovery architecture (Blockscout API v2 with on-chain RPC fallback) and lookalike token impersonation detection against canonical Base assets.
5. **Calldata Inspector:** Decodes EVM calldata (`approve`, `transfer`, `transferFrom`) and flags unlimited token allowances (`uint256.max`).
6. **Production Build & Test Suite Expansion:** Expanded the automated test suite and added a build that bundles ESM, CJS, type declarations and the stdio MCP server. Run `npm test` and check the latest CI run for the current result; the CJS bundle has a known issue (see [Limitations and Roadmap](limitations-roadmap.md)).

---

## The Security Problem PayGuard Solves

### 1. The Autonomous AI Agent Signing Problem
Modern AI agents are granted financial autonomy to hire compute, execute swaps, and interact with smart contracts. However:
- AI agents cannot see browser address bars or identify lookalike website domains.
- AI agents parse URLs lexically, leaving them vulnerable to invisible Unicode Bidi overrides and Punycode confusable tricks.
- AI agents blindly sign `uint256.max` unlimited ERC-20 approvals if prompted by malicious dApp interfaces.
- AI agents matching tokens by ticker symbol are easily tricked by lookalike counterfeit contracts.

### 2. The Three Common Web3 Misconceptions
- **HTTPS does not equal legitimacy:** Phishing websites obtain free SSL certificates in seconds.
- **Verified contract source code does not equal official:** Attackers verify source code on Basescan to conceal honeypots and drain mechanics.
- **A token name or symbol does not equal authenticity:** Anyone on Base can deploy a token named "USDC".

---

## The Seven MCP Tools

| Tool Name | Core Capability |
|-----------|-----------------|
| `payguard_check_payment_intent` | Evaluates x402 payment requirements against an explicit user intent policy |
| `payguard_analyze_url` | Local anti-phishing analysis (Bidi overrides, homoglyphs); never fetches the URL |
| `payguard_prepare_threat_report` | Generates privacy-redacted security incident drafts without leaking secrets |
| `payguard_inspect_calldata` | Decodes EVM calldata and detects unlimited `approve(spender, uint256.max)` |
| `payguard_check_token_security` | Audits Base Mainnet contracts via GoPlus for honeypot traps and trading taxes |
| `payguard_check_address_security` | Screens Base addresses for sanctions, cybercrime, and phishing records |
| `payguard_scan_wallet_tokens` | Two-tier discovery scanning Base wallet holdings for honeypots and impersonators |

---

## Verification & Technical Metrics

- **Repository:** `https://github.com/technea/PayGuard` (Branch: `main`)
- **Automated Tests:** `npm test` (see the latest CI run for results)
- **Tools Exposed:** **7 MCP tools** (`npm run build`)
- **Runtime Dependencies:** Zero external HTTP frameworks; only `@coinbase/wallet-sdk@4.4.0` for smart wallet client.
- **Fail-Closed Architecture:** All external API errors, timeouts, or unindexed tokens return `UNVERIFIED` — never `PASS`.
- **No user-directed fetching:** URL Sentinel analyzes URL text and never initiates a connection to the submitted URL. Provider calls go only to fixed endpoints.
- **Planned, not built:** an AI Security Agent. See [AI Security Agent](ai-security-agent.md).
- **No grant or funding is claimed.** See the [Whitepaper](whitepaper.md) for the roadmap.
