# PayGuard — Frequently Asked Questions (FAQ)

**Version 0.1.0 | November 2026**
*Mission: Verify Before You Trust*
*Repository: https://github.com/technea/PayGuard*

---

### Table of Contents

1. [General Overview](#general-overview)
   - [What is PayGuard?](#what-is-payguard)
   - [Is PayGuard free to use?](#is-payguard-free-to-use)
   - [Does PayGuard require a subscription or trial?](#does-payguard-require-a-subscription-or-trial)
   - [How can users support PayGuard?](#how-can-users-support-payguard)
2. [Ecosystem & Phishing Defense](#ecosystem--phishing-defense)
   - [Does HTTPS mean a website is legitimate?](#does-https-mean-a-website-is-legitimate)
   - [Can PayGuard identify fake Base ecosystem websites?](#can-payguard-identify-fake-base-ecosystem-websites)
   - [How does PayGuard inspect URLs without risking SSRF?](#how-does-payguard-inspect-urls-without-risking-ssrf)
3. [Token & Contract Verification](#token--contract-verification)
   - [How does token verification work?](#how-does-token-verification-work)
   - [Does a verified contract on Basescan mean a token is official?](#does-a-verified-contract-on-basescan-mean-a-token-is-official)
   - [Can a token name or symbol establish authenticity?](#can-a-token-name-or-symbol-establish-authenticity)
   - [Can PayGuard detect every scam token?](#can-payguard-detect-every-scam-token)
   - [How does the Base Wallet Token Scanner work?](#how-does-the-base-wallet-token-scanner-work)
4. [Security Boundaries & Enforcement](#security-boundaries--enforcement)
   - [Does PayGuard automatically block transactions?](#does-payguard-automatically-block-transactions)
   - [Does PayGuard freeze, hide, or quarantine on-chain assets?](#does-payguard-freeze-hide-or-quarantine-on-chain-assets)
   - [Does PayGuard store or access private keys?](#does-payguard-store-or-access-private-keys)
   - [Why should users verify before connecting a wallet or signing?](#why-should-users-verify-before-connecting-a-wallet-or-signing)
5. [AI Agents & Model Context Protocol (MCP)](#ai-agents--model-context-protocol-mcp)
   - [Does PayGuard support AI agents and MCP?](#does-payguard-support-ai-agents-and-mcp)
   - [Which MCP tools are available?](#which-mcp-tools-are-available)
   - [What are the current limitations of PayGuard?](#what-are-the-current-limitations-of-payguard)

---

## General Overview

### What is PayGuard?
PayGuard is a free, Base-first ecosystem security platform and advisory sentinel built for human users, developers, and autonomous AI agents. Its core mission is **"Verify Before You Trust."**

PayGuard helps users identify:
- Phishing websites and lookalike domains impersonating official Base ecosystem projects (e.g., `base.org` vs `bases.org`).
- Fake and impersonated ERC-20 tokens copying canonical names and ticker symbols.
- Malicious smart contract mechanics (honeypots, hidden taxes, arbitrary balance modification, transfer pausing).
- High-risk counterparty addresses (phishing records, sanctions, darkweb or mixer interactions).
- Suspicious transaction calldata (such as unlimited `uint256.max` ERC-20 approvals).
- Deceptive x402 payment intent requirements.

PayGuard operates on a strict **inspect first, never act** principle. It performs deterministic, advisory evaluations and provides machine-readable intelligence so you can decide whether to proceed.

---

### Is PayGuard free to use?
**Yes.** PayGuard is completely free to use. All interactive security tools in the web dashboard, the HTTP API endpoints, and the Model Context Protocol (MCP) tool suite are accessible without cost.

---

### Does PayGuard require a subscription or trial?
**No.** There are no mandatory subscriptions, paywalls, credit cards, or hidden trial periods. PayGuard is designed to be an accessible public security utility for the Base and Web3 community.

---

### How can users support PayGuard?
PayGuard is maintained as an open-source security project for the Base ecosystem. Users and developers who wish to support the initiative can:
- Star and contribute to the GitHub repository at [https://github.com/technea/PayGuard](https://github.com/technea/PayGuard).
- Report deceptive domains, newly discovered honeypot contracts, or phishing vectors.
- Integrate PayGuard's MCP tools into autonomous AI agent workflows (Claude, Cursor, LangChain).
- Voluntary community donations may be accepted in the future to fund infrastructure, RPC nodes, and threat intelligence feeds, but donations are strictly voluntary and optional.

---

## Ecosystem & Phishing Defense

### Does HTTPS mean a website is legitimate?
**No, absolutely not.**

A common misconception in Web3 is that an HTTPS padlock icon proves that a website is safe or official. In reality:
- HTTPS only proves that the connection between your browser and the remote server is encrypted.
- Anyone can register a phishing domain (like `bases.org` or `claim-base-airdrop.xyz`) and obtain a free TLS/SSL certificate from Let's Encrypt in seconds.
- Threat actors routinely serve malicious dApps over HTTPS.

PayGuard's URL Sentinel ignores the padlock and inspects what actually matters: lexical similarity to legitimate brands, Internationalized Domain Name (IDN) Punycode homoglyphs, bidirectional Unicode override exploits, deceptive subdomains, and credential leaks.

---

### Can PayGuard identify fake Base ecosystem websites?
**Yes.** PayGuard incorporates specialized detection rules for Base ecosystem projects and infrastructure:
1. **Homoglyph & Confusable Detection:** Flags visually identical Cyrillic, Greek, or full-width characters (e.g., `bаse.org` where `а` is Cyrillic U+0430).
2. **Sibling & Suffix Spoofing:** Flags attacker subdomains mimicking official brands (e.g., `base.org.attacker-domain.com`).
3. **Punycode Deobfuscation:** Decodes `xn--` representations to surface the true underlying character sets.
4. **Target Allowlist Comparison:** Allows callers to pass an `expectedDomain` (e.g., `base.org`) and computes normalized string distance metrics.

---

### How does PayGuard inspect URLs without risking SSRF?
Server-Side Request Forgery (SSRF) occurs when a security scanner attempts to visit an attacker-supplied link and is tricked into querying private internal servers or cloud metadata services.

PayGuard's URL Sentinel does not fetch user-supplied URLs, so it adds no SSRF surface:
- The URL analysis runs locally and in memory.
- It uses the standard WHATWG URL parser and lexical pattern matchers locally.
- PayGuard **never fetches, opens, pings, or resolves** the target host.
- Other tools call fixed provider endpoints (GoPlus, Base RPC, Blockscout) and, only when you request it, Google Web Risk.
- High-entropy tokens, API keys, passwords, and sensitive query strings are scrubbed locally before any optional reputation check.

---

## Token & Contract Verification

### How does token verification work?
PayGuard provides a dual-layer approach to token verification on Base Mainnet (Chain ID 8453):
1. **Canonical Registry & Impersonation Engine:** Compares the asset contract address and symbol against an authoritative registry of official Base tokens (e.g., canonical WETH, native USDC, cbETH, VIRTUAL, DAI, USDbC, AERO). If an unknown contract uses the ticker "USDC", PayGuard flags it immediately as an **IMPERSONATION** risk.
2. **GoPlus Security Intelligence:** Evaluates over 30 on-chain security parameters, including:
   - Honeypot status (`is_honeypot` — whether buyers are prevented from selling).
   - Arbitrary balance modification (`owner_change_balance` — whether the contract creator can mint to themselves or wipe user balances).
   - Excessive buy or sell taxes (slippage traps).
   - Pausable transfers (`is_airdrop_scam` / `transfer_pausable`).
   - Hidden mint functions and proxy implementation volatility.

---

### Does a verified contract on Basescan mean a token is official?
**No.**

"Contract verification" on Basescan or Etherscan only means that the compiler output matches the submitted Solidity source code. It does **not** mean:
- The contract is safe.
- The project is officially endorsed.
- The creator cannot drain funds or pause trading.

Malicious actors intentionally verify their contract source code on block explorers to appear legitimate. PayGuard evaluates the contract's actual operational rules, owner privileges, and honeypot mechanics rather than relying on source verification badges.

---

### Can a token name or symbol establish authenticity?
**No.**

On Ethereum and Base, anyone can deploy an ERC-20 contract with any name and ticker symbol. Deploying a contract named "USD Coin" with the symbol "USDC" costs pennies in gas.

Authenticity can only be established by comparing the **exact, immutable contract address** against authoritative ecosystem registries. PayGuard flags any contract that adopts a well-known canonical symbol without matching the official contract address.

---

### Can PayGuard detect every scam token?
**No.** PayGuard does not make absolute security guarantees.

Limitations to keep in mind:
- **Zero-Day / Brand New Contracts:** Brand new scam contracts deployed minutes ago may not yet be indexed in threat intelligence feeds. PayGuard marks unindexed contracts as `UNVERIFIED / UNINDEXED_TOKEN` (failing closed), never as `PASS`.
- **Complex Economic Exploits:** PayGuard evaluates contract logic and known indicators, but does not simulate flash loan attacks, oracle manipulation, or cross-protocol economic exploits.

---

### How does the Base Wallet Token Scanner work?
The Base Wallet Token Scanner (`payguard_scan_wallet_tokens` / `/api/scan-wallet-tokens`) inspects ERC-20 assets associated with a Base Mainnet wallet address.

It uses a two-tier discovery architecture:
1. **Tier 1 (Full Indexer):** Queries the Blockscout Base API v2 (`GET https://base.blockscout.com/api/v2/addresses/{addr}/tokens?type=ERC-20`). If accessible, it returns all discovered ERC-20 tokens.
2. **Tier 2 (RPC Fallback):** When automated requests encounter indexer protections (such as Cloudflare bot management), PayGuard falls back to direct `eth_call` multicall queries against the official Base RPC (`https://mainnet.base.org`). The fallback queries the curated canonical Base token registry plus any optional `customTokenAddresses` supplied by the user.

Every discovered token with a non-zero balance is audited for honeypot mechanics and symbol impersonation. The response includes an explicit `discoveryMode` (`FULL_INDEXER` or `REGISTRY_AND_CUSTOM_PARTIAL`) so users are always aware of scan coverage.

---

## Security Boundaries & Enforcement

### Does PayGuard automatically block transactions?
**Outside of PayGuard-controlled signing paths, no.**

PayGuard is an **advisory intelligence sentinel**. It delivers structured verdicts (`PASS`, `REVIEW`, `BLOCK`, `UNVERIFIED`) with human-readable guidance and machine-readable risk factors.

- **In general dApps / wallets:** A `BLOCK` verdict informs the user or AI agent that a high-risk indicator was detected, but PayGuard cannot forcibly seize or block an external third-party wallet.
- **In PayGuard's Base Smart Wallet SDK client (`src/smart-wallet.mjs`):** The client's `requestTransaction()` method enforces pre-signing inspection and automatically aborts if the calldata inspection verdict is not `PASS`.

---

### Does PayGuard freeze, hide, or quarantine on-chain assets?
**No.** PayGuard is non-custodial and read-only. It has no on-chain administrative privileges and cannot freeze tokens, burn contracts, or alter blockchain state. It reports security findings to the user.

---

### Does PayGuard store or access private keys?
**Never.** PayGuard has zero access to private keys, seed phrases, hardware wallet credentials, or browser keystores. No module in PayGuard ever accepts a private key as input or stores cryptographic secrets.

---

### Why should users verify before connecting a wallet or signing?
Once a transaction is signed and confirmed on an EVM blockchain:
- Smart contract execution is irreversible.
- If you approve an unlimited allowance (`uint256.max`) to a malicious spender contract, the spender can drain your tokens at any time in the future without asking for another signature.
- If you connect your wallet to a phishing dApp, you risk signing malicious EIP-712 permits or lookalike transfers.

**Verification before signing is the only moment where funds can be protected.**

---

## AI Agents & Model Context Protocol (MCP)

### Does PayGuard support AI agents and MCP?
**Yes.** PayGuard is built from the ground up for the Model Context Protocol (MCP). It can run as a standard JSON-RPC 2.0 stdio server, allowing AI models (such as Claude Desktop, Cursor, or autonomous agent frameworks) to invoke security inspections natively before executing tool calls.

---

### Which MCP tools are available?
PayGuard exports **7 Model Context Protocol tools**:

1. `payguard_check_payment_intent` — Compares x402 payment requirements against an explicit user policy.
2. `payguard_analyze_url` — Inspects URLs locally for homoglyphs, Bidi overrides, and impersonation.
3. `payguard_prepare_threat_report` — Generates privacy-redacted security drafts for human or team review.
4. `payguard_inspect_calldata` — Decodes EVM calldata (`approve`, `transfer`, `transferFrom`) and flags unlimited approvals or untrusted spenders.
5. `payguard_check_token_security` — Audits Base Mainnet ERC-20 contracts using GoPlus intelligence for honeypots and trading taxes.
6. `payguard_check_address_security` — Screens Base addresses against known phishing, sanction, and cybercrime registries.
7. `payguard_scan_wallet_tokens` — Scans Base Mainnet wallet holdings to surface honeypots, balance-drain risks, and impersonated tokens.

---

### What are the current limitations of PayGuard?
In keeping with our transparency principles, PayGuard's current limitations include:
- **Base Mainnet Only for GoPlus:** GoPlus intelligence is active on Base Mainnet (8453). Base Sepolia (84532) returns `UNVERIFIED / UNSUPPORTED_CHAIN`.
- **Three Core EVM Selectors:** Calldata inspection decodes standard ERC-20 methods (`approve`, `transfer`, `transferFrom`). Complex DEX aggregators or custom multicalls return advisory `REVIEW`.
- **Static Analysis Only:** PayGuard does not execute on-chain sandbox simulations (debug trace calls).
- **Partial Wallet Scan on RPC Fallback:** When external indexers are unreachable due to bot protection, the wallet scanner checks the 7 canonical Base tokens and caller-specified addresses rather than the entire universe of unsolicited tokens.
- **Fail-Closed on Outages:** If an upstream threat provider times out, PayGuard returns `UNVERIFIED`, never `PASS`.

---

*For further details, refer to the [Architecture Documentation](architecture.md), [Security Model](security-model.md), and [Limitations & Roadmap](limitations-roadmap.md).*

---

### Does PayGuard have an AI agent?
Not yet. PayGuard exposes seven tools that an AI agent can call through MCP, but PayGuard does not include its own investigating agent. An AI Security Agent that would coordinate the tools, correlate evidence and explain findings is a planned development objective. See [AI Security Agent](ai-security-agent.md).

### Has PayGuard received a grant or funding?
No grant or funding is claimed in this documentation. The [Whitepaper](whitepaper.md) describes a development roadmap as a proposal.
