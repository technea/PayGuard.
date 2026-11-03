# PayGuard Technical Whitepaper

**A Base-First Pre-Signing Security Layer for Humans and Autonomous AI Agents**

**Version 1.1.0 | November 2026**
*Mission: Verify Before You Trust*
*Repository: https://github.com/technea/PayGuard | Branch: main*

> **Evidence policy.** Every capability in this paper is labeled **Implemented and tested**, **Implemented, not verified live**, or **Planned**. PayGuard never claims a scan, detection or protection works without a test or recorded evidence behind it. Section 16 lists what is not yet proven.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Problem: Impersonation and Pre-Signing Risk](#2-the-problem-impersonation-and-pre-signing-risk)
3. [Mission and Positioning](#3-mission-and-positioning)
4. [Why HTTPS Does Not Mean a Website Is Legitimate](#4-why-https-does-not-mean-a-website-is-legitimate)
5. [Why Verified Contract Source Does Not Prove Safety](#5-why-verified-contract-source-does-not-prove-safety)
6. [Why Token Names and Symbols Cannot Establish Identity](#6-why-token-names-and-symbols-cannot-establish-identity)
7. [Security Architecture and Invariants](#7-security-architecture-and-invariants)
8. [x402 Payment-Intent Guard](#8-x402-payment-intent-guard)
9. [URL Sentinel](#9-url-sentinel)
10. [Token, Address and Wallet Security](#10-token-address-and-wallet-security)
11. [Calldata Inspection](#11-calldata-inspection)
12. [Base Ecosystem Integration](#12-base-ecosystem-integration)
13. [Interfaces: REST API, MCP Tools, Console](#13-interfaces-rest-api-mcp-tools-console)
14. [Threat Model and Security Boundaries](#14-threat-model-and-security-boundaries)
15. [Capability Status](#15-capability-status)
16. [Known Limitations and Unverified Items](#16-known-limitations-and-unverified-items)
17. [Roadmap](#17-roadmap)

---

## 1. Executive Summary

Irreversible on-chain payments meet two growing risks: people are tricked by look-alike domains, tokens and approvals, and autonomous AI agents now pay for services over HTTP (the x402 protocol) with no human reading the request. Once a transaction settles on Base, it cannot be reversed.

PayGuard is a free, open, **advisory** security layer that returns one of four verdicts before a user or agent acts:

| Verdict | Meaning |
| :--- | :--- |
| `PASS` | Every check that ran passed. Not a guarantee of safety. |
| `REVIEW` | Something needs human or policy attention. |
| `BLOCK` | A check found a clear violation or high-risk signal. |
| `UNVERIFIED` | Evidence was unavailable. PayGuard does not guess. |

Core design rules:

- **Zero custody.** PayGuard never requests, stores or handles private keys, seed phrases or signatures, and never broadcasts transactions.
- **Fail closed.** Timeouts, upstream errors, unsupported chains and unindexed contracts return `UNVERIFIED` or `BLOCK`, never a silent `PASS`.
- **Policy from the user, not the payer.** The x402 guard compares a payment request against a policy the user or developer wrote in advance. It never trusts values taken from the request being judged.
- **Exact identity, not appearance.** Tokens are identified by contract address, domains by normalized hostname, never by displayed name.
- **Honest scope.** Base Mainnet (chain ID 8453) first. Other chains return `UNVERIFIED`.

---

## 2. The Problem: Impersonation and Pre-Signing Risk

### 2.1 Attack vectors

| Attack vector | Mechanism | Impact |
| :--- | :--- | :--- |
| Domain typosquatting and homoglyphs | Look-alike hostnames (`bases.org`, Cyrillic `а` in `bаse.org`) | Wallet connected to a drainer |
| Token look-alike impersonation | Contract copies a canonical ticker such as `USDC` | Victim buys a worthless token |
| Honeypot logic | `buy()` works, `sell()` reverts or is taxed heavily | Total loss of capital |
| Owner balance control | Privileged mint or balance edit | Holders wiped or liquidity drained |
| Unlimited allowance | `approve(spender, 2^256 - 1)` | Spender can drain tokens at any later time |
| Malicious payment request (x402) | Swapped `payTo`, inflated amount, wrong asset or network, plain-HTTP quote | Agent pays the wrong party or too much |
| Signature-based drains | Permit, Permit2 and EIP-712 typed-data signatures | Funds moved without an on-chain approval |
| Delegation phishing (EIP-7702) | Account delegated to a malicious contract | Wallet swept |
| Counterparty risk | Address linked to sanctions or crime | Compliance and reputation loss |

Rows 7 and 8 are known attack classes. PayGuard does **not** yet inspect them (see Sections 16 and 17).

### 2.2 What a local check can and cannot catch for x402

Some payment failures are visible offline: a changed recipient, an amount above a cap, a disallowed asset or network, an insecure transport. Others need reputation data, such as a fake endpoint cluster or a prompt-injection that talks an agent into paying. PayGuard's current x402 guard covers the first group. The second group is the reason for the threat-intelligence work in Section 17.

---

## 3. Mission and Positioning

**Mission: Verify Before You Trust.** PayGuard gives people and software an independent, inspectable check that runs before money moves.

PayGuard is not a wallet and does not hold funds. Wallet vendors ship their own spending limits and key isolation. PayGuard's position is a neutral, open guard that works with any wallet or agent framework and explains each verdict with evidence.

---

## 4. Why HTTPS Does Not Mean a Website Is Legitimate

- **Encryption is not identity.** TLS protects the channel. It says nothing about who operates the server.
- **Free, automatic certificates.** Domain-validated certificates are issued in seconds by automated authorities, so attackers use them too.
- **Consequence.** Phishing sites commonly present a valid padlock. PayGuard ignores the padlock and examines the hostname itself: Unicode normalization, Punycode, edit distance and subdomain structure.

---

## 5. Why Verified Contract Source Does Not Prove Safety

An explorer's "source verified" badge proves only that published source compiles to the deployed bytecode. Scam deployers verify their contracts on purpose. A verified contract can still contain owner balance controls, hidden sell taxes, blacklists or pausable transfers.

PayGuard therefore evaluates behavior-related risk flags from a threat-intelligence provider (GoPlus) and does not treat the verification badge as a safety signal.

---

## 6. Why Token Names and Symbols Cannot Establish Identity

ERC-20 `name()` and `symbol()` are free-form strings anyone can set. The only authoritative identifier of a token is its 20-byte contract address. For example, native USDC on Base is `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`.

PayGuard matches contract addresses exactly against a curated Base canonical registry. A contract that presents a canonical symbol at a different address is flagged `TOKEN_LOOKALIKE_IMPERSONATION`.

---

## 7. Security Architecture and Invariants

```
 Inbound: x402 payment requirement | URL | calldata | token | address | wallet
                                   |
                                   v
 +-------------------------------------------------------------------+
 |  Input validation (strict schemas, size limits, no extra fields)  |
 +-------------------------------------------------------------------+
                  |                                   |
                  v                                   v
 +-------------------------------+     +------------------------------+
 |  Local, deterministic checks  |     |  Optional upstream evidence  |
 |  - x402 intent policy         |     |  - GoPlus (Base 8453)        |
 |  - URL lexical analysis       |     |  - Base RPC (eth_call)       |
 |  - calldata selectors         |     |  - Blockscout indexer        |
 |  - canonical registry         |     |  (cached, fail-closed)       |
 +-------------------------------+     +------------------------------+
                  |                                   |
                  +-----------------+-----------------+
                                    v
         Verdict: PASS | REVIEW | BLOCK | UNVERIFIED  + evidence list
```

### 7.1 Invariants

1. **Non-custodial.** No keys, seed phrases, signing or broadcasting.
2. **In-memory URL analysis.** The URL Sentinel parses a URL as text and does not contact the inspected host. This removes SSRF from that tool.
3. **Bounded upstream calls.** Token, address and wallet tools call fixed, operator-chosen providers (GoPlus, Base RPC, Blockscout). They do not fetch attacker-supplied URLs. Responses are cached for 10 minutes and failures return `UNVERIFIED`.
4. **Fail closed.** No evidence never becomes `PASS`.
5. **Advisory only.** Verdicts inform a decision. They do not enforce one outside the paths PayGuard controls.

---

## 8. x402 Payment-Intent Guard

*Status: Implemented. Unit-tested in the repository's suite.*

The guard compares an x402 payment requirement with an explicit policy (the *intent*). Policy fields:

| Field | Purpose |
| :--- | :--- |
| `expectedResourceUrl` | The resource the user meant to pay for |
| `maxAmountAtomic` | Highest allowed amount in the asset's smallest unit (integer string) |
| `allowedNetworks` | Permitted network identifiers |
| `allowedAssets` | Permitted asset addresses |
| `allowedPayTo` | Permitted recipient addresses |
| `allowedSchemes` | Permitted payment schemes |
| `maxTimeoutSeconds` | Longest accepted payment validity window |

Behavior:

- A missing or incomplete policy cannot yield `PASS`.
- A recipient, asset, network or amount outside the policy yields `BLOCK`.
- Inputs are schema-validated; oversized or malformed values are rejected.

**SDK integration.** `createPayGuardX402Hook` and `registerPayGuardX402` attach the guard to an x402 client through its `onBeforePaymentCreation` hook, so a rejected payment is aborted before a payload is created. Observed behavior of `@x402/core` 2.29.0 (default spend controls run before hooks; an abort surfaces as "Payment creation aborted") was confirmed in a CI probe. A full end-to-end integration test suite against the real SDK is **not** confirmed on main (Section 16).

---

## 9. URL Sentinel

*Status: Implemented. In-memory analysis only.*

Checks performed on a URL string:

1. **Unicode bidirectional controls** (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069).
2. **NFKC normalization and homoglyph detection** for full-width, Cyrillic and Greek confusables.
3. **Punycode (`xn--`) decoding** and character-set review.
4. **Edit distance** against official Base ecosystem domains.
5. **Credential and token redaction** (userinfo and high-entropy query values) before reporting.

URL Sentinel does not yet consume live threat-intelligence feeds. That integration is planned (Section 17).

### 9.1 Passive website scanner and threat-intel feeds (separate branch)

A passive website scanner (PR #5, not merged) adds an SSRF-restricted collector (public IPv4 only, DNS pinning, redirect revalidation, TLS metadata), OpenPhish and URLhaus parsers with exact-URL matching, and a feed-refresh and signed-snapshot storage layer. It is unit-tested but has **not** been run against live feeds or hardened for production egress. Nothing in this section is a claim about the current main branch.

---

## 10. Token, Address and Wallet Security

*Status: Implemented. Depends on third-party data; not independently audited.*

### 10.1 Token indicators (Base 8453, via GoPlus)

| Indicator | Condition | Result |
| :--- | :--- | :--- |
| `is_honeypot` | `1` | `BLOCK` |
| `owner_change_balance` | `1` | `BLOCK` |
| `cannot_sell_all` | `1` | `BLOCK` |
| `buy_tax` / `sell_tax` | above 10% | `BLOCK` or `REVIEW` |
| `transfer_pausable` | `1` | `REVIEW` |
| `is_airdrop_scam` | `1` | `BLOCK` |
| `is_open_source` | `0` | `REVIEW` |
| Canonical symbol, wrong address | mismatch | `BLOCK` |

Thresholds are policy choices, not proof of malice.

### 10.2 Address security

Counterparty addresses are screened through GoPlus for phishing, sanctions and mixer links. A clean result means "no listed risk", not "safe".

### 10.3 Wallet token scanner

Two tiers: the Blockscout API v2 indexer first, then an `eth_call` multicall fallback against Base RPC. The fallback checks the seven canonical registry tokens plus user-supplied contracts and labels the result `REGISTRY_AND_CUSTOM_PARTIAL`, because it cannot enumerate unsolicited tokens.

---

## 11. Calldata Inspection

*Status: Implemented for ERC-20 selectors.*

- Decodes `approve` (`0x095ea7b3`), `transfer` (`0xa9059cbb`) and `transferFrom` (`0x23b872dd`).
- Flags `UNLIMITED_ALLOWANCE` when the amount is `2^256 - 1`.
- Checks spender and recipient against user allowlists.
- Unknown selectors, multicalls and DEX aggregator calls return advisory `REVIEW`, not `PASS`.

Not covered: Permit and Permit2 signatures, EIP-712 typed data, `setApprovalForAll`, EIP-7702 authorizations and transaction simulation.

---

## 12. Base Ecosystem Integration

- **Canonical registry:** WETH `0x4200000000000000000000000000000000000006`, native USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, cbETH `0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22`, VIRTUAL `0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b`, DAI `0x50c5725949a6F0c72E6C4a641F24049A917DB0Cb`, USDbC `0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA`, AERO `0x940181a94A35A4569E4529A3CDfB74e38FD98631`. Re-verify these against official sources before each release.
- **Smart wallet client:** integrates `@coinbase/wallet-sdk` with pre-signing calldata inspection.
- **Browser wallet connection:** standard EIP-1193 injected providers, chain check with `eth_chainId`, and a Base switch request. Connection is read-only and starts only after a user click.
- **Network scope:** Base Mainnet only. Base Sepolia (84532) returns `UNVERIFIED / UNSUPPORTED_CHAIN`.

---

## 13. Interfaces: REST API, MCP Tools, Console

### 13.1 MCP tools (JSON-RPC 2.0 over stdio)

| Tool | Purpose |
| :--- | :--- |
| `payguard_check_payment_intent` | x402 requirement vs. user policy |
| `payguard_analyze_url` | In-memory phishing, Bidi and look-alike checks |
| `payguard_prepare_threat_report` | Privacy-conscious draft incident report |
| `payguard_inspect_calldata` | ERC-20 calldata and unlimited-approval check |
| `payguard_check_token_security` | GoPlus token risk (Base 8453) |
| `payguard_check_address_security` | GoPlus address reputation |
| `payguard_scan_wallet_tokens` | Wallet holdings scan with impersonation detection |

### 13.2 REST endpoints

`/api/check-payment`, `/api/analyze-url`, `/api/threat-report`, `/api/inspect-calldata`, `/api/token-security`, `/api/address-security`, `/api/scan-wallet-tokens`, `/api/capabilities`, `/api/bazaar`.

### 13.3 Current server controls

Request body limit 64 KB, a concurrency cap (default 100), and a per-IP rate limit over a 60-second window. **There is no authentication or per-user quota.** The rate limiter reads the client IP from a forwarded header, so it must sit behind a trusted proxy to be reliable. See Section 16.

---

## 14. Threat Model and Security Boundaries

### 14.1 Mitigated (with the stated scope)

| Threat | Mitigation | Scope |
| :--- | :--- | :--- |
| Invisible Bidi characters in URLs | Control-range scan | URL Sentinel |
| Confusable hostnames | NFKC, Punycode, script checks | URL Sentinel |
| Deceptive suffix domains | Parent-domain extraction vs. allowlist | URL Sentinel |
| Unlimited ERC-20 approvals | Parse amount, flag `2^256 - 1` | Calldata inspector |
| Wrong x402 recipient, asset, network or amount | Intent policy | x402 guard |
| Honeypot and owner-control tokens | GoPlus flags | Base 8453 only |
| Sanctioned counterparties | GoPlus address screening | Base 8453 only |

### 14.2 Out of scope or not yet covered

- Brand-new contracts not yet indexed (returns `UNVERIFIED`).
- Transactions signed directly in a wallet extension outside PayGuard-controlled paths.
- Off-chain social engineering and credential compromise.
- Signature-based and delegation-based drains (Permit, Permit2, EIP-712, EIP-7702).
- Prompt-injection detection for agents (needs reputation data).
- Compromise of an upstream provider such as GoPlus.

---

## 15. Capability Status

| Capability | Status |
| :--- | :--- |
| x402 payment-intent guard and SDK hook | Implemented, unit-tested |
| URL Sentinel (in-memory) | Implemented, tested |
| ERC-20 calldata inspection | Implemented, tested |
| GoPlus token and address checks | Implemented, tested with mocks; live behavior depends on provider |
| Wallet token scanner (two-tier) | Implemented, tested with mocks |
| REST API, MCP server, console | Implemented |
| Passive website scanner, threat-intel parsers, feed refresh | On unmerged PR #5; unit-tested, not verified live |
| Authentication, quotas, production egress controls | Planned |
| Permit/Permit2/EIP-712, EIP-7702, simulation | Planned |

The test suite last passed 155 of 155 tests in a recorded CI run. Test counts change with every commit; treat CI as the source of truth.

---

## 16. Known Limitations and Unverified Items

1. **CommonJS bundle is broken on main.** `dist/index.cjs` retains an ES `import`, so the CommonJS check fails and CI is red until the build script is fixed. ES module use is unaffected.
2. **No authentication or quotas.** Public endpoints rely on an IP rate limit that trusts a forwarded header.
3. **Third-party assets.** Public pages load fonts and icons from external CDNs without subresource integrity.
4. **x402 end-to-end tests.** The hook is implemented, but a real-SDK integration test suite is not confirmed on main.
5. **No live-feed verification.** Threat-intel refresh and storage have not been exercised against live feeds.
6. **Provider dependence.** Token and address verdicts rely on GoPlus data and public RPC and indexer availability.
7. **Partial wallet discovery** when the indexer is unavailable (Section 10.3).
8. **Base Mainnet only.**
9. **License file.** The project states an MIT license, but a LICENSE file is not yet in the repository root.
10. **No independent security review** has been performed.

---

## 17. Roadmap

Ordered by value and dependency. Items are plans, not commitments.

**Now: trust and hygiene**
- Fix the CommonJS build and restore green CI.
- Add LICENSE, SECURITY.md and `.env.example`.
- Align all public claims with this paper's status labels.

**Next: production safety**
- API-key or JWT authentication, per-identity quotas and trusted-proxy handling.
- Production SSRF and egress controls for the passive scanner; review and merge PR #5 only after explicit approval.
- Verify feed refresh against live OpenPhish and URLhaus and record the evidence.
- Connect URL Sentinel to threat-intelligence matches.

**Then: coverage**
- Permit, Permit2 and EIP-712 typed-data inspection.
- EIP-7702 delegation check.
- Multicall decoding and transaction simulation.
- Contract and token risk analysis beyond provider flags, and Base and NEAR security adapters.
- Evidence correlation and reporting across modules.
- Real-SDK x402 integration tests in CI.

**Then: assurance**
- Independent security review, and a testnet demonstration with real transactions.

### Explicit non-goals

- Private key custody, signing or transaction broadcasting.
- On-chain freezing, burning or quarantine.
- Paywalls on the core checks.

---

*PayGuard is an open-source project for the Base and Web3 communities. Licensing: MIT is intended; see Section 16, item 9.*
