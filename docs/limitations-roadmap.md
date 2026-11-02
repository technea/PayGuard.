# PayGuard — Known Limitations & Roadmap

## Current Limitations

These are honest, accurate limitations of the current implementation. They represent areas where the system's scope is intentionally narrow, where external dependencies constrain coverage, or where future work is planned.

---

### Security Analysis

| # | Limitation | Details |
|---|-----------|---------|
| 1 | **GoPlus Base Sepolia not supported** | Chain ID 84532 returns `UNVERIFIED / UNSUPPORTED_CHAIN`. GoPlus does not index testnet tokens or addresses. |
| 2 | **ERC-20 calldata only (3 selectors)** | The calldata inspector recognizes `approve`, `transfer`, and `transferFrom`. Any other selector returns advisory `REVIEW`, not `BLOCK`. EIP-712 typed-data, permit2, multicall, and other patterns are not decoded. |
| 3 | **No on-chain simulation** | PayGuard analyzes calldata statically. It cannot simulate execution, detect reentrancy, assess gas manipulation, or evaluate dynamic state-dependent behaviors. |
| 4 | **GoPlus indexing lag** | New or recently deployed scam tokens may not appear in the GoPlus database immediately. An unindexed token returns `UNVERIFIED / UNINDEXED_TOKEN`, not `PASS`. |
| 5 | **GoPlus data quality not verified** | PayGuard evaluates what GoPlus returns but does not independently audit GoPlus's threat intelligence sources, coverage, or accuracy. |
| 6 | **Advisory verdicts only outside signing path** | BLOCK only automatically stops signing within `requestTransaction()` in the Base Smart Wallet integration. PayGuard cannot enforce blocks in other wallet clients, external signing paths, or upstream payment executors. |
| 7 | **No proxy upgrade risk analysis** | The `is_proxy` GoPlus flag is surfaced as an informational finding. PayGuard does not analyze proxy upgrade slots, implementation addresses, or access control of upgradeable contracts. |
| 8 | **No MEV or sandwich attack detection** | Chain-level transaction ordering and MEV analysis are out of scope. |
| 9 | **URL heuristics produce false positives** | Legitimate IDN domains, non-standard ports, and non-HTTPS internal tools may trigger warnings. Findings are advisory; the user must exercise judgment. |
| 10 | **Bidi detection covers known control ranges only** | Detected ranges: U+061C, U+200E, U+200F, U+202A–202E, U+2066–2069. Novel or future Unicode control characters not in these ranges are not detected. |

---

### Infrastructure and Coverage

| # | Limitation | Details |
|---|-----------|---------|
| 11 | **In-memory cache only** | GoPlus results are cached in process memory with a 10-minute TTL. Cache resets on process restart. No persistent cache layer. |
| 12 | **Single-process GoPlus rate limiting** | Rate limit awareness (`RATE_LIMITED` error) is reactive — PayGuard does not implement proactive token-bucket or request-queue management across multiple processes. |
| 13 | **No cross-chain support** | All GoPlus intelligence is Base Mainnet (8453) only. Ethereum mainnet, Polygon, Arbitrum, and other chains are not supported. |
| 14 | **Google Web Risk opt-in** | Web Risk reputation lookup requires both `checkReputation: true` in the request and a valid `GOOGLE_WEB_RISK_API_KEY` server-side. No default threat feed is active without configuration. |
| 15 | **No document or message analysis** | PayGuard analyzes URLs and EVM calldata. It does not parse PDFs, emails, Discord messages, or other media for social engineering signals. |
| 16 | **No persistent audit log** | Security decisions are not persisted. There is no built-in audit trail of tool invocations or verdicts. |

---

### Signing and Enforcement

| # | Limitation | Details |
|---|-----------|---------|
| 17 | **Pre-signing guard covers only PayGuard-initiated transactions** | `requestTransaction()` guards transactions initiated through the Base Smart Wallet client. It does not intercept transactions from other code, browser extensions, direct provider calls, or other wallet integrations. |
| 18 | **User can bypass UI** | PayGuard is not a wallet restriction. A user can still approve transactions directly in their wallet regardless of PayGuard's verdict. |
| 19 | **No EIP-712 typed-data inspection** | `eth_signTypedData` and permit-style signatures are not inspected. Only raw EVM calldata is analyzed. |
| 20 | **x402 hook is client-side only** | The x402 pre-signing hook guards only the x402 client instance it is registered on. It does not affect other payment paths or other x402 clients. |

---

## Roadmap

The following are areas considered for future development. None of these are committed, scheduled, or funded. They represent potential directions, not promises.

> [!NOTE]
> Items marked **planned** are the most likely near-term additions. Items marked **exploratory** have not been designed in detail.

### Near-Term (Planned)

| Feature | Description |
|---------|-------------|
| **EIP-712 typed-data inspection** | Decode and analyze `eth_signTypedData` payloads, including permit and permit2 patterns |
| **Expanded calldata selector library** | Add support for common DEX operations (swap, addLiquidity), NFT approvals (ERC-721 setApprovalForAll), and wrapped token patterns |
| **Persistent GoPlus cache** | Optional Redis or SQLite backend for cross-process and cross-restart caching |
| **Multi-chain GoPlus support** | Add Ethereum mainnet and other chains when GoPlus intelligence is verified for those chains |
| **Structured audit log** | Optional append-only event log of tool invocations and verdicts for operator review |

### Medium-Term (Exploratory)

| Feature | Description |
|---------|-------------|
| **On-chain simulation** | Pre-flight transaction simulation using a forked node or debug_traceCall to detect revert risks |
| **Formal rule engine** | Configurable YAML/JSON policy definitions for complex transaction constraints |
| **Browser extension** | In-browser URL and transaction inspection at the dApp interaction layer |
| **Additional threat feeds** | Integration with Chainabuse, ScamSniffer, and other community threat intelligence sources |
| **Cross-chain address tracking** | Address reputation across multiple chains where the same key is used |

### Deferred / Out of Current Scope

| Feature | Reason deferred |
|---------|----------------|
| RAG and PDF ingestion | Architecture not yet designed |
| NEAR and non-EVM chain adapters | Base-first MVP scope |
| Paid credits, subscriptions, billing | Product/business decision not made |
| Production custody or signing | Explicit non-goal for PayGuard |
| Mainnet payment enforcement | Requires wallet-level integration beyond current scope |

---

## Disclosure Statement

PayGuard is an **advisory tool**. It provides security intelligence to help users and AI agents make informed decisions. It is not:
- A certified security audit
- A regulatory compliance tool
- A financial advice service
- A guarantee that inspected tokens, addresses, or URLs are safe

The security industry benchmark for "safe" requires extensive, multi-layer verification beyond what any single tool can provide. PayGuard is one layer of defense, not a complete solution.
