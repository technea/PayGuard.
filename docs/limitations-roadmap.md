# PayGuard — Known Limitations & Roadmap

## Current Limitations

These are honest, accurate limitations of the current implementation. They represent areas where the system's scope is intentionally narrow, where external dependencies constrain coverage, or where future work is planned.

---

### Security Analysis & Coverage

| # | Limitation | Details |
|---|-----------|---------|
| 1 | **GoPlus Base Sepolia not supported** | Chain ID 84532 returns `UNVERIFIED / UNSUPPORTED_CHAIN`. GoPlus threat feeds index Base Mainnet (8453) only. |
| 2 | **ERC-20 calldata only (3 selectors)** | The calldata inspector recognizes `approve`, `transfer`, and `transferFrom`. Any other selector returns advisory `REVIEW`, not `BLOCK`. EIP-712 typed-data, permit2, multicall, and DEX routers are not decoded. |
| 3 | **No on-chain state simulation** | PayGuard analyzes calldata statically. It cannot simulate dynamic contract execution, detect flash loan reentrancy, assess gas manipulation, or evaluate runtime state transitions. |
| 4 | **GoPlus indexing lag on zero-day scams** | Brand-new scam tokens deployed minutes ago may not appear in the GoPlus database immediately. Unindexed tokens fail closed as `UNVERIFIED / UNINDEXED_TOKEN`, never as `PASS`. |
| 5 | **GoPlus data quality not verified** | PayGuard evaluates what GoPlus returns but does not independently audit GoPlus's internal threat intelligence scoring or raw data accuracy. |
| 6 | **Advisory verdicts only outside signing path** | A `BLOCK` verdict automatically prevents signing only within PayGuard's opt-in `BaseSmartWalletClient`. PayGuard cannot enforce blocks in external wallet extensions or third-party signing clients. |
| 7 | **No proxy upgrade slot analysis** | The `is_proxy` flag is surfaced as an informational finding. PayGuard does not inspect proxy implementation addresses or timelock parameters. |
| 8 | **No MEV or sandwich attack detection** | Mempool transaction ordering, frontrunning, and sandwich attacks are out of scope. |
| 9 | **URL heuristics produce false positives** | Legitimate IDN domains, non-standard development ports, and local staging environments may trigger warnings. Findings are advisory. |
| 10 | **Bidi detection covers known control ranges only** | Detected ranges: U+061C, U+200E, U+200F, U+202A–202E, U+2066–2069. Novel control characters outside these ranges are not covered. |

---

### Base Wallet Token Scanner Limitations

| # | Limitation | Details |
|---|-----------|---------|
| 11 | **Public Indexer Bot Protection Fallback** | In automated serverless environments or headless CI runners, the Blockscout API v2 (`base.blockscout.com`) triggers Cloudflare bot challenges (HTTP 403). When blocked, PayGuard falls back to on-chain RPC queries. |
| 12 | **RPC Multicall Fallback Scope** | When running in Tier 2 RPC fallback mode, discovery is **partial**: PayGuard queries the 7 curated Base canonical tokens (WETH, USDC, cbETH, VIRTUAL, DAI, USDbC, AERO) plus any caller-specified `customTokenAddresses`. It **cannot** discover arbitrary unsolicited tokens without an indexer or explicit addresses. |
| 13 | **Base Public RPC Log Rate Limits** | Public Base RPC endpoints (`https://mainnet.base.org`) restrict `eth_getLogs` queries across large block spans (error `-32011: request limit reached`). Transfer log scraping is therefore not viable on public RPCs without a dedicated commercial node. |
| 14 | **Explorer API Key Constraints** | Etherscan / Basescan API v2 requires paid commercial API keys for programmatic token listing queries. PayGuard avoids mandatory paid API keys to keep the core service accessible. |
| 15 | **Honest Status Reporting** | PayGuard never claims complete discovery when falling back to the curated registry. It flags the scan explicitly as `discoveryMode: "REGISTRY_AND_CUSTOM_PARTIAL"` with an advisory notice. |

---

### Infrastructure & Operations

| # | Limitation | Details |
|---|-----------|---------|
| 16 | **In-memory cache only** | GoPlus and address results are cached in process memory with a 10-minute TTL. Cache resets on process restart. |
| 17 | **No cross-chain GoPlus support** | Threat intelligence is scoped to Base Mainnet (8453). Ethereum mainnet, Arbitrum, Optimism, and Solana are not supported. |
| 18 | **Google Web Risk opt-in** | Web Risk reputation lookup requires both `checkReputation: true` in the request and a valid `GOOGLE_WEB_RISK_API_KEY` server-side. |
| 19 | **No document or message analysis** | PayGuard analyzes URLs, EVM calldata, and on-chain addresses. It does not parse PDFs, emails, Discord messages, or social media text. |

---

## Roadmap

The following areas are considered for future development. Items marked **planned** are the most likely near-term additions. Items marked **exploratory** have not been designed in detail.

### Near-Term (Planned)

| Feature | Description |
|---------|-------------|
| **EIP-712 typed-data inspection** | Decode and analyze `eth_signTypedData_v4` payloads, including permit and permit2 patterns |
| **Expanded calldata selector library** | Add support for common DEX operations (Uniswap V3 swap, Aerodrome multicall) and NFT approvals (`setApprovalForAll`) |
| **Dedicated Indexer RPC Support** | Support optional dedicated Alchemy/QuickNode/Goldsky endpoints for full historical token indexing |
| **Persistent GoPlus cache** | Optional Redis or SQLite backend for cross-process and cross-restart caching |
| **Structured audit log** | Optional append-only event log of tool invocations and verdicts for operator review |

### Medium-Term (Exploratory)

| Feature | Description |
|---------|-------------|
| **On-chain simulation** | Pre-flight transaction simulation using a forked node or debug_traceCall to detect revert risks |
| **Formal rule engine** | Configurable YAML/JSON policy definitions for complex transaction constraints |
| **Browser extension** | In-browser URL and transaction inspection at the dApp interaction layer |
| **Additional threat feeds** | Integration with Chainabuse, ScamSniffer, and other community threat intelligence sources |

### Business Model & Deferred Scope

| Feature | Reason Deferred |
|---------|-----------------|
| **Mandatory subscriptions or paywalls** | PayGuard is committed to remaining a free community utility. Voluntary donations may be accepted, but mandatory fees are an explicit non-goal. |
| **Private key custody or signing** | Explicit non-goal for PayGuard. PayGuard will always remain strictly non-custodial and read-only. |
| **Asset freezing or quarantine** | PayGuard has no administrative smart contract privileges and cannot alter on-chain state. |

---

## Disclosure Statement

PayGuard is an **advisory intelligence platform**. It delivers structured security data to help users and AI agents make informed decisions. It is not a certified security audit, not financial advice, and not an absolute guarantee that inspected assets or websites are safe.
