# PayGuard AI Security Agent

## Phase D — Payment Intent and Transaction Correlation

**Status:** Deterministic, read-only correlation of caller-supplied payment context and decoded ERC-20 transfer calldata.

---

## 1. Why this phase exists

Individual checks can pass while the combined interaction is inconsistent. For example, the URL may be familiar, the token contract may be known, and the payment option may satisfy policy, while the transaction's decoded recipient differs from the recipient the user intended to pay.

Phase D adds a separate correlation evidence record to expose this mismatch. It does not replace or weaken the original tool results.

## 2. Inputs and selection

Correlation runs only when the caller supplies:
- trusted user intent,
- received x402 payment requirements,
- a proposed transaction, including its network.

The payment requirements must contain an `accepts` array. When exactly one payment option exists, it is selected automatically. When multiple options exist, the caller must supply `selectedPaymentIndex`; otherwise the correlation remains UNVERIFIED.

The transaction must decode to a supported ERC-20 `transfer` or `transferFrom` operation. An approval is not treated as a completed payment.

## 3. Fields compared

| Payment option | Decoded transaction |
|---|---|
| `network` | Caller-supplied `transaction.network` |
| `asset` | Decoded `details.tokenContract` |
| `payTo` | Decoded `details.recipient` or `details.to` |
| `amount` / `maxAmountRequired` | Decoded `details.amount` |

Network identifiers are normalized for common EVM forms such as `8453` and `eip155:8453`. EVM addresses are compared case-insensitively. Amounts are compared as integer atomic-unit strings; display names and floating-point amounts are not used.

## 4. Correlation outcomes

- **VERIFIED:** All four fields are present and match for the selected payment option.
- **RISK_DETECTED:** At least one decoded field conflicts with the selected payment option, or the selected option failed explicit policy.
- **UNVERIFIED:** A field is missing/unsupported, the payment option is ambiguous, or calldata does not decode to a supported transfer.
- **NOT_CHECKED:** Required payment context was not supplied or the relevant check was not run.
- **ERROR:** A required source check failed to execute.

A correlation risk finding is a mismatch signal. It does not by itself prove fraud or malicious intent.

## 5. Evidence integrity

The correlation is emitted as a separate derived evidence record with:
- its own source identifier,
- deterministic status and reason,
- individual field comparison results,
- canonical JSON SHA-256 provenance hash.

The original payment and calldata evidence remain unchanged. The derived record participates in the same required-check aggregation as other evidence.

## 6. Security boundaries

- No URL fetching, RPC calls, provider calls, or chain-state reads are added.
- No transaction simulation, signature verification, settlement verification, or on-chain execution is performed.
- The network field is supplied by the caller; it is not independently proven by the calldata decoder.
- Only supported ERC-20 transfer selectors are correlated.
- A matching report does not prove that a transaction was signed, broadcast, mined, or settled.
- No LLM or public endpoint is introduced by this phase.

This phase addresses the intent-to-authorization gap at the supplied-data level. A later phase may add authenticated transaction context and independently sourced network/asset identity, with separate tests and explicit trust boundaries.
