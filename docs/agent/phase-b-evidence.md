# PayGuard AI Security Agent

## Phase B — Evidence Normalization and Correlation

**Status:** Deterministic library only.  
**Runtime model:** No LLM, no network calls, no REST route, no MCP tool registration.

---

## 1. Purpose and scope

Phase B creates a reusable evidence layer around the seven existing PayGuard tools. It does not execute tools or decide which tools to call. Bounded execution and orchestration belong to the next phase.

Each result is retained as a detached JSON snapshot, hashed using canonical JSON, normalized into a common status, and accompanied by a bounded display-only projection of untrusted text.

## 2. Folder structure

```text
src/agent/
  aggregate.mjs
  canonical-json.mjs
  constants.mjs
  evidence-record.mjs
  index.mjs
  normalize-result.mjs
  report.mjs
  status.mjs
  tool-catalog.mjs
  untrusted-data.mjs

test/
  agent-evidence.test.mjs
  agent-normalization.test.mjs
  fixtures/agent-tool-results.mjs

docs/agent/
  phase-b-evidence.md
```

Every source module has a module header and one responsibility. Tests remain directly under test/ so the existing test script discovers them.

## 3. Five-state evidence vocabulary

| State | Meaning |
|---|---|
| VERIFIED | This particular implemented check completed and passed. It does not certify overall safety. |
| RISK_DETECTED | A tool reported an explicit blocking, suspicious, or supported risk finding. |
| UNVERIFIED | The check ran but returned incomplete, unknown, unsupported, or inconclusive evidence. |
| NOT_CHECKED | The check was intentionally not run. |
| ERROR | The check could not execute or its result could not be safely serialized and preserved. |

Required-check precedence is RISK_DETECTED > ERROR > UNVERIFIED > NOT_CHECKED > VERIFIED.

## 4. Required and optional checks

A risk finding from any check, including an optional check, raises the overall state to RISK_DETECTED.

A required check ending in ERROR, UNVERIFIED, or NOT_CHECKED prevents an overall VERIFIED result.

An optional check ending in ERROR, UNVERIFIED, or NOT_CHECKED sets degraded: true but does not otherwise change the overall state. An optional RISK_DETECTED remains decisive.

## 5. Existing tool status mapping

| Existing tool | Conservative mapping |
|---|---|
| Payment intent | PASS → VERIFIED; BLOCK → RISK_DETECTED; REVIEW → UNVERIFIED |
| URL analysis | EXPECTED_DOMAIN_MATCH → VERIFIED; known malicious/suspicious/caution → RISK_DETECTED; no-known-threat → UNVERIFIED |
| Threat report | Uses its underlying URL verdict; report creation is not a separate safety proof |
| Calldata | PASS → VERIFIED; BLOCK or known risk reason → RISK_DETECTED; unsupported/ambiguous review → UNVERIFIED |
| Token/address | Provider-backed PASS with dataStatus AVAILABLE → VERIFIED; BLOCK/REVIEW with provider findings → RISK_DETECTED; unavailable → UNVERIFIED |
| Wallet scan | Full-indexer scan without risk/unverified holdings → VERIFIED; flagged token → RISK_DETECTED; partial discovery → UNVERIFIED |

A no-known-threat result, missing provider, unsupported chain, partial wallet scan, or unknown verdict is never promoted to VERIFIED.

## 6. Evidence integrity and untrusted data

Each normalized record includes the tool name, check identifier, required/optional flag, timestamps, duration, normalized state, fixed reason, detached rawOutput, and rawOutputSha256.

The hash is calculated over canonical JSON: object keys are sorted and array order is preserved. The original raw object is not sanitized or rewritten.

The separate untrustedData projection contains bounded strings labelled UNTRUSTED_DATA. It is sanitized for display only and must never be interpreted as instructions by a future model.

Serialization failure becomes ERROR. Output above 512,000 characters becomes ERROR while retaining the canonical SHA-256 digest and an explicit omission reason; the oversized raw body is not retained. This bounded exception is visible and cannot manufacture a pass.

## 7. Deterministic report

buildEvidenceReport creates a fixed-template summary from normalized records. It uses no model-generated claims. Every risk and unresolved item references its evidence record.

## 8. Security boundaries

- No LLM or prompt execution.
- No HTTP, RPC, provider, or blockchain calls.
- No wallet connection, key access, signing, broadcasting, or transaction execution.
- No planner or tool invocation in this phase.
- No public REST endpoint or new MCP tool in this phase.
- Unknown data remains unknown; a missing result is never a pass.

## 9. Validation

Synthetic fixtures cover all seven tool families, provider-unavailable cases, partial wallet discovery, malformed and oversized output, canonical hashing, untrusted text isolation, required/optional failures, and status precedence. These fixtures are not a measured detection benchmark and must not be presented as real-world detection metrics.
