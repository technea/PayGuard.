# PayGuard AI Security Agent

## Phase C — Deterministic Assessment Orchestration

**Status:** Library-only orchestration.  
**Runtime model:** No LLM, public REST endpoint, new MCP tool, signing, or transaction execution.

---

## 1. Purpose

Phase C connects the Phase B evidence primitives to the seven existing PayGuard tools. The planner selects checks only from subjects explicitly supplied by the caller. It does not infer missing payment intent, wallet identity, trusted domains, or transaction details.

The orchestrator returns:
- the exact checks selected,
- one evidence record per selected check,
- explicit NOT_CHECKED records when a required input pair is incomplete,
- a deterministic report with required-check aggregation.

## 2. Folder structure

```text
src/agent/
  plan.mjs
  execution.mjs
  orchestrator.mjs
  ...Phase B evidence modules

test/
  agent-orchestration.test.mjs

docs/agent/
  phase-c-orchestration.md
```

- `plan.mjs`: deterministic input-to-tool mapping.
- `execution.mjs`: bounded worker pool, per-tool timeout, total deadline, input size validation.
- `orchestrator.mjs`: public assessment entry point and report assembly.

## 3. Supported explicit inputs

| Input field | Existing PayGuard tool |
|---|---|
| `url` | `payguard_analyze_url` |
| `contractAddress` | `payguard_check_token_security` |
| `address` | `payguard_check_address_security` |
| `walletAddress` | `payguard_scan_wallet_tokens` |
| `transaction` | `payguard_inspect_calldata` |
| `intent` + `paymentRequirements` | `payguard_check_payment_intent` |
| `prepareThreatReport: true` + `url` | `payguard_prepare_threat_report` |

A payment check requires both trusted user intent and payment requirements. If only one is supplied, the planner records NOT_CHECKED rather than deriving or inventing the missing side.

No check is run merely because an address or URL appears inside unrelated free-form text.

## 4. Execution limits

| Limit | Default | Hard maximum |
|---|---:|---:|
| Concurrent tool calls | 3 | 3 |
| Per-tool deadline | 20 seconds | 30 seconds |
| Total assessment deadline | 45 seconds | 60 seconds |
| Serialized input size | 64,000 characters | Configured by caller |

There are no automatic retries. This avoids duplicate provider traffic and prevents an ambiguous timeout from silently becoming a second request.

A timeout becomes ERROR. A task that cannot start before the total deadline becomes NOT_CHECKED. A timed-out JavaScript Promise cannot be forcibly cancelled by this orchestration layer; existing provider-specific timeouts remain responsible for aborting their own network requests.

## 5. Report semantics

The orchestrator retains each tool's raw result and normalized evidence. The existing Phase B aggregation rules remain authoritative:

- Any explicit risk finding produces RISK_DETECTED.
- A required ERROR, UNVERIFIED, or NOT_CHECKED prevents an overall VERIFIED result.
- No known threat is not proof of legitimacy.
- A partial wallet discovery is UNVERIFIED.
- A tool timeout is ERROR, not a clean result.

## 6. Example

```js
import { runSecurityAssessment } from "./src/agent/index.mjs";

const result = await runSecurityAssessment({
  url: "https://example.com",
  contractAddress: "0x1111111111111111111111111111111111111111",
  intent: trustedUserIntent,
  paymentRequirements: receivedPaymentRequirements
});

console.log(result.report.overallStatus);
console.log(result.report.evidence);
```

Use trusted policy values for `intent`; do not construct the user's policy from the payment request being evaluated.

## 7. Security boundaries and deferred work

- No model calls or model-generated risk decisions.
- No public REST route. Hosted access requires authentication, quotas, request validation, and deployment-runtime review first.
- No new MCP tool registration in this phase.
- No wallet connection, private-key access, signing, broadcasting, or payment execution.
- No cross-signal intent-to-calldata correlation claim is made by this phase; that requires a separate, explicitly tested correlation layer.
- No real-world detection benchmark or performance metric is claimed.

Phase C is a deterministic orchestration foundation, not an autonomous agent.
