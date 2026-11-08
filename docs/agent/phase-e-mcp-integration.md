# PayGuard AI Security Agent

## Phase E — Composite MCP Tool Integration

**Status:** Local stdio MCP integration.  
**Exposure:** Local MCP clients only; no new hosted REST endpoint.

---

## 1. Purpose

Phase E makes the deterministic agent callable as one composite MCP tool:

`payguard_run_security_assessment`

An MCP-compatible assistant can submit one or more explicit subjects. PayGuard selects the corresponding existing checks, executes them within bounded limits, correlates payment intent with supported transfer calldata when both are supplied, and returns a deterministic evidence report.

The MCP client/assistant may explain that report, but PayGuard itself does not call an LLM or generate model-based security decisions.

## 2. Tool inputs

The composite tool accepts any combination of:
- `url`, with optional `expectedDomain`, `trustedDomains`, and `checkReputation`;
- `contractAddress` and optional `chainId`;
- `address` and optional `chainId`;
- `walletAddress` and optional `customTokenAddresses`;
- `transaction` with `to`, `data`, optional `value`, `policy`, and caller-supplied `network`;
- `intent` and `paymentRequirements`;
- `selectedPaymentIndex` when the x402 request offers multiple payment options;
- `prepareThreatReport: true` with a URL.

The payment intent must be trusted user-authored policy. Do not derive it from the received payment request.

## 3. Tool behavior

The tool delegates to the deterministic planner and bounded execution layer:
- maximum 3 concurrent checks;
- 20-second default per-tool deadline;
- 45-second default total deadline;
- no automatic retries;
- 64,000-character serialized input limit;
- skipped or incomplete checks are explicit, not silently omitted.

When payment intent, payment requirements, and a transaction are supplied, a derived evidence record compares network, token contract, recipient, and atomic amount for the selected payment option.

## 4. Result

The tool returns:
- the exact existing checks selected;
- derived correlation checks, when applicable;
- a fixed-template report;
- normalized evidence records and their provenance hashes;
- limitations and unresolved checks.

The report uses the evidence states `VERIFIED`, `RISK_DETECTED`, `UNVERIFIED`, `NOT_CHECKED`, and `ERROR`. These describe implemented check outcomes, not an absolute safety guarantee.

## 5. Local MCP setup

Build the distribution first:

```bash
npm ci
npm run build
```

Then run the stdio server:

```bash
node dist/index.js
```

The build copies the modular `src/agent/` tree into `dist/agent/` so the composite tool works from the packaged plugin.

## 6. Hosted API is intentionally deferred

This phase does not expose the composite tool through the public Vercel HTTP API. A hosted route requires a proper authentication design, durable per-key quotas, abuse monitoring, request limits, and runtime/deadline review. An in-memory serverless rate limiter is not sufficient for a public agent endpoint.

## 7. Security boundaries

- Local stdio MCP tool only.
- No LLM dependency or model call.
- No private-key access, wallet connection, signing, broadcasting, or payment execution.
- No transaction simulation, chain-state verification, or settlement proof.
- Provider and transaction outputs remain evidence, not instructions.
- A matching intent-to-transfer correlation does not prove the transaction was executed or settled.

Phase E integrates the deterministic core into the local agent workflow without making it an autonomous financial actor.
