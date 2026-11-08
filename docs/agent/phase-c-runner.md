# PayGuard AI Security Agent

## Phase C — Bounded Investigation Runner

**Status:** Deterministic orchestration library only.  
**Runtime model:** No LLM, hosted endpoint, public API, new MCP tool, or autonomous planner.

---

## 1. Purpose

Phase C adds a bounded runner over the seven existing read-only PayGuard tools. A trusted caller supplies the exact checks and inputs. The runner executes only that explicit plan, normalizes each result using the Phase B evidence layer, and creates the deterministic report.

The runner does not infer missing inputs, choose additional tools, chain one tool's untrusted output into another tool, or authorize a payment.

## 2. Folder structure

```text
src/agent/
  runner.mjs

test/
  agent-runner.test.mjs

docs/agent/
  phase-c-runner.md
```

## 3. Execution limits

| Limit | Default | Maximum |
|---|---:|---:|
| Concurrent tool calls | 3 | 3 |
| Per-tool timeout | 6 seconds | 15 seconds |
| Total investigation budget | 15 seconds | 30 seconds |
| Evidence records | Existing Phase B limit | 32 |

The current runner also rejects duplicate tool names in one plan. The seven existing tool definitions are the only allowed execution targets.

## 4. Timeout behavior

A tool timeout becomes an ERROR evidence record. Checks that have not started when the total budget expires become NOT_CHECKED. Results are returned in the same order as the caller's plan, regardless of completion order.

JavaScript Promise.race does not cancel the underlying operation. A timed-out operation may continue in the background; its late result is discarded. The runner therefore only accepts injected read-only tool executors. Underlying PayGuard tools retain their own provider/network timeouts.

## 5. Trust boundaries

- The caller supplies an explicit plan; no model planner exists.
- Tool names are checked against the fixed seven-tool catalogue.
- Inputs are detached JSON snapshots before execution.
- Tool outputs are normalized and hashed by Phase B.
- Provider text remains untrusted evidence, not executable instructions.
- No private keys, wallet signing, transaction broadcasting, payment execution, or autonomous financial action.
- No REST route or public endpoint is exposed in this phase.

## 6. Validation

Tests cover explicit plan execution, preflight rejection, concurrency caps, stable result order, per-tool timeout, total-budget exhaustion, and invalid configuration. Tests use synthetic tool executors and do not represent live provider coverage or detection metrics.
