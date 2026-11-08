# PayGuard AI Security Agent

## Runtime Adapter — Integrated Investigation Entry Point

**Status:** Local TypeScript library adapter.
**Scope:** Connects the bounded Phase C runner to the existing seven read-only PayGuard tool handlers.

---

## 1. Purpose

The runtime adapter removes the need for a host application to manually write the executor callback. It accepts an explicit check plan and dispatches each approved tool name through the existing PayGuard plugin's `invokeTool` method.

## 2. Modules

```text
src/agent/
  payguard-executor.mjs
  investigation.mjs

test/
  agent-integration.test.mjs

docs/agent/
  runtime-adapter.md
```

## 3. Execution flow

1. The trusted caller supplies the subject and exact check plan.
2. The adapter validates that the target plugin exposes `invokeTool`.
3. The Phase C runner validates tool names, inputs, concurrency and time budgets.
4. The adapter delegates each approved check to the existing plugin handler.
5. Phase B normalizes the outputs and creates the deterministic evidence report.

## 4. Security boundaries

- The caller still selects every tool and provides every input.
- Only the seven names in the fixed tool catalogue can run.
- Provider output is not chained into another tool's input.
- The adapter does not create an MCP tool, HTTP endpoint, or hosted agent route.
- It does not introduce an LLM, wallet connection, signing, broadcasting, or payment execution.
- Tests use an injected fake plugin and do not call live providers.

## 5. Validation

Tests verify tool delegation, normalized evidence output, target validation, and preflight rejection of unknown tool names. The adapter inherits Phase C concurrency and timeout limits.
