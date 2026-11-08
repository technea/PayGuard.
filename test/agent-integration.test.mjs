import test from "node:test";
import assert from "node:assert/strict";
import { createPayGuardToolExecutor } from "../src/agent/payguard-executor.mjs";
import { runPayGuardInvestigation } from "../src/agent/investigation.mjs";

test("runtime adapter delegates only the named tool and preserves input", async () => {
  const calls = [];
  const fakePlugin = {
    invokeTool(name, input) {
      calls.push({ name, input });
      return { verdict: "PASS", dataStatus: "AVAILABLE" };
    }
  };
  const execute = createPayGuardToolExecutor(fakePlugin);
  const input = { contractAddress: "0x0000000000000000000000000000000000000001" };
  const result = await execute("payguard_check_token_security", input);

  assert.deepEqual(calls, [{ name: "payguard_check_token_security", input }]);
  assert.equal(result.verdict, "PASS");
});

test("integrated investigation returns normalized evidence from existing handlers", async () => {
  const calls = [];
  const fakePlugin = {
    invokeTool(name, input) {
      calls.push(name);
      assert.deepEqual(input, { url: "https://example.org" });
      return { verdict: "EXPECTED_DOMAIN_MATCH", checks: [] };
    }
  };

  const report = await runPayGuardInvestigation({
    subject: { type: "url", value: "https://example.org" },
    checks: [{ toolName: "payguard_analyze_url", input: { url: "https://example.org" } }],
    targetPlugin: fakePlugin
  });

  assert.deepEqual(calls, ["payguard_analyze_url"]);
  assert.equal(report.overallStatus, "VERIFIED");
  assert.equal(report.evidence[0].source, "payguard_analyze_url");
  assert.equal(report.evidence[0].status, "VERIFIED");
  assert.equal(report.execution.mode, "EXPLICIT_PLAN");
});

test("adapter rejects a target without invokeTool", () => {
  assert.throws(() => createPayGuardToolExecutor({}), /invokeTool/);
});

test("integrated investigation still rejects unknown tools before invoking plugin", async () => {
  let calls = 0;
  const fakePlugin = { invokeTool() { calls++; return {}; } };
  await assert.rejects(runPayGuardInvestigation({
    checks: [{ toolName: "payguard_unknown", input: {} }],
    targetPlugin: fakePlugin
  }), /Unknown PayGuard tool/);
  assert.equal(calls, 0);
});
