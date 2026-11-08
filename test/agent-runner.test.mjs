import test from "node:test";
import assert from "node:assert/strict";
import { runInvestigation } from "../src/agent/runner.mjs";

const pass = { verdict: "PASS", dataStatus: "AVAILABLE", findings: [] };

test("runs an explicit plan and preserves plan order in evidence", async () => {
  const result = await runInvestigation({
    subject: { type: "token", value: "0xabc" },
    checks: [
      { toolName: "payguard_check_token_security", input: { contractAddress: "0xabc" } },
      { toolName: "payguard_analyze_url", input: { url: "https://example.com" }, required: false }
    ],
    executeTool: async name => name === "payguard_check_token_security" ? pass : { verdict: "NO_KNOWN_THREAT" }
  });
  assert.equal(result.evidence.length, 2);
  assert.equal(result.evidence[0].source, "payguard_check_token_security");
  assert.equal(result.evidence[0].status, "VERIFIED");
  assert.equal(result.evidence[1].status, "UNVERIFIED");
  assert.equal(result.overallStatus, "VERIFIED");
  assert.equal(result.degraded, true);
  assert.equal(result.execution.mode, "EXPLICIT_PLAN");
});

test("rejects unknown and duplicate tools before executing anything", async () => {
  let calls = 0;
  const executeTool = async () => { calls++; return pass; };
  await assert.rejects(runInvestigation({
    checks: [{ toolName: "payguard_unknown", input: {} }],
    executeTool
  }), /Unknown PayGuard tool/);
  await assert.rejects(runInvestigation({
    checks: [
      { toolName: "payguard_analyze_url", input: {} },
      { toolName: "payguard_analyze_url", input: {} }
    ],
    executeTool
  }), /Duplicate tool checks/);
  assert.equal(calls, 0);
});

test("concurrency never exceeds configured limit and result order stays stable", async () => {
  let active = 0;
  let peak = 0;
  const names = [
    "payguard_analyze_url",
    "payguard_check_token_security",
    "payguard_check_address_security",
    "payguard_inspect_calldata"
  ];
  const result = await runInvestigation({
    checks: names.map(toolName => ({ toolName, input: {} })),
    options: { maxConcurrency: 2 },
    executeTool: async () => {
      active++;
      peak = Math.max(peak, active);
      await new Promise(resolve => setTimeout(resolve, 10));
      active--;
      return pass;
    }
  });
  assert.equal(peak, 2);
  assert.deepEqual(result.evidence.map(item => item.source), names);
});

test("tool timeout is explicit ERROR and does not accept a late result", async () => {
  const result = await runInvestigation({
    checks: [{ toolName: "payguard_analyze_url", input: {} }],
    options: { perToolTimeoutMs: 5, totalTimeoutMs: 50 },
    executeTool: async () => {
      await new Promise(resolve => setTimeout(resolve, 25));
      return { verdict: "EXPECTED_DOMAIN_MATCH" };
    }
  });
  assert.equal(result.evidence[0].status, "ERROR");
  assert.equal(result.evidence[0].errorCode, "TOOL_TIMEOUT");
  assert.equal(result.overallStatus, "ERROR");
  assert.equal(result.execution.timedOutChecks, 1);
});

test("total budget leaves queued checks explicitly NOT_CHECKED", async () => {
  const names = [
    "payguard_analyze_url",
    "payguard_check_token_security",
    "payguard_check_address_security"
  ];
  const result = await runInvestigation({
    checks: names.map(toolName => ({ toolName, input: {} })),
    options: { maxConcurrency: 1, perToolTimeoutMs: 40, totalTimeoutMs: 5 },
    executeTool: async () => new Promise(resolve => setTimeout(() => resolve(pass), 20))
  });
  assert.equal(result.evidence[0].status, "ERROR");
  assert.equal(result.evidence[1].status, "NOT_CHECKED");
  assert.equal(result.evidence[2].status, "NOT_CHECKED");
  assert.equal(result.execution.notStartedChecks, 2);
});

test("rejects invalid time budgets", async () => {
  await assert.rejects(runInvestigation({
    checks: [{ toolName: "payguard_analyze_url", input: {} }],
    executeTool: async () => pass,
    options: { maxConcurrency: 4 }
  }), /maxConcurrency/);
});
