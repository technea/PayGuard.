/**
 * @module agent/runner
 * @section Bounded deterministic tool orchestration
 * Executes an explicit, caller-supplied plan with fixed concurrency and time budgets.
 * It does not plan, discover, chain, or authorize tools autonomously.
 */
import { MAX_EVIDENCE_RECORDS } from "./constants.mjs";
import { isKnownPayGuardTool } from "./tool-catalog.mjs";
import { cloneJsonValue } from "./canonical-json.mjs";
import { normalizeToolResult } from "./normalize-result.mjs";
import { createErrorEvidence, createNotCheckedEvidence } from "./evidence-record.mjs";
import { buildEvidenceReport } from "./report.mjs";

const MAX_CONCURRENCY = 3;
const DEFAULT_CONCURRENCY = 3;
const DEFAULT_PER_TOOL_TIMEOUT_MS = 6_000;
const DEFAULT_TOTAL_TIMEOUT_MS = 15_000;
const MAX_PER_TOOL_TIMEOUT_MS = 15_000;
const MAX_TOTAL_TIMEOUT_MS = 30_000;

function requireIntegerInRange(value, name, min, max, fallback) {
  const resolved = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) {
    throw new RangeError(name + " must be an integer between " + min + " and " + max + ".");
  }
  return resolved;
}

function validatePlan(checks, executeTool) {
  if (!Array.isArray(checks) || checks.length === 0) {
    throw new TypeError("An investigation requires at least one explicit check.");
  }
  if (checks.length > MAX_EVIDENCE_RECORDS) {
    throw new RangeError("Investigation exceeds the evidence record limit.");
  }
  if (typeof executeTool !== "function") {
    throw new TypeError("executeTool must be a function supplied by the trusted host.");
  }

  const seen = new Set();
  return checks.map((check, index) => {
    if (!check || typeof check !== "object" || Array.isArray(check)) {
      throw new TypeError("Each check must be an object.");
    }
    const toolName = check.toolName;
    if (!isKnownPayGuardTool(toolName)) {
      throw new TypeError("Unknown PayGuard tool in check " + index + ".");
    }
    if (seen.has(toolName)) {
      throw new TypeError("Duplicate tool checks are not allowed: " + toolName + ".");
    }
    seen.add(toolName);
    const input = check.input === undefined ? {} : check.input;
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new TypeError("Tool input must be a JSON object for " + toolName + ".");
    }
    return {
      toolName,
      input: cloneJsonValue(input),
      checkId: typeof check.checkId === "string" && check.checkId.trim() ? check.checkId.slice(0, 120) : toolName,
      required: check.required !== false
    };
  });
}

function raceWithTimeout(promise, timeoutMs) {
  let timer;
  const timeout = new Promise(resolve => {
    timer = setTimeout(() => resolve({ timedOut: true }), timeoutMs);
  });
  return Promise.race([
    Promise.resolve(promise).then(value => ({ value }), error => ({ error })),
    timeout
  ]).finally(() => clearTimeout(timer));
}

async function executeCheck(check, executeTool, timeoutMs) {
  const startedAt = new Date().toISOString();
  const started = Date.now();
  try {
    const pending = executeTool(check.toolName, cloneJsonValue(check.input));
    const outcome = await raceWithTimeout(pending, timeoutMs);
    const durationMs = Math.max(0, Date.now() - started);
    const completedAt = new Date().toISOString();

    if (outcome.timedOut) {
      return createErrorEvidence(check.toolName, new Error("Tool timeout"), {
        checkId: check.checkId,
        required: check.required,
        startedAt,
        completedAt,
        durationMs,
        errorCode: "TOOL_TIMEOUT"
      });
    }
    if (outcome.error) {
      return createErrorEvidence(check.toolName, outcome.error, {
        checkId: check.checkId,
        required: check.required,
        startedAt,
        completedAt,
        durationMs,
        errorCode: "TOOL_EXECUTION_FAILED"
      });
    }
    return normalizeToolResult(check.toolName, outcome.value, {
      checkId: check.checkId,
      required: check.required,
      startedAt,
      completedAt,
      durationMs
    });
  } catch (error) {
    return createErrorEvidence(check.toolName, error, {
      checkId: check.checkId,
      required: check.required,
      startedAt,
      completedAt: new Date().toISOString(),
      durationMs: Math.max(0, Date.now() - started),
      errorCode: "TOOL_EXECUTION_FAILED"
    });
  }
}

/**
 * Run an explicit set of existing read-only PayGuard tools.
 * Tool execution is injected by the trusted caller; this module has no network access.
 * Timed-out work is not cancelled, so executors must remain read-only and late results
 * are discarded. The runner never signs, broadcasts, or executes transactions.
 */
export async function runInvestigation({
  subject = null,
  checks,
  executeTool,
  options = {}
} = {}) {
  const plan = validatePlan(checks, executeTool);
  const maxConcurrency = requireIntegerInRange(options.maxConcurrency, "maxConcurrency", 1, MAX_CONCURRENCY, DEFAULT_CONCURRENCY);
  const perToolTimeoutMs = requireIntegerInRange(options.perToolTimeoutMs, "perToolTimeoutMs", 1, MAX_PER_TOOL_TIMEOUT_MS, DEFAULT_PER_TOOL_TIMEOUT_MS);
  const totalTimeoutMs = requireIntegerInRange(options.totalTimeoutMs, "totalTimeoutMs", 1, MAX_TOTAL_TIMEOUT_MS, DEFAULT_TOTAL_TIMEOUT_MS);

  const started = Date.now();
  const deadline = started + totalTimeoutMs;
  const records = new Array(plan.length);
  let cursor = 0;

  async function worker() {
    while (true) {
      const index = cursor++;
      if (index >= plan.length) return;
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) {
        records[index] = createNotCheckedEvidence(plan[index].toolName, {
          checkId: plan[index].checkId,
          required: plan[index].required,
          reason: "The total investigation time budget expired before this check started."
        });
        continue;
      }
      records[index] = await executeCheck(plan[index], executeTool, Math.min(perToolTimeoutMs, remainingMs));
    }
  }

  await Promise.all(Array.from({ length: Math.min(maxConcurrency, plan.length) }, () => worker()));

  const completedAt = new Date().toISOString();
  const report = buildEvidenceReport(subject, records, {
    investigationId: "investigation:" + started
  });
  return {
    ...report,
    execution: {
      mode: "EXPLICIT_PLAN",
      plannedChecks: plan.length,
      maxConcurrency,
      perToolTimeoutMs,
      totalTimeoutMs,
      durationMs: Math.max(0, Date.now() - started),
      startedAt: new Date(started).toISOString(),
      completedAt,
      timedOutChecks: records.filter(record => record?.errorCode === "TOOL_TIMEOUT").length,
      notStartedChecks: records.filter(record => record?.status === "NOT_CHECKED").length,
      lateResultsCancelled: false
    }
  };
}
