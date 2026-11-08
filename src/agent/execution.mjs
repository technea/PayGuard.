/**
 * @module agent/execution
 * @section Bounded tool execution
 * Runs only planned PayGuard tools with a capped worker pool and explicit deadlines.
 * A timed-out Promise is no longer awaited, but cannot be forcibly cancelled by this layer.
 */

import { plugin } from "../plugin.mjs";
import { createErrorEvidence, createNotCheckedEvidence } from "./evidence-record.mjs";
import { normalizeToolResult } from "./normalize-result.mjs";
import { cloneJsonValue, canonicalJson } from "./canonical-json.mjs";

export const DEFAULT_EXECUTION_LIMITS = Object.freeze({
  maxConcurrency: 3,
  perToolTimeoutMs: 20_000,
  totalTimeoutMs: 45_000,
  maxInputChars: 64_000
});

function boundedInteger(value, fallback, min, max) {
  if (!Number.isSafeInteger(value)) return fallback;
  return Math.min(max, Math.max(min, value));
}

function withTimeout(promise, timeoutMs, toolName) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error("Tool execution deadline exceeded.");
      error.name = "TimeoutError";
      error.code = "AGENT_TOOL_TIMEOUT";
      reject(error);
    }, timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

export function validateAssessmentInput(input, maxInputChars = DEFAULT_EXECUTION_LIMITS.maxInputChars) {
  let serialized;
  try {
    serialized = canonicalJson(input);
  } catch {
    throw new TypeError("Assessment input must be JSON-serializable.");
  }
  if (serialized.length > maxInputChars) {
    throw new RangeError("Assessment input exceeds the configured size limit.");
  }
  return cloneJsonValue(input);
}

export async function executeAssessmentPlan(plan, options = {}) {
  const limits = {
    maxConcurrency: boundedInteger(options.maxConcurrency, DEFAULT_EXECUTION_LIMITS.maxConcurrency, 1, 3),
    perToolTimeoutMs: boundedInteger(options.perToolTimeoutMs, DEFAULT_EXECUTION_LIMITS.perToolTimeoutMs, 1, 30_000),
    totalTimeoutMs: boundedInteger(options.totalTimeoutMs, DEFAULT_EXECUTION_LIMITS.totalTimeoutMs, 1, 60_000)
  };
  const invokeTool = typeof options.invokeTool === "function"
    ? options.invokeTool
    : plugin.invokeTool.bind(plugin);

  const records = new Array(plan.tasks.length);
  const deadline = Date.now() + limits.totalTimeoutMs;
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const index = nextIndex++;
      if (index >= plan.tasks.length) return;
      const current = plan.tasks[index];

      if (current.skipReason) {
        records[index] = createNotCheckedEvidence(current.toolName, { reason: current.skipReason });
        continue;
      }

      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        records[index] = createNotCheckedEvidence(current.toolName, {
          reason: "The total assessment deadline elapsed before this check could start."
        });
        continue;
      }

      const startedAt = new Date().toISOString();
      const started = Date.now();
      try {
        const args = cloneJsonValue(current.input);
        const pending = Promise.resolve().then(() => invokeTool(current.toolName, args));
        const result = await withTimeout(
          pending,
          Math.min(limits.perToolTimeoutMs, remaining),
          current.toolName
        );
        records[index] = normalizeToolResult(current.toolName, result, {
          startedAt,
          completedAt: new Date().toISOString(),
          durationMs: Date.now() - started,
          required: current.required
        });
      } catch (error) {
        records[index] = createErrorEvidence(current.toolName, error, {
          startedAt,
          completedAt: new Date().toISOString(),
          durationMs: Date.now() - started,
          errorCode: error?.code || (error?.name === "TimeoutError" ? "AGENT_TOOL_TIMEOUT" : "TOOL_EXECUTION_FAILED")
        });
      }
    }
  }

  await Promise.all(Array.from(
    { length: Math.min(limits.maxConcurrency, plan.tasks.length) },
    () => worker()
  ));

  return records;
}
