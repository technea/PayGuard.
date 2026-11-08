/**
 * @module agent/evidence-record
 * @section Evidence record constructors
 * Creates explicit records for completed, skipped, failed, and derived checks.
 */

import { createHash } from "node:crypto";
import { EVIDENCE_SCHEMA_VERSION, EVIDENCE_STATUSES, MAX_RAW_OUTPUT_CHARS } from "./constants.mjs";
import { canonicalJson, cloneJsonValue } from "./canonical-json.mjs";

export function createNotCheckedEvidence(toolName, options = {}) {
  const now = options.timestamp || new Date().toISOString();
  return {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    id: options.id || `${toolName}:not-checked`,
    source: toolName,
    checkId: options.checkId || toolName,
    required: options.required !== false,
    status: "NOT_CHECKED",
    reason: options.reason || "This check was not executed.",
    startedAt: null,
    completedAt: now,
    durationMs: 0,
    rawOutput: null,
    rawOutputSha256: null,
    evidence: [],
    untrustedData: []
  };
}

export function createErrorEvidence(toolName, error, options = {}) {
  const now = options.completedAt || new Date().toISOString();
  const safeName = error && typeof error.name === "string" ? error.name.slice(0, 80) : "Error";
  return {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    id: options.id || `${toolName}:error`,
    source: toolName,
    checkId: options.checkId || toolName,
    required: options.required !== false,
    status: "ERROR",
    reason: `${safeName}: The check could not complete.`,
    errorCode: options.errorCode || "TOOL_EXECUTION_FAILED",
    startedAt: options.startedAt || null,
    completedAt: now,
    durationMs: Number.isFinite(options.durationMs) && options.durationMs >= 0 ? options.durationMs : null,
    rawOutput: null,
    rawOutputSha256: null,
    evidence: [],
    untrustedData: []
  };
}

/**
 * Create a hash-backed evidence record for a deterministic, locally derived check.
 * Derived checks do not add a new MCP tool or external provider dependency.
 */
export function createDerivedEvidence(source, output, options = {}) {
  if (typeof source !== "string" || !source.trim()) {
    throw new TypeError("Derived evidence requires a non-empty source identifier.");
  }
  if (!EVIDENCE_STATUSES.includes(options.status)) {
    throw new TypeError("Derived evidence requires a recognized evidence status.");
  }

  const completedAt = options.completedAt || new Date().toISOString();
  try {
    const canonical = canonicalJson(output);
    if (canonical.length > MAX_RAW_OUTPUT_CHARS) {
      return createErrorEvidence(source, new Error("Derived output limit exceeded"), {
        completedAt,
        errorCode: "DERIVED_OUTPUT_LIMIT_EXCEEDED"
      });
    }
    const rawOutputSha256 = createHash("sha256").update(canonical, "utf8").digest("hex");
    const rawOutput = cloneJsonValue(output);
    const evidence = Array.isArray(output?.checks)
      ? output.checks.slice(0, 100).map(check => ({
          code: typeof check?.id === "string" ? check.id.slice(0, 120) : "CORRELATION_CHECK",
          severity: typeof check?.status === "string" ? check.status.toUpperCase().slice(0, 20) : null
        }))
      : [];

    return {
      schemaVersion: EVIDENCE_SCHEMA_VERSION,
      id: options.id || `${source}:${completedAt}`,
      source,
      checkId: options.checkId || source,
      required: options.required !== false,
      status: options.status,
      reason: options.reason || "Deterministic derived check completed.",
      startedAt: options.startedAt || completedAt,
      completedAt,
      durationMs: Number.isFinite(options.durationMs) && options.durationMs >= 0 ? options.durationMs : 0,
      rawOutput,
      rawOutputSha256,
      rawOutputSizeChars: canonical.length,
      evidence,
      untrustedData: []
    };
  } catch (error) {
    return createErrorEvidence(source, error, {
      completedAt,
      errorCode: "DERIVED_EVIDENCE_SERIALIZATION_FAILED"
    });
  }
}
