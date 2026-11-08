/**
 * @module agent/evidence-record
 * @section Evidence record constructors
 * Creates explicit records for completed, skipped and failed checks.
 */

import { EVIDENCE_SCHEMA_VERSION } from "./constants.mjs";

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
    durationMs: Number.isFinit(options.durationMs) && options.durationMs >= 0 ? options.durationMs : null,
    rawOutput: null,
    rawOutputSha256: null,
    evidence: [],
    untrustedData: []
  };
}
