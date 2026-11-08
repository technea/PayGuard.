/**
 * @module agent
 * @section Public deterministic agent API
 * Exposes evidence normalization, bounded orchestration, and the integrated
 * PayGuard runtime adapter. No model planner, hosted endpoint, signing, or execution.
 */

export { EVIDENCE_STATUSES, STATUS_PRECEDENCE, EVIDENCE_SCHEMA_VERSION, TOOL_CATALOG } from "./constants.mjs";
export { canonicalJson, cloneJsonValue } from "./canonical-json.mjs";
export { sanitizeUntrustedText, extractUntrustedText } from "./untrusted-data.mjs";
export { normalizeToolStatus, resolveStatus } from "./status.mjs";
export { listAgentCompatibleTools, isKnownPayGuardTool, getToolDefinition } from "./tool-catalog.mjs";
export { createNotCheckedEvidence, createErrorEvidence } from "./evidence-record.mjs";
export { normalizeToolResult } from "./normalize-result.mjs";
export { aggregateEvidence } from "./aggregate.mjs";
export { buildEvidenceReport } from "./report.mjs";
export { runInvestigation } from "./runner.mjs";
export { createPayGuardToolExecutor } from "./payguard-executor.mjs";
export { runPayGuardInvestigation } from "./investigation.mjs";
