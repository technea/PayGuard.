/**
 * @module agent
 * @section Public deterministic agent API
 * Exposes evidence and bounded explicit-plan orchestration; no model planner, REST route,
 * MCP tool registration, signing or transaction execution is included.
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
