/**
 * @module agent
 * @section Public Phase B evidence API
 * Exposes deterministic evidence primitives only; no planner, model, REST route,
 * MCP tool registration, signing or transaction execution is included in Phase B.
 */

export { EVIDENCE_STATUSES, STATUS_PRECEDENCE, EVIDENCE_SCHEMA_VERSION, TOOL_CATALOG } from "./constants.mjs";
export { canonicalJson, cloneJsonValue } from "./canonical-json.mjs";
export { sanitizeUntrustedText, extractUntrustedText } from "./untrusted-data.mjs";
export { normalizeToolStatus, resolveStatus } from "./status.mjs";
export { listAgentCompatibleTools, isKnownPayGuardTool, getToolDefinition } from "./tool-catalog.mjs";
export { createNotCheckedEvidence, createErrorEvidence, createDerivedEvidence } from "./evidence-record.mjs";
export { normalizeToolResult } from "./normalize-result.mjs";
export { aggregateEvidence } from "./aggregate.mjs";
export { buildEvidenceReport } from "./report.mjs";
export { buildAssessmentPlan } from "./plan.mjs";
export { DEFAULT_EXECUTION_LIMITS, validateAssessmentInput, executeAssessmentPlan } from "./execution.mjs";
export { runSecurityAssessment } from "./orchestrator.mjs";
export { correlatePaymentAndTransaction, CORRELATION_SOURCE } from "./correlation.mjs";
