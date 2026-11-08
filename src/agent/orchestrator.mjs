/**
 * @module agent/orchestrator
 * @section Public deterministic security assessment
 * Coordinates explicit checks, preserves evidence, and returns a fixed-template report.
 * This library does not expose an HTTP route or register an MCP tool.
 */

import { buildAssessmentPlan } from "./plan.mjs";
import { executeAssessmentPlan, validateAssessmentInput } from "./execution.mjs";
import { buildEvidenceReport } from "./report.mjs";

export async function runSecurityAssessment(input, options = {}) {
  const safeInput = validateAssessmentInput(input, options.maxInputChars);
  const plan = buildAssessmentPlan(safeInput);
  const records = await executeAssessmentPlan(plan, options);

  const report = buildEvidenceReport(plan.subject, records, {
    investigationId: options.investigationId || null
  });

  return {
    plan: plan.tasks.map(item => ({
      toolName: item.toolName,
      required: item.required,
      skipped: Boolean(item.skipReason)
    })),
    report
  };
}
