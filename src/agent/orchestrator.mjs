/**
 * @module agent/orchestrator
 * @section Public deterministic security assessment
 * Coordinates explicit checks, adds intent-to-transfer correlation when possible,
 * preserves evidence, and returns a fixed-template report.
 * This library does not expose an HTTP route or register an MCP tool.
 */

import { buildAssessmentPlan } from "./plan.mjs";
import { executeAssessmentPlan, validateAssessmentInput } from "./execution.mjs";
import { buildEvidenceReport } from "./report.mjs";
import { createDerivedEvidence } from "./evidence-record.mjs";
import { correlatePaymentAndTransaction, CORRELATION_SOURCE } from "./correlation.mjs";

export async function runSecurityAssessment(input, options = {}) {
  const safeInput = validateAssessmentInput(input, options.maxInputChars);
  const plan = buildAssessmentPlan(safeInput);
  const records = await executeAssessmentPlan(plan, options);

  const hasPaymentContext = Object.hasOwn(safeInput, "intent") ||
    Object.hasOwn(safeInput, "paymentRequirements");
  if (Object.hasOwn(safeInput, "transaction") && hasPaymentContext) {
    const paymentEvidence = records.find(item => item.source === "payguard_check_payment_intent");
    const calldataEvidence = records.find(item => item.source === "payguard_inspect_calldata");
    const correlation = correlatePaymentAndTransaction({
      input: safeInput,
      paymentEvidence,
      calldataEvidence
    });
    records.push(createDerivedEvidence(CORRELATION_SOURCE, correlation, {
      status: correlation.status,
      reason: correlation.reason
    }));
  }

  const report = buildEvidenceReport(plan.subject, records, {
    investigationId: options.investigationId || null
  });

  return {
    plan: plan.tasks.map(item => ({
      toolName: item.toolName,
      required: item.required,
      skipped: Boolean(item.skipReason)
    })),
    derivedChecks: records.filter(item => item.source === CORRELATION_SOURCE).map(item => ({
      source: item.source,
      status: item.status
    })),
    report
  };
}
