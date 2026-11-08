/**
 * @module agent/aggregate
 * @section Required and optional evidence correlation
 * Resolves an investigation state without allowing optional provider failures to
 * erase required-check results or any explicit risk finding.
 */

import { MAX_EVIDENCE_RECORDS } from "./constants.mjs";
import { resolveStatus } from "./status.mjs";

export function aggregateEvidence(records) {
  if (!Array.isArray(records)) throw new TypeError("Evidence records must be an array.");
  if (records.length > MAX_EVIDENCE_RECORDS) throw new RangeError("At most 32 evidence records are supported.");

  const required = records.filter(record => record?.required !== false);
  const optional = records.filter(record => record?.required === false);
  const riskDetected = records.some(record => record?.status === "RISK_DETECTED");
  const overallStatus = riskDetected
    ? "RISK_DETECTED"
    : required.length === 0
      ? "NOT_CHECKED"
      : resolveStatus(required.map(record => record?.status));

  const degraded = optional.some(record => record?.status !== "VERIFIED");
  return {
    overallStatus,
    degraded,
    requiredChecks: required.length,
    optionalChecks: optional.length,
    completedChecks: records.filter(record => record?.status !== "NOT_CHECKED").length,
    riskFindingCount: records.filter(record => record?.status === "RISK_DETECTED").length,
    unresolvedRequiredCount: required.filter(record => !["VERIFIED", "RISK_DETECTED"].includes(record?.status)).length,
    optionalFailureCount: optional.filter(record => ["ERROR", "UNVERIFIED", "NOT_CHECKED"].includes(record?.status)).length
  };
}
