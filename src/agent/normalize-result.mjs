/**
 * @module agent/normalize-result
 * @section Tool result normalization
 * Retains a detached raw result and hash while exposing a bounded normalized view.
 */

import { createHash } from "node:crypto";
import {
  EVIDENCE_SCHEMA_VERSION,
  MAX_RAW_OUTPUT_CHARS,
  TOOL_CATALOG
} from "./constants.mjs";
import { canonicalJson, cloneJsonValue } from "./canonical-json.mjs";
import { extractUntrustedText } from "./untrusted-data.mjs";
import { normalizeToolStatus } from "./status.mjs";
import { createErrorEvidence } from "./evidence-record.mjs";

function summarizeEvidence(result) {
  const findings = [];
  const add = (code, severity) => {
    if (typeof code !== "string") return;
    findings.push({ code: code.slice(0, 120), severity: typeof severity === "string" ? severity.toUpperCase().slice(0, 20) : null });
  };
  if (Array.isArray(result.findings)) {
    for (const finding of result.findings.slice(0, 100)) add(finding?.code || finding?.id, finding?.severity);
  }
  if (Array.isArray(result.reasonCodes)) {
    for (const code of result.reasonCodes.slice(0, 100)) add(code, null);
  }
  if (Array.isArray(result.checks)) {
    for (const check of result.checks.slice(0, 100)) {
      if (["fail", "failed", "warning", "unknown", "FAIL", "WARNING"].includes(String(check?.status || ""))) {
        add(check?.id || check?.code, check?.severity);
      }
    }
  }
  return findings;
}

export function normalizeToolResult(toolName, rawResult, options = {}) {
  if (!Object.hasOwn(TOOL_CATALOG, toolName)) {
    throw new TypeError(`Unknown PayGuard tool '${toolName}'.`);
  }

  const completedAt = options.completedAt || new Date().toISOString();
  const base = {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    id: options.id || `${toolName}:${completedAt}`,
    source: toolName,
    checkId: options.checkId || toolName,
    required: options.required !== false,
    startedAt: options.startedAt || null,
    completedAt,
    durationMs: Number.isFinite(options.durationMs) && options.durationMs >= 0 ? options.durationMs : null
  };

  try {
    const canonical = canonicalJson(rawResult);
    if (canonical.length > MAX_RAW_OUTPUT_CHARS) {
      return createErrorEvidence(toolName, new Error("Output limit exceeded"), {
        ...base,
        errorCode: "RAW_OUTPUT_LIMIT_EXCEEDED"
      });
    }
    const detachedRaw = cloneJsonValue(rawResult);
    const rawOutputSha256 = createHash("sha256").update(canonical, "utf8").digest("hex");
    const normalized = normalizeToolStatus(toolName, rawResult);
    const evidence = summarizeEvidence(rawResult);

    return {
      ...base,
      status: normalized.status,
      reason: normalized.reason,
      rawOutput: detachedRaw,
      rawOutputSha256,
      evidence,
      untrustedData: extractUntrustedText(rawResult)
    };
  } catch (error) {
    return createErrorEvidence(toolName, error, {
      ...base,
      errorCode: "EVIDENCE_SERIALIZATION_FAILED"
    });
  }
}
