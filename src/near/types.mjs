/**
 * PayGuard — NEAR Protocol Type Definitions & Enums
 */

export const AccountStatus = Object.freeze({
  EXISTS: "EXISTS",
  UNREGISTERED: "UNREGISTERED",
  UNVERIFIED: "UNVERIFIED",
  INVALID_SYNTAX: "INVALID_SYNTAX"
});

export const AssessmentVerdict = Object.freeze({
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  UNVERIFIED: "UNVERIFIED"
});

export const FindingType = Object.freeze({
  FACT: "FACT",
  SUSPICIOUS_INDICATOR: "SUSPICIOUS_INDICATOR",
  UNKNOWN: "UNKNOWN",
  CONFIRMED_THREAT: "CONFIRMED_THREAT"
});

export const Severity = Object.freeze({
  INFO: "INFO",
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL"
});

export const FindingCategory = Object.freeze({
  BYTECODE: "BYTECODE",
  AUTHENTICATION: "AUTHENTICATION",
  STORAGE: "STORAGE",
  IMPERSONATION: "IMPERSONATION",
  CONSISTENCY: "CONSISTENCY"
});

