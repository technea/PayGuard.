/** Public types for PayGuard's deterministic agent library. */

export type EvidenceStatus =
  | "VERIFIED"
  | "RISK_DETECTED"
  | "UNVERIFIED"
  | "NOT_CHECKED"
  | "ERROR";

export interface EvidenceRecord {
  schemaVersion: string;
  id: string;
  source: string;
  checkId: string;
  required: boolean;
  status: EvidenceStatus;
  reason: string;
  rawOutput?: unknown;
  rawOutputSha256?: string | null;
  [key: string]: unknown;
}

export interface AssessmentInput {
  url?: string;
  expectedDomain?: string;
  trustedDomains?: string[];
  checkReputation?: boolean;
  contractAddress?: string;
  address?: string;
  walletAddress?: string;
  customTokenAddresses?: string[];
  chainId?: string | number;
  transaction?: {
    to: string;
    value?: string | number;
    data: string;
    policy?: Record<string, unknown>;
    network?: string | number;
  };
  intent?: Record<string, unknown>;
  paymentRequirements?: {
    resource?: string;
    accepts: Record<string, unknown>[];
    [key: string]: unknown;
  };
  selectedPaymentIndex?: number;
  prepareThreatReport?: boolean;
}

export interface AssessmentOptions {
  maxConcurrency?: number;
  perToolTimeoutMs?: number;
  totalTimeoutMs?: number;
  maxInputChars?: number;
  investigationId?: string;
  invokeTool?: (name: string, input: unknown) => Promise<unknown> | unknown;
}

export interface AssessmentReport {
  schemaVersion: string;
  investigationId: string | null;
  createdAt: string;
  overallStatus: EvidenceStatus;
  degraded: boolean;
  summary: string;
  findings: Array<Record<string, unknown>>;
  unresolved: Array<Record<string, unknown>>;
  evidence: EvidenceRecord[];
  limitations: string[];
  metrics: Record<string, unknown>;
}

export interface AssessmentResult {
  plan: Array<{ toolName: string; required: boolean; skipped: boolean }>;
  derivedChecks: Array<{ source: string; status: EvidenceStatus }>;
  report: AssessmentReport;
}

export declare function runSecurityAssessment(
  input: AssessmentInput,
  options?: AssessmentOptions
): Promise<AssessmentResult>;
