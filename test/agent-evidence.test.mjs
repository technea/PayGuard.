import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  aggregateEvidence,
  buildEvidenceReport,
  canonicalJson,\
  createErrorEvidence,
  createNotCheckedEvidence,
  extractUntrustedText,
  listAgentCompatibleTools,
  normalizeToolResult,
  normalizeToolStatus,
  resolveStatus
} from '../src/agent/index.mjs';
import { fixtures } from './fixtures/agent-tool-results.mjs';
