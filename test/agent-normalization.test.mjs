import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeToolResult, aggregateEvidence, createErrorEvidence } from '../src/agent/index.mjs';

test('normalizer rejects unknown tool names instead of silently accepting them', () => {
  assert.throws(() => normalizeToolResult('payguard_unknown', { verdict: 'PASS' }), /Unknown PayGuard tool/);
});

test('serialization failure becomes ERROR and cannot become a pass', () => {
  const circular = {};
  circular.self = circular;
  const result = normalizeToolResult('payguard_check_token_security', circular);
  assert.equal(result.status, 'ERROR');
  assert.equal(result.errorCode, 'EVIDENCE_SERIALIZATION_FAILED');
  assert.equal(aggregateEvidence([result]).overallStatus, 'ERROR');
});

test('oversized output becomes ERROR instead of dropping provenance and passing', () => {
  const result = normalizeToolResult('payguard_check_token_security', { text: 'x'.repeat(513_000) });
  assert.equal(result.status, 'ERROR');
  assert.equal(result.errorCode, 'RAW_OUTPUT_LIMIT_EXCEEDED');
  assert.equal(typeof result.rawOutputSha256, 'string');
  assert.equal(result.rawOutputOmittedReason, 'MAX_RAW_OUTPUT_CHARS_EXCEEDED');
});

test('explicit provider-unavailable payload stays UNVERIFIED, not ERROR or VERIFIED', () => {
  const result = normalizeToolResult('payguard_check_address_security', {
    verdict: 'UNVERIFIED', dataStatus: 'UNAVAILABLE', provider: 'goplus'
  });
  assert.equal(result.status, 'UNVERIFIED');
});

test('explicit execution failure is represented as ERROR', () => {
  const result = normalizeToolResult('payguard_scan_wallet_tokens', { status: 'ERROR', error: 'provider failed' });
  assert.equal(result.status, 'ERROR');
});
