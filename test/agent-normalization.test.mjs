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

test('null tool output remains UNVERIFIED with preserved raw output', () => {
  const result = normalizeToolResult('payguard_check_token_security', null);
  assert.equal(result.status, 'UNVERIFIED');
  assert.equal(result.rawOutput, null);
  assert.equal(typeof result.rawOutputSha256, 'string');
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

test('maps actual PayGuard URL verdicts without treating unknown as safe', () => {
  const official = normalizeToolResult('payguard_analyze_url', {
    verdict: 'EXPECTED_DOMAIN_MATCH', riskLevel: 'LOW', statusCategory: 'VERIFIED OFFICIAL'
  });
  const suspicious = normalizeToolResult('payguard_analyze_url', {
    verdict: 'SUSPICIOUS', riskLevel: 'HIGH', statusCategory: 'HIGH RISK'
  });
  const noKnownThreat = normalizeToolResult('payguard_analyze_url', {
    verdict: 'NO_KNOWN_THREAT', riskLevel: 'LOW'
  });
  assert.equal(official.status, 'VERIFIED');
  assert.equal(suspicious.status, 'RISK_DETECTED');
  assert.equal(noKnownThreat.status, 'UNVERIFIED');
});

test('maps actual payment-intent statuses conservatively', () => {
  const pass = normalizeToolResult('payguard_check_payment_intent', {
    status: 'PASS', paymentExecuted: false
  });
  const review = normalizeToolResult('payguard_check_payment_intent', {
    status: 'REVIEW', paymentExecuted: false
  });
  const block = normalizeToolResult('payguard_check_payment_intent', {
    status: 'BLOCK', paymentExecuted: false
  });
  assert.equal(pass.status, 'VERIFIED');
  assert.equal(review.status, 'UNVERIFIED');
  assert.equal(block.status, 'RISK_DETECTED');
});

test('provider dataStatus ERROR is not mistaken for a successful or merely unknown check', () => {
  const result = normalizeToolResult('payguard_check_token_security', {
    verdict: 'UNVERIFIED', dataStatus: 'ERROR', findings: [], reasonCodes: ['AUTH_FAILED']
  });
  assert.equal(result.status, 'ERROR');
});

test('partial wallet discovery remains UNVERIFIED even when discovered tokens pass', () => {
  const result = normalizeToolResult('payguard_scan_wallet_tokens', {
    status: 'SUCCESS',
    discoveryMode: 'REGISTRY_AND_CUSTOM_PARTIAL',
    summary: { totalTokensScanned: 7, highRiskCount: 0, suspiciousCount: 0, cleanCount: 7, unverifiedCount: 0 },
    tokens: Array.from({ length: 7 }, () => ({
      verdict: 'PASS', riskLevel: 'LOW', securityStatus: 'NO KNOWN ISSUES FOUND'
    }))
  });
  assert.equal(result.status, 'UNVERIFIED');
});


test('calldata BLOCK is a risk finding while calldata REVIEW remains inconclusive', () => {
  const blocked = normalizeToolResult('payguard_inspect_calldata', {
    verdict: 'BLOCK', riskLevel: 'HIGH', reasons: ['UNLIMITED_ALLOWANCE_UINT256_MAX'],
    checks: [{ id: 'allowance_size', status: 'WARN' }]
  });
  const review = normalizeToolResult('payguard_inspect_calldata', {
    verdict: 'REVIEW', riskLevel: 'MEDIUM', reasons: ['UNSUPPORTED_SELECTOR'],
    checks: [{ id: 'selector', status: 'WARN' }]
  });
  assert.equal(blocked.status, 'RISK_DETECTED');
  assert.equal(review.status, 'UNVERIFIED');
});

test('token provider REVIEW remains UNVERIFIED instead of being overstated as malicious', () => {
  const result = normalizeToolResult('payguard_check_token_security', {
    verdict: 'REVIEW', riskLevel: 'MEDIUM', dataStatus: 'AVAILABLE',
    findings: [{ code: 'MEDIUM_RISK', severity: 'medium' }]
  });
  assert.equal(result.status, 'UNVERIFIED');
});

test('wallet scanner summary risk counts and impersonation are preserved as risk signals', () => {
  const result = normalizeToolResult('payguard_scan_wallet_tokens', {
    status: 'SUCCESS',
    discoveryMode: 'FULL_INDEXER',
    summary: { totalTokensScanned: 1, highRiskCount: 0, suspiciousCount: 1, cleanCount: 0, unverifiedCount: 0 },
    tokens: [{ verdict: 'REVIEW', riskLevel: 'MEDIUM', securityStatus: 'SUSPICIOUS', isImpersonation: true }]
  });
  assert.equal(result.status, 'RISK_DETECTED');
});
