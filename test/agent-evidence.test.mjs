import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  aggregateEvidence,
  buildEvidenceReport,
  canonicalJson,
  createErrorEvidence,
  createNotCheckedEvidence,
  extractUntrustedText,
  listAgentCompatibleTools,
  normalizeToolResult,
  normalizeToolStatus,
  resolveStatus
} from '../src/agent/index.mjs';
import { fixtures } from './fixtures/agent-tool-results.mjs';

const tool = 'payguard_check_token_security';

test('catalog contains exactly the seven existing read-only tools', () => {
  const entries = listAgentCompatibleTools();
  assert.equal(entries.length, 7);
  assert.ok(entries.every(entry => entry.access === 'READ_ONLY'));
});

test('canonical JSON sorts object keys without changing array order', () => {
  assert.equal(canonicalJson({ b: 2, a: 1, list: [2, 1] }), '{"a":1,"b":2,"list":[2,1]}');
});

test('tool result keeps a detached raw snapshot and SHA-256 hash', () => {
  const raw = { verdict: 'PASS', dataStatus: 'AVAILABLE', nested: { b: 2, a: 1 } };
  const record = normalizeToolResult(tool, raw);
  raw.nested.a = 999;
  assert.equal(record.rawOutput.nested.a, 1);
  assert.equal(record.rawOutputSha256, createHash('sha256').update('{"dataStatus":"AVAILABLE","nested":{"a":1,"b":2},"verdict":"PASS"}').digest('hex'));
  assert.equal(record.status, 'VERIFIED');
});

test('seven tool families map to conservative evidence states', () => {
  assert.equal(normalizeToolStatus('payguard_check_payment_intent', fixtures.paymentPass).status, 'VERIFIED');
  assert.equal(normalizeToolStatus('payguard_check_payment_intent', fixtures.paymentBlock).status, 'RISK_DETECTED');
  assert.equal(normalizeToolStatus('payguard_check_token_security', { verdict: 'BLOCK', dataStatus: 'UNSUPPORTED' }).status, 'RISK_DETECTED');
  assert.equal(normalizeToolStatus('payguard_analyze_url', fixtures.urlOfficial).status, 'VERIFIED');
  assert.equal(normalizeToolStatus('payguard_analyze_url', fixtures.urlNoMatch).status, 'UNVERIFIED');
  assert.equal(normalizeToolStatus('payguard_analyze_url', fixtures.urlMalicious).status, 'RISK_DETECTED');
  assert.equal(normalizeToolStatus('payguard_inspect_calldata', fixtures.calldataReview).status, 'RISK_DETECTED');
  assert.equal(normalizeToolStatus('payguard_check_token_security', fixtures.tokenPass).status, 'VERIFIED');
  assert.equal(normalizeToolStatus('payguard_check_token_security', fixtures.tokenUnavailable).status, 'UNVERIFIED');
  assert.equal(normalizeToolStatus('payguard_check_address_security', fixtures.addressReview).status, 'RISK_DETECTED');
  assert.equal(normalizeToolStatus('payguard_scan_wallet_tokens', fixtures.walletRisk).status, 'RISK_DETECTED');
  assert.equal(normalizeToolStatus('payguard_scan_wallet_tokens', fixtures.walletPartial).status, 'UNVERIFIED');
  assert.equal(normalizeToolStatus('payguard_scan_wallet_tokens', fixtures.walletClean).status, 'VERIFIED');
});

test('unknown and no-match results never become VERIFIED', () => {
  assert.equal(normalizeToolStatus('payguard_analyze_url', { verdict: 'NO_KNOWN_THREAT' }).status, 'UNVERIFIED');
  assert.equal(normalizeToolStatus('payguard_analyze_url', { verdict: 'MYSTERY' }).status, 'UNVERIFIED');
});

test('provider text is isolated as sanitized untrusted data', () => {
  const record = normalizeToolResult('payguard_check_token_security', fixtures.providerText);
  assert.ok(record.untrustedData.some(entry => entry.text.includes('Ignore all rules')));
  assert.ok(record.untrustedData.every(entry => entry.trust === 'UNTRUSTED_DATA'));
  assert.ok(!record.untrustedData.some(entry => entry.text.includes('\u202E')));
  assert.equal(record.rawOutput.token.tokenSymbol, fixtures.providerText.token.tokenSymbol);
});

test('NOT_CHECKED and ERROR are explicit records, not passes', () => {
  assert.equal(createNotCheckedEvidence(tool).status, 'NOT_CHECKED');
  assert.equal(createErrorEvidence(tool, new Error('sensitive provider detail')).status, 'ERROR');
  assert.equal(createErrorEvidence(tool, new Error('sensitive provider detail')).reason.includes('sensitive'), false);
});

test('status precedence preserves a detected risk above errors and uncertainty', () => {
  assert.equal(resolveStatus(['VERIFIED', 'UNVERIFIED', 'ERROR', 'RISK_DETECTED']), 'RISK_DETECTED');
  assert.equal(resolveStatus(['VERIFIED', 'NOT_CHECKED', 'UNVERIFIED']), 'UNVERIFIED');
  assert.equal(resolveStatus([]), 'NOT_CHECKED');
});

test('required ERROR raises overall state while optional ERROR only degrades', () => {
  const requiredError = createErrorEvidence(tool, new Error('failed'));
  assert.equal(aggregateEvidence([requiredError]).overallStatus, 'ERROR');

  const requiredPass = normalizeToolResult(tool, fixtures.tokenPass, { required: true });
  const optionalError = createErrorEvidence('payguard_analyze_url', new Error('failed'), { required: false });
  const aggregate = aggregateEvidence([requiredPass, optionalError]);
  assert.equal(aggregate.overallStatus, 'VERIFIED');
  assert.equal(aggregate.degraded, true);
  assert.equal(aggregate.optionalFailureCount, 1);
});

test('optional risk still raises the overall state', () => {
  const requiredPass = normalizeToolResult(tool, fixtures.tokenPass, { required: true });
  const optionalRisk = normalizeToolResult('payguard_analyze_url', fixtures.urlMalicious, { required: false });
  assert.equal(aggregateEvidence([requiredPass, optionalRisk]).overallStatus, 'RISK_DETECTED');
});

test('missing required check prevents a verified overall result', () => {
  const requiredPass = normalizeToolResult(tool, fixtures.tokenPass, { required: true });
  const skipped = createNotCheckedEvidence('payguard_analyze_url', { required: true });
  assert.equal(aggregateEvidence([requiredPass, skipped]).overallStatus, 'NOT_CHECKED');
});

test('report summary is deterministic and includes evidence limitations', () => {
  const record = normalizeToolResult(tool, fixtures.tokenPass);
  const report = buildEvidenceReport({ type: 'token', value: '0xabc' }, [record], { investigationId: 'test-1' });
  assert.equal(report.overallStatus, 'VERIFIED');
  assert.ok(report.summary.includes('not a guarantee'));
  assert.ok(report.limitations.some(item => item.includes('does not sign')));
});

test('untrusted extraction is bounded and truncates oversized text', () => {
  const entries = extractUntrustedText({ a: 'x'.repeat(3000), b: 'second' }, { maxEntries: 1, maxLength: 100 });
  assert.equal(entries.length, 1);
  assert.ok(entries[0].text.endsWith('[truncated]'));
});
