import test from 'node:test';
import assert from 'node:assert/strict';
import { runSyntheticBenchmark } from '../src/agent/benchmark.mjs';

test('synthetic offline benchmark is deterministic and makes no production accuracy claim', async () => {
  const result = await runSyntheticBenchmark();
  assert.equal(result.benchmarkType, 'SYNTHETIC_OFFLINE');
  assert.equal(result.externalNetworkCalls, 0);
  assert.equal(result.realWorldAccuracyClaim, false);
  assert.equal(result.summary.totalCases, 12);
  assert.equal(result.summary.fixtureMatchRate, 1);
  assert.equal(result.summary.syntheticRiskDetectionRate, 1);
  assert.equal(result.summary.syntheticFalsePositiveRate, 0);
  assert.deepEqual(result.summary.missedRiskCases, []);
  assert.deepEqual(result.summary.falsePositiveCases, []);
  assert.equal(result.summary.unresolvedCases.length, 1);
  assert.ok(result.cases.some(item => item.id === 'calldata.unsupported-selector' && item.actualStatus === 'UNVERIFIED'));
});

test('benchmark contains payment intent and decoded transaction mismatch scenarios', async () => {
  const result = await runSyntheticBenchmark();
  const mismatch = result.cases.find(item => item.id === 'correlation.recipient-mismatch');
  const match = result.cases.find(item => item.id === 'correlation.intent-transfer-match');
  assert.equal(mismatch.expectedStatus, 'RISK_DETECTED');
  assert.equal(mismatch.actualStatus, 'RISK_DETECTED');
  assert.equal(match.expectedStatus, 'VERIFIED');
  assert.equal(match.actualStatus, 'VERIFIED');
});
