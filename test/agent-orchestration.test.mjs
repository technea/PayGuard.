import test from 'node:test';
import assert from 'node:assert/strict';
import { runSecurityAssessment, buildAssessmentPlan } from '../src/agent/index.mjs';

test('planner only selects tools for explicitly supplied subjects', () => {
  const plan = buildAssessmentPlan({
    url: 'https://base.org',
    contractAddress: '0x1111111111111111111111111111111111111111'
  });
  assert.deepEqual(plan.tasks.map(item => item.toolName), [
    'payguard_analyze_url',
    'payguard_check_token_security'
  ]);
});

test('missing payment context is recorded as NOT_CHECKED, never silently skipped', async () => {
  const result = await runSecurityAssessment(
    { intent: { expectedResourceUrl: 'https://merchant.example' } },
    { invokeTool: async () => { throw new Error('must not execute'); } }
  );
  assert.equal(result.report.overallStatus, 'NOT_CHECKED');
  assert.equal(result.report.evidence[0].status, 'NOT_CHECKED');
  assert.equal(result.plan[0].skipped, true);
});

test('bounded worker pool never exceeds configured concurrency', async () => {
  let active = 0;
  let maximum = 0;
  const invokeTool = async (name) => {
    active += 1;
    maximum = Math.max(maximum, active);
    await new Promise(resolve => setTimeout(resolve, 8));
    active -= 1;
    if (name === 'payguard_analyze_url') {
      return { verdict: 'EXPECTED_DOMAIN_MATCH', riskLevel: 'LOW' };
    }
    if (name === 'payguard_check_token_security' || name === 'payguard_check_address_security') {
      return { verdict: 'PASS', dataStatus: 'AVAILABLE' };
    }
    return {
      status: 'SUCCESS',
      discoveryMode: 'FULL_INDEXER',
      summary: { totalTokensScanned: 1, highRiskCount: 0, suspiciousCount: 0, cleanCount: 1, unverifiedCount: 0 },
      tokens: [{ verdict: 'PASS', riskLevel: 'LOW', securityStatus: 'NO KNOWN ISSUES FOUND' }]
    };
  };

  const result = await runSecurityAssessment({
    url: 'https://base.org',
    contractAddress: '0x1111111111111111111111111111111111111111',
    address: '0x2222222222222222222222222222222222222222',
    walletAddress: '0x3333333333333333333333333333333333333333'
  }, { invokeTool, maxConcurrency: 2, perToolTimeoutMs: 500, totalTimeoutMs: 2_000 });

  assert.equal(maximum, 2);
  assert.equal(result.report.overallStatus, 'VERIFIED');
  assert.equal(result.report.evidence.length, 4);
});

test('tool timeout becomes ERROR and cannot be reported as VERIFIED', async () => {
  const result = await runSecurityAssessment(
    { url: 'https://example.com' },
    {
      invokeTool: () => new Promise(() => {}),
      perToolTimeoutMs: 10,
      totalTimeoutMs: 100
    }
  );
  assert.equal(result.report.overallStatus, 'ERROR');
  assert.equal(result.report.evidence[0].errorCode, 'AGENT_TOOL_TIMEOUT');
});

test('total deadline leaves queued checks explicitly NOT_CHECKED', async () => {
  const result = await runSecurityAssessment({
    url: 'https://example.com',
    contractAddress: '0x1111111111111111111111111111111111111111'
  }, {
    invokeTool: async () => new Promise(resolve => setTimeout(
      () => resolve({ verdict: 'EXPECTED_DOMAIN_MATCH', riskLevel: 'LOW' }),
      30
    )),
    maxConcurrency: 1,
    perToolTimeoutMs: 100,
    totalTimeoutMs: 10
  });
  assert.equal(result.report.evidence[0].status, 'ERROR');
  assert.equal(result.report.evidence[1].status, 'NOT_CHECKED');
  assert.equal(result.report.overallStatus, 'ERROR');
});

test('input validation rejects circular and oversized payloads', async () => {
  const circular = {};
  circular.self = circular;
  await assert.rejects(() => runSecurityAssessment({ url: 'https://example.com', extra: circular }), /JSON-serializable/);
  await assert.rejects(() => runSecurityAssessment({ url: 'x'.repeat(65_000) }), /size limit/);
});

test('transaction planning omits absent optional fields instead of creating undefined values', () => {
  const plan = buildAssessmentPlan({
    transaction: {
      to: '0x1111111111111111111111111111111111111111',
      data: '0x'
    }
  });
  assert.deepEqual(plan.tasks[0].input, {
    to: '0x1111111111111111111111111111111111111111',
    data: '0x'
  });
});

test('planner rejects empty requests instead of inventing a scan target', () => {
  assert.throws(() => buildAssessmentPlan({}), /at least one supported subject/);
});
