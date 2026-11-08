import test from 'node:test';
import assert from 'node:assert/strict';
import { runSecurityAssessment } from '../src/agent/index.mjs';

const ASSET = '0x1111111111111111111111111111111111111111';
const RECIPIENT = '0x2222222222222222222222222222222222222222';
const OTHER = '0x3333333333333333333333333333333333333333';

function baseInput(overrides = {}) {
  return {
    intent: { trusted: true },
    paymentRequirements: {
      resource: 'https://merchant.example',
      accepts: [{
        scheme: 'exact',
        network: 'eip155:8453',
        asset: ASSET,
        payTo: RECIPIENT,
        amount: '5000000',
        maxTimeoutSeconds: 300
      }]
    },
    transaction: {
      network: '8453',
      to: ASSET,
      data: '0x'
    },
    ...overrides
  };
}

function invoker({ recipient = RECIPIENT, amount = '5000000', asset = ASSET, operation = 'ERC20_TRANSFER', network = 'eip155:8453', candidateStatus = 'PASS' } = {}) {
  return async (name) => {
    if (name === 'payguard_check_payment_intent') {
      return {
        status: candidateStatus === 'PASS' ? 'PASS' : candidateStatus,
        paymentExecuted: false,
        candidateResults: [{ index: 0, status: candidateStatus, checks: [] }]
      };
    }
    if (name === 'payguard_inspect_calldata') {
      return {
        verdict: 'PASS',
        operation,
        details: {
          tokenContract: asset,
          recipient,
          amount
        },
        checks: [{ id: 'calldata_decode', status: 'PASS' }]
      };
    }
    throw new Error('Unexpected tool: ' + name);
  };
}

test('matching payment intent and ERC-20 transfer produce verified correlation evidence', async () => {
  const result = await runSecurityAssessment(baseInput(), { invokeTool: invoker() });
  assert.equal(result.derivedChecks[0].status, 'VERIFIED');
  assert.equal(result.report.overallStatus, 'VERIFIED');
  const correlation = result.report.evidence.find(item => item.source === 'payguard_agent_intent_transaction_correlation');
  assert.equal(correlation.rawOutput.checks.length, 4);
  assert.equal(typeof correlation.rawOutputSha256, 'string');
});

test('recipient mismatch is a deterministic risk finding', async () => {
  const result = await runSecurityAssessment(baseInput(), { invokeTool: invoker({ recipient: OTHER }) });
  assert.equal(result.derivedChecks[0].status, 'RISK_DETECTED');
  assert.equal(result.report.overallStatus, 'RISK_DETECTED');
  assert.ok(result.report.findings.some(item => item.source === 'payguard_agent_intent_transaction_correlation'));
});

test('asset and amount mismatches are risk findings', async () => {
  const assetMismatch = await runSecurityAssessment(baseInput(), { invokeTool: invoker({ asset: OTHER }) });
  const amountMismatch = await runSecurityAssessment(baseInput(), { invokeTool: invoker({ amount: '5000001' }) });
  assert.equal(assetMismatch.derivedChecks[0].status, 'RISK_DETECTED');
  assert.equal(amountMismatch.derivedChecks[0].status, 'RISK_DETECTED');
});

test('network mismatch is a risk finding', async () => {
  const result = await runSecurityAssessment(baseInput({ transaction: {
    network: 'eip155:84532', to: ASSET, data: '0x'
  } }), { invokeTool: invoker() });
  assert.equal(result.derivedChecks[0].status, 'RISK_DETECTED');
});

test('missing network evidence remains UNVERIFIED', async () => {
  const result = await runSecurityAssessment(baseInput({ transaction: {
    to: ASSET, data: '0x'
  } }), { invokeTool: invoker() });
  assert.equal(result.derivedChecks[0].status, 'UNVERIFIED');
  assert.equal(result.report.overallStatus, 'UNVERIFIED');
});

test('unsupported network identifiers remain UNVERIFIED instead of matching arbitrary strings', async () => {
  const input = baseInput({ transaction: {
    network: 'made-up-network', to: ASSET, data: '0x'
  } });
  const result = await runSecurityAssessment(input, { invokeTool: invoker() });
  assert.equal(result.derivedChecks[0].status, 'UNVERIFIED');
});

test('multiple payment alternatives require an explicit selectedPaymentIndex', async () => {
  const input = baseInput();
  input.paymentRequirements.accepts.push({ ...input.paymentRequirements.accepts[0], payTo: OTHER });
  const result = await runSecurityAssessment(input, { invokeTool: invoker() });
  assert.equal(result.derivedChecks[0].status, 'UNVERIFIED');
});

test('explicitly selected payment alternative can be correlated', async () => {
  const input = baseInput({ selectedPaymentIndex: 1 });
  input.paymentRequirements.accepts.push({ ...input.paymentRequirements.accepts[0] });
  const invoke = async (name) => {
    if (name === 'payguard_check_payment_intent') {
      return {
        status: 'PASS',
        candidateResults: [
          { index: 0, status: 'PASS', checks: [] },
          { index: 1, status: 'PASS', checks: [] }
        ]
      };
    }
    return invoker()(name);
  };
  const result = await runSecurityAssessment(input, { invokeTool: invoke });
  assert.equal(result.derivedChecks[0].status, 'VERIFIED');
  const correlation = result.report.evidence.find(item => item.source === 'payguard_agent_intent_transaction_correlation');
  assert.equal(correlation.rawOutput.selectedPaymentIndex, 1);
});

test('transferFrom recipient field is correlated correctly', async () => {
  const invoke = async (name) => {
    if (name === 'payguard_check_payment_intent') {
      return { status: 'PASS', candidateResults: [{ index: 0, status: 'PASS', checks: [] }] };
    }
    if (name === 'payguard_inspect_calldata') {
      return {
        verdict: 'PASS',
        operation: 'ERC20_TRANSFER_FROM',
        details: { tokenContract: ASSET, from: OTHER, to: RECIPIENT, amount: '5000000' },
        checks: [{ id: 'calldata_decode', status: 'PASS' }]
      };
    }
  };
  const result = await runSecurityAssessment(baseInput(), { invokeTool: invoke });
  assert.equal(result.derivedChecks[0].status, 'VERIFIED');
});

test('payment option REVIEW remains UNVERIFIED during correlation', async () => {
  const result = await runSecurityAssessment(baseInput(), { invokeTool: invoker({ candidateStatus: 'REVIEW' }) });
  assert.equal(result.derivedChecks[0].status, 'UNVERIFIED');
  assert.equal(result.report.overallStatus, 'UNVERIFIED');
});

test('approval is not misrepresented as a completed payment transfer', async () => {
  const result = await runSecurityAssessment(baseInput(), { invokeTool: invoker({ operation: 'ERC20_APPROVE' }) });
  assert.equal(result.derivedChecks[0].status, 'UNVERIFIED');
});

test('selected payment option that fails user policy remains RISK_DETECTED', async () => {
  const result = await runSecurityAssessment(baseInput(), { invokeTool: invoker({ candidateStatus: 'BLOCK' }) });
  assert.equal(result.derivedChecks[0].status, 'RISK_DETECTED');
  assert.equal(result.report.overallStatus, 'RISK_DETECTED');
});

test('incomplete payment context produces an explicit NOT_CHECKED correlation record', async () => {
  const input = {
    intent: { trusted: true },
    transaction: { network: 'eip155:8453', to: ASSET, data: '0x' }
  };
  const result = await runSecurityAssessment(input, { invokeTool: invoker() });
  assert.equal(result.derivedChecks[0].status, 'NOT_CHECKED');
  assert.equal(result.report.overallStatus, 'NOT_CHECKED');
});
