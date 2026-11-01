// TEMPORARY scratch-branch probe: observe the real @x402/core client's behaviour.
import { x402Client } from '@x402/core/client';
import * as clientEntry from '@x402/core/client';
import * as rootEntry from '@x402/core';

const plugin = await import('file://' + process.env.GITHUB_WORKSPACE + '/src/plugin.mjs');

const RES = 'https://api.example.com/report';
const ASSET = '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PAYTO = '0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const OTHER = '0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC';
const intent = () => ({
  expectedResourceUrl: RES, maxAmountAtomic: '2000', allowedNetworks: ['eip155:8453'],
  allowedAssets: [ASSET.toLowerCase()], allowedPayTo: [PAYTO.toLowerCase()],
  allowedSchemes: ['exact'], maxTimeoutSeconds: 300
});
const req = (o = {}) => ({ scheme: 'exact', network: 'eip155:8453', asset: ASSET, payTo: PAYTO, amount: '1500', maxTimeoutSeconds: 120, extra: {}, ...o });
const required = (accepts, resource = { url: RES }) => {
  const pr = { x402Version: 2, accepts };
  if (resource !== undefined) pr.resource = resource;
  return pr;
};

function mockScheme() {
  const calls = [];
  return {
    calls,
    scheme: {
      scheme: 'exact',
      async createPaymentPayload(version, requirements, context) {
        calls.push({ version, payTo: requirements.payTo, amount: requirements.amount, ctx: context ? Object.keys(context) : null });
        return { x402Version: version, payload: { signed: 'MOCK_PAYLOAD' } };
      }
    }
  };
}

async function run(name, build, pr) {
  const { calls, scheme } = mockScheme();
  const events = [];
  let result;
  try {
    const client = build(scheme, events);
    const payload = await client.createPaymentPayload(pr);
    result = { outcome: 'resolved', payloadKeys: Object.keys(payload), accepted: payload.accepted ? { payTo: payload.accepted.payTo, amount: payload.accepted.amount } : null };
  } catch (error) {
    result = { outcome: 'rejected', errorName: error?.constructor?.name, errorMessage: String(error?.message).slice(0, 300) };
  }
  console.log('CASE ' + name + ' => ' + JSON.stringify({ ...result, schemeCalls: calls.length, calls, events }));
}

console.log('EXPORTS root:', Object.keys(rootEntry).sort().join(', '));
console.log('EXPORTS client:', Object.keys(clientEntry).sort().join(', '));
console.log('DEFAULT_MAX_AMOUNT_PER_PAYMENT:', JSON.stringify(clientEntry.DEFAULT_MAX_AMOUNT_PER_PAYMENT ?? rootEntry.DEFAULT_MAX_AMOUNT_PER_PAYMENT));

const plain = (scheme) => new x402Client().register('eip155:*', scheme);
const open = (scheme) => plain(scheme).setSpendControls(false);

// --- How the bare SDK behaves (no PayGuard) ---
await run('sdk-default-spendcontrols-fake-asset', (s) => plain(s), required([req()]));
await run('sdk-spendcontrols-off-no-hooks', (s) => open(s), required([req()]));
await run('sdk-hook-returns-undefined', (s, ev) => open(s).onBeforePaymentCreation(async (ctx) => { ev.push({ ctxKeys: Object.keys(ctx), prKeys: Object.keys(ctx.paymentRequired), sameRef: ctx.selectedRequirements === ctx.paymentRequired.accepts[0] }); }), required([req()]));
await run('sdk-hook-aborts', (s) => open(s).onBeforePaymentCreation(async () => ({ abort: true, reason: 'TEST ABORT REASON' })), required([req()]));
await run('sdk-hook-throws', (s) => open(s).onBeforePaymentCreation(async () => { throw new Error('HOOK BOOM'); }), required([req()]));
await run('sdk-hook-sync-non-promise-abort', (s) => open(s).onBeforePaymentCreation(() => ({ abort: true, reason: 'SYNC ABORT' })), required([req()]));
await run('sdk-failure-hook-after-abort-can-recover?', (s, ev) => open(s)
  .onBeforePaymentCreation(async () => ({ abort: true, reason: 'ABORT' }))
  .onPaymentCreationFailure(async (ctx) => { ev.push({ failureHookRan: true, err: String(ctx.error?.message).slice(0, 80) }); return { recovered: true, payload: { x402Version: 2, payload: { forged: true }, accepted: ctx.selectedRequirements } }; }), required([req()]));
await run('sdk-hook-mutates-selected-amount', (s, ev) => open(s).onBeforePaymentCreation(async (ctx) => { ctx.selectedRequirements.amount = '1'; ev.push({ mutated: true }); }), required([req({ amount: '9999' })]));
await run('sdk-multi-default-selector', (s, ev) => open(s).onBeforePaymentCreation(async (ctx) => { ev.push({ selectedPayTo: ctx.selectedRequirements.payTo, offered: ctx.paymentRequired.accepts.map((a) => a.payTo) }); }), required([req({ payTo: OTHER }), req()]));
await run('sdk-multi-custom-selector-index1', (s, ev) => new x402Client((version, reqs) => reqs[1]).register('eip155:*', s).setSpendControls(false).onBeforePaymentCreation(async (ctx) => { ev.push({ selectedPayTo: ctx.selectedRequirements.payTo }); }), required([req(), req({ payTo: OTHER })]));
await run('sdk-no-resource', (s) => open(s), required([req()], undefined));
await run('sdk-empty-accepts', (s) => open(s), required([]));
await run('sdk-no-accepts-field', (s) => open(s), { x402Version: 2, resource: { url: RES } });

// --- The real PayGuard adapter on the real client ---
const guarded = (policy, opts = {}) => (s, ev) => plugin.registerPayGuardX402(open(s), { intent: policy, onDecision: (r) => ev.push({ decision: r.status }), ...opts });
await run('pg-safe', guarded(intent()), required([req()]));
await run('pg-over-max-amount', guarded(intent()), required([req({ amount: '2001' })]));
const incomplete = intent(); delete incomplete.allowedPayTo;
await run('pg-incomplete-policy', guarded(incomplete), required([req()]));
await run('pg-wrong-recipient', guarded(intent()), required([req({ payTo: OTHER })]));
await run('pg-wrong-asset', guarded(intent()), required([req({ asset: '0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' })]));
await run('pg-wrong-network', guarded(intent()), required([req({ network: 'eip155:1' })]));
await run('pg-missing-resource', guarded(intent()), required([req()], undefined));
await run('pg-resource-wrong-url', guarded(intent()), required([req()], { url: 'https://evil.example.com/report' }));
await run('pg-resource-http', guarded(intent()), required([req()], { url: 'http://api.example.com/report' }));
await run('pg-resource-not-an-object', guarded(intent()), required([req()], 'https://api.example.com/report'));
await run('pg-multi-default-selector-first-unsafe', guarded(intent()), required([req({ payTo: OTHER }), req()]));
await run('pg-multi-default-selector-first-safe', guarded(intent()), required([req(), req({ payTo: OTHER })]));
await run('pg-multi-custom-selector-picks-unsafe', (s, ev) => plugin.registerPayGuardX402(new x402Client((v, r) => r[1]).register('eip155:*', s).setSpendControls(false), { intent: intent(), onDecision: (r) => ev.push({ decision: r.status }) }), required([req(), req({ payTo: OTHER })]));
await run('pg-multi-custom-selector-picks-safe', (s, ev) => plugin.registerPayGuardX402(new x402Client((v, r) => r[1]).register('eip155:*', s).setSpendControls(false), { intent: intent(), onDecision: (r) => ev.push({ decision: r.status }) }), required([req({ payTo: OTHER }), req()]));
await run('pg-audit-callback-throws', guarded(intent(), { onDecision() { throw new Error('audit unavailable'); } }), required([req()]));
await run('pg-failure-hook-registered-after-pg-tries-recover', (s, ev) => guarded(intent())(s, ev).onPaymentCreationFailure(async (ctx) => { ev.push({ failureHookRan: true }); return { recovered: true, payload: { x402Version: 2, payload: { forged: true }, accepted: ctx.selectedRequirements } }; }), required([req({ amount: '2001' })]));
await run('pg-default-spendcontrols-client-fake-asset', (s, ev) => plugin.registerPayGuardX402(plain(s), { intent: intent() }), required([req()]));
