import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrlSecurity, evaluatePaymentIntent, prepareThreatReport, plugin } from '../src/plugin.mjs';

const resource = 'https://api.example.com/report';
const policy = {
  expectedResourceUrl: resource,
  maxAmountAtomic: '2000',
  allowedNetworks: ['eip155:8453'],
  allowedAssets: ['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
  allowedPayTo: ['0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'],
  allowedSchemes: ['exact'],
  maxTimeoutSeconds: 300
};
const safeCandidate = {
  scheme: 'exact',
  network: 'eip155:8453',
  asset: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  payTo: '0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
  amount: '1500',
  maxTimeoutSeconds: 120
};
const goodInput = () => ({
  intent: structuredClone(policy),
  paymentRequirements: { resource, accepts: [structuredClone(safeCandidate)] }
});

test('safe request matching full user policy returns PASS and never executes payment', () => {
  const out = evaluatePaymentIntent(goodInput());
  assert.equal(out.status, 'PASS');
  assert.equal(out.paymentExecuted, false);
});
test('amount above the user maximum returns BLOCK', () => {
  const input = goodInput(); input.paymentRequirements.accepts[0].amount = '2001';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
});
test('unapproved recipient returns BLOCK', () => {
  const input = goodInput(); input.paymentRequirements.accepts[0].payTo = '0xcccccccccccccccccccccccccccccccccccccccc';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
});
test('unapproved network returns BLOCK', () => {
  const input = goodInput(); input.paymentRequirements.accepts[0].network = 'eip155:1';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
});
test('incomplete trusted policy returns REVIEW rather than PASS', () => {
  const input = goodInput(); delete input.intent.allowedPayTo;
  assert.equal(evaluatePaymentIntent(input).status, 'REVIEW');
});
test('conflicting current and legacy amount fields fail closed', () => {
  const input = goodInput(); input.paymentRequirements.accepts[0].maxAmountRequired = '1499';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
});
test('wrong resource returns BLOCK', () => {
  const input = goodInput(); input.paymentRequirements.resource = 'https://attacker.example/report';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
});
test('multiple safe options pass, mixed safe and unsafe options return REVIEW', () => {
  const allSafe = goodInput(); allSafe.paymentRequirements.accepts.push(structuredClone(safeCandidate));
  assert.equal(evaluatePaymentIntent(allSafe).status, 'PASS');
  const mixed = goodInput(); mixed.paymentRequirements.accepts.push({ ...structuredClone(safeCandidate), payTo: '0xcccccccccccccccccccccccccccccccccccccccc' });
  assert.equal(evaluatePaymentIntent(mixed).status, 'REVIEW');
});
test('credentialed and fragment URLs are rejected', () => {
  const input = goodInput(); input.paymentRequirements.resource = 'https://alice:secret@api.example.com/report';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
  const second = goodInput(); second.paymentRequirements.resource = 'https://api.example.com/report#fragment';
  assert.equal(evaluatePaymentIntent(second).status, 'BLOCK');
});
test('malformed options and oversized input fail closed', () => {
  assert.equal(evaluatePaymentIntent({ intent: policy, paymentRequirements: { resource, accepts: [] } }).status, 'BLOCK');
  assert.equal(evaluatePaymentIntent('not an object').status, 'BLOCK');
  assert.equal(evaluatePaymentIntent({ x: 'x'.repeat(70000) }).status, 'BLOCK');
});
test('malformed amount and recipient return BLOCK', () => {
  const badAmount = goodInput(); badAmount.paymentRequirements.accepts[0].amount = '1.5';
  assert.equal(evaluatePaymentIntent(badAmount).status, 'BLOCK');
  const badRecipient = goodInput(); badRecipient.paymentRequirements.accepts[0].payTo = { address: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' };
  assert.equal(evaluatePaymentIntent(badRecipient).status, 'BLOCK');
});
test('plugin descriptor dispatches only the declared tool', () => {
  assert.equal(plugin.tools.length, 8);
  assert.equal(plugin.invokeTool('payguard_check_payment_intent', goodInput()).status, 'PASS');
  assert.throws(() => plugin.invokeTool('pay', {}), /Unknown tool/);
});


test('URL Sentinel detects PayBox impersonation and never opens the URL', async () => {
  const result = await analyzeUrlSecurity({ url: 'https://secure-paybox-login.attacker.example/verify-wallet' });
  assert.equal(result.verdict, 'SUSPICIOUS');
  assert.equal(result.privacy.urlOpened, false);
  assert.equal(result.paymentExecuted, false);
  assert.ok(result.checks.some(c => c.id === 'possible_paybox_impersonation'));
  assert.ok(result.checks.some(c => c.id === 'wallet_secret_language'));
});
test('URL Sentinel flags a one-character lookalike against an independent trusted domain', async () => {
  const result = await analyzeUrlSecurity({ url: 'https://paypa1.com/login', expectedDomain: 'paypal.com' });
  assert.equal(result.verdict, 'SUSPICIOUS');
  assert.ok(result.checks.some(c => c.id === 'trusted_domain_mismatch'));
  assert.ok(result.checks.some(c => c.id === 'possible_lookalike_domain'));
});
test('URL Sentinel recognizes an independently supplied trusted-domain match without calling it guaranteed safe', async () => {
  const result = await analyzeUrlSecurity({ url: 'https://app.paybox.sh/', expectedDomain: 'paybox.sh' });
  assert.equal(result.verdict, 'EXPECTED_DOMAIN_MATCH');
  assert.ok(result.summary.includes('not a guarantee'));
});
test('URL Sentinel highlights embedded credentials, HTTP and URL shorteners', async () => {
  const credentialUrl = await analyzeUrlSecurity({ url: 'http://user:secret@bit.ly/path' });
  assert.equal(credentialUrl.verdict, 'SUSPICIOUS');
  assert.ok(credentialUrl.checks.some(c => c.id === 'embedded_credentials'));
  assert.ok(credentialUrl.checks.some(c => c.id === 'unencrypted_http'));
  assert.ok(credentialUrl.checks.some(c => c.id === 'shortened_url'));
  assert.ok(!credentialUrl.displayedUrl.includes('secret'));
});
test('URL Sentinel returns UNVERIFIED for an ordinary URL when there is no reputation provider or trusted domain', async () => {
  const result = await analyzeUrlSecurity({ url: 'https://example.org/' });
  assert.equal(result.verdict, 'UNVERIFIED');
});
test('URL Sentinel optionally queries Web Risk without sending query parameters or putting API key in URL', async () => {
  let calledUrl = '';
  let calledOptions = null;
  const result = await analyzeUrlSecurity(
    { url: 'https://example.org/path?access_token=DO_NOT_SEND&campaign=test', checkReputation: true },
    {
      webRiskApiKey: 'test-api-key',
      fetchImpl: async (url, options) => {
        calledUrl = url;
        calledOptions = options;
        return { ok: true, json: async () => ({ threat: { threatTypes: ['SOCIAL_ENGINEERING'] } }) };
      }
    }
  );
  assert.equal(result.verdict, 'KNOWN_MALICIOUS');
  assert.ok(!calledUrl.includes('DO_NOT_SEND'));
  assert.ok(!calledUrl.includes('campaign=test'));
  assert.ok(!calledUrl.includes('test-api-key'));
  assert.equal(calledOptions.headers['X-Goog-Api-Key'], 'test-api-key');
});
test('URL Sentinel handles an unavailable or unconfigured reputation provider without claiming clean', async () => {
  const result = await analyzeUrlSecurity({ url: 'https://example.org', checkReputation: true }, { webRiskApiKey: '' });
  assert.ok(['NOT_CONFIGURED', 'UNAVAILABLE'].includes(result.reputation.status));
  assert.notEqual(result.verdict, 'NO_KNOWN_THREAT');
});
test('URL Sentinel rejects unsupported and malformed URLs without network access', async () => {
  const invalid = await analyzeUrlSecurity({ url: 'javascript:alert(1)' });
  assert.equal(invalid.verdict, 'SUSPICIOUS');
  const malformed = await analyzeUrlSecurity({ url: 'http://[' });
  assert.equal(malformed.verdict, 'SUSPICIOUS');
});
test('Threat report redacts sensitive query values and is explicitly not submitted', async () => {
  const report = await prepareThreatReport({ url: 'https://bad.example/path?access_token=TOPSECRET&redirect=https%3A%2F%2Fevil.example', userNotes: 'Possible wallet recovery page' });
  assert.equal(report.reportStatus, 'DRAFT_NOT_SUBMITTED');
  assert.equal(report.submission.automaticNotificationSent, false);
  assert.ok(!report.subject.url.includes('TOPSECRET'));
  assert.ok(report.subject.url.includes('%5BREDACTED%5D') || report.subject.url.includes('%5BVALUE%20REDACTED%5D'));
});
test('plugin exposes the URL Sentinel and report tools', async () => {
  assert.equal(plugin.tools.length, 7);
  const result = await plugin.invokeTool('payguard_analyze_url', { url: 'https://paybox-login.attacker.example' });
  assert.equal(result.verdict, 'SUSPICIOUS');
  const report = await plugin.invokeTool('payguard_prepare_threat_report', { url: 'https://bad.example' });
  assert.equal(report.submission.automaticNotificationSent, false);
});


test('URL Sentinel accepts hostnames with an explicit port without treating the domain as a scheme', async () => {
  const result = await analyzeUrlSecurity({ url: 'example.org:8443/path' });
  assert.equal(result.hostname, 'example.org');
  assert.ok(result.checks.some(c => c.id === 'nonstandard_port'));
});
test('Threat report never copies free-form notes that might contain wallet secrets', async () => {
  const report = await prepareThreatReport({ url: 'https://bad.example', userNotes: 'seed phrase: alpha beta gamma delta epsilon zeta' });
  assert.equal(Object.hasOwn(report, 'userNotes'), false);
  assert.equal(report.submission.automaticNotificationSent, false);
});

// Adversarial tests for URL Sentinel and Payment Guard
test('Adversarial: trusted-domain suffix attack is rejected (not matched as trusted)', async () => {
  // attacker owns evilpaybox.sh or paybox.sh.attacker.com, not paybox.sh
  const suffixAttack1 = await analyzeUrlSecurity({
    url: 'https://evilpaybox.sh/login',
    expectedDomain: 'paybox.sh'
  });
  assert.equal(suffixAttack1.verdict, 'SUSPICIOUS');
  assert.ok(suffixAttack1.checks.some(c => c.id === 'trusted_domain_mismatch'));
  assert.ok(!suffixAttack1.checks.some(c => c.id === 'trusted_domain_match'));

  const suffixAttack2 = await analyzeUrlSecurity({
    url: 'https://paybox.sh.attacker.example/login',
    expectedDomain: 'paybox.sh'
  });
  assert.equal(suffixAttack2.verdict, 'SUSPICIOUS');
  assert.ok(suffixAttack2.checks.some(c => c.id === 'trusted_domain_mismatch'));
  assert.ok(!suffixAttack2.checks.some(c => c.id === 'trusted_domain_match'));
});

test('Adversarial: Unicode homoglyph and IDN punycode are flagged', async () => {
  // Punycode domain representing Cyrillic 'a' (xn--pypal-4ve.com)
  const punycodeResult = await analyzeUrlSecurity({
    url: 'https://xn--pypal-4ve.com/signin',
    expectedDomain: 'paypal.com'
  });
  assert.ok(punycodeResult.checks.some(c => c.id === 'idn_punycode'));
  assert.equal(punycodeResult.verdict, 'SUSPICIOUS');

  // Direct unicode hostname
  const unicodeResult = await analyzeUrlSecurity({
    url: 'https://рaybox.sh/login' // Cyrillic 'р'
  });
  assert.ok(unicodeResult.checks.some(c => c.id === 'unicode_hostname' || c.id === 'idn_punycode'));
  assert.ok(['CAUTION', 'SUSPICIOUS'].includes(unicodeResult.verdict));
});

test("Official Base domain verification correctly identifies official base.org and flags lookalikes", async () => {
  const official = await analyzeUrlSecurity({ url: "https://base.org" });
  assert.equal(official.verdict, "EXPECTED_DOMAIN_MATCH");
  assert.equal(official.statusCategory, "VERIFIED OFFICIAL");
  assert.equal(official.isOfficialBaseProject, true);
  assert.ok(official.checks.some(c => c.id === "verified_official_base_domain"));

  const lookalike = await analyzeUrlSecurity({ url: "https://bases.org" });
  assert.equal(lookalike.verdict, "SUSPICIOUS");
  assert.equal(lookalike.statusCategory, "HIGH RISK");
  assert.equal(lookalike.isBaseImpersonation, true);
  assert.ok(lookalike.checks.some(c => c.id === "base_ecosystem_impersonation"));
});
test('Adversarial: sensitive path segments (reset tokens, invite codes) are redacted in reputation query and display', async () => {
  let calledUrl = '';
  const result = await analyzeUrlSecurity(
    {
      url: 'https://service.example/reset-password/secret-token-abc123xyz987longtokenvalue/invite-code-999',
      checkReputation: true
    },
    {
      webRiskApiKey: 'test-api-key',
      fetchImpl: async (url) => {
        calledUrl = url;
        return { ok: true, json: async () => ({}) };
      }
    }
  );
  // In the Web Risk query URL, the sensitive token path segments must be redacted
  assert.ok(!calledUrl.includes('secret-token-abc123xyz987longtokenvalue'), 'Token was exposed in Web Risk lookup!');
  assert.ok(!calledUrl.includes('invite-code-999'), 'Invite code was exposed in Web Risk lookup!');
  assert.ok(calledUrl.includes('%5BREDACTED%5D') || calledUrl.includes('[REDACTED]'));
  assert.equal(result.privacy.pathSegmentsRedactedForReputationProvider, true);
  // Also redacted in displayedUrl
  assert.ok(!result.displayedUrl.includes('secret-token-abc123xyz987longtokenvalue'));
});

test('Adversarial: reputation service network error fails safe without claiming safe', async () => {
  const result = await analyzeUrlSecurity(
    { url: 'https://unknown-service.example', checkReputation: true },
    {
      webRiskApiKey: 'test-api-key',
      fetchImpl: async () => {
        throw new Error('Connection refused / DNS lookup failed');
      }
    }
  );
  assert.equal(result.reputation.status, 'UNAVAILABLE');
  assert.notEqual(result.verdict, 'NO_KNOWN_THREAT');
  assert.ok(result.checks.some(c => c.id === 'threat_intelligence_unavailable'));
});

test('Adversarial: payment amount exceeding policy or negative/floating-point values fail closed', async () => {
  // Negative amount
  const negInput = goodInput();
  negInput.paymentRequirements.accepts[0].amount = '-500';
  assert.equal(evaluatePaymentIntent(negInput).status, 'BLOCK');

  // Floating point amount
  const floatInput = goodInput();
  floatInput.paymentRequirements.accepts[0].amount = '100.50';
  assert.equal(evaluatePaymentIntent(floatInput).status, 'BLOCK');

  // Exceeds max amount atomic
  const overInput = goodInput();
  overInput.paymentRequirements.accepts[0].amount = '200000000000000000000000000000';
  assert.equal(evaluatePaymentIntent(overInput).status, 'BLOCK');

  // Exponential notation amount (e.g., '1e6')
  const expInput = goodInput();
  expInput.paymentRequirements.accepts[0].amount = '1e6';
  assert.equal(evaluatePaymentIntent(expInput).status, 'BLOCK');
});

test('Adversarial: unapproved network or recipient substitution returns BLOCK', async () => {
  // Network mismatch (e.g. eip155:1 mainnet when only Base eip155:8453 is allowed)
  const netInput = goodInput();
  netInput.paymentRequirements.accepts[0].network = 'eip155:1';
  assert.equal(evaluatePaymentIntent(netInput).status, 'BLOCK');

  // Recipient substitution
  const recipInput = goodInput();
  recipInput.paymentRequirements.accepts[0].payTo = '0x1111111111111111111111111111111111111111';
  assert.equal(evaluatePaymentIntent(recipInput).status, 'BLOCK');
});

test('Adversarial: resource path substitution / cross-site resource returns BLOCK', async () => {
  const diffResource = goodInput();
  diffResource.paymentRequirements.resource = 'https://api.example.com/other-endpoint';
  assert.equal(evaluatePaymentIntent(diffResource).status, 'BLOCK');
  assert.ok(evaluatePaymentIntent(diffResource).checks.some(c => c.id === 'resource' && c.status === 'fail'));

  const diffProtocol = goodInput();
  diffProtocol.paymentRequirements.resource = 'http://api.example.com/report';
  assert.equal(evaluatePaymentIntent(diffProtocol).status, 'BLOCK');
});

test('Adversarial: mixed payment options with one malicious option returns REVIEW and never PASS', async () => {
  const mixedInput = goodInput();
  mixedInput.paymentRequirements.accepts = [
    structuredClone(safeCandidate), // safe option
    {
      scheme: 'exact',
      network: 'eip155:8453',
      asset: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      payTo: '0x9999999999999999999999999999999999999999', // unauthorized recipient!
      amount: '100',
      maxTimeoutSeconds: 60
    }
  ];
  const res = evaluatePaymentIntent(mixedInput);
  assert.equal(res.status, 'REVIEW');
  assert.notEqual(res.status, 'PASS');
  assert.equal(res.paymentExecuted, false);
});

test('Bundled distribution artifacts export valid PayBox plugin contract and tools', async () => {
  const pluginEsm = await import('../dist/plugin.mjs');
  const indexEsm = await import('../dist/index.js');

  assert.equal(typeof pluginEsm.createPayGuardX402Hook, 'function');
  assert.equal(typeof pluginEsm.registerPayGuardX402, 'function');
  assert.equal(typeof indexEsm.createPayGuardX402Hook, 'function');
  assert.equal(typeof indexEsm.registerPayGuardX402, 'function');

  for (const mod of [pluginEsm, indexEsm]) {
    assert.equal(mod.default.id, 'payguard');
    assert.equal(mod.default.name, 'PayGuard');
    assert.equal(mod.default.protocol, 'mcp');
    assert.equal(mod.default.tools.length, 7);
    for (const tool of mod.default.tools) {
      assert.ok(tool.name);
      assert.ok(tool.description);
      assert.ok(tool.inputSchema);
      assert.equal(typeof tool.handler, 'function');
    }
  }
});

test('MCP stdio tool discovery discovers tools without running them', async () => {
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');

  const targetPath = fileURLToPath(new URL('../dist/index.js', import.meta.url));

  const responses = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [targetPath], {
      stdio: ['pipe', 'pipe', 'inherit']
    });

    let buffer = '';
    const received = [];

    child.stdout.on('data', chunk => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (line.trim()) {
          received.push(JSON.parse(line.trim()));
          if (received.length === 2) {
            child.kill();
            resolve(received);
          }
        }
      }
    });

    child.on('error', reject);
    child.on('exit', code => {
      if (received.length < 2) {
        reject(new Error('Process exited with code ' + code + ' before responding to discovery'));
      }
    });

    // Send initialize
    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05' }
    }) + '\n');

    // Send tools/list
    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: {}
    }) + '\n');
  });

  const initMsg = responses.find(r => r.id === 1);
  const toolsMsg = responses.find(r => r.id === 2);

  assert.equal(initMsg?.result?.serverInfo?.name, 'PayGuard');
  assert.equal(toolsMsg?.result?.tools?.length, 7);
  const names = toolsMsg.result.tools.map(t => t.name);
  assert.ok(names.includes('payguard_check_payment_intent'));
  assert.ok(names.includes('payguard_analyze_url'));
  assert.ok(names.includes('payguard_prepare_threat_report'));
  assert.ok(names.includes('payguard_check_token_security'));
  assert.ok(names.includes('payguard_check_address_security'));
});



import { createPayGuardX402Hook, registerPayGuardX402 } from '../src/plugin.mjs';

const x402Context = (requirements = structuredClone(safeCandidate), url = resource) => ({
  paymentRequired: {
    x402Version: 2,
    resource: { url },
    accepts: [structuredClone(requirements)]
  },
  selectedRequirements: structuredClone(requirements)
});

test('x402 pre-signing hook allows only a selected requirement that fully passes policy', async () => {
  let decision;
  const hook = createPayGuardX402Hook({
    intent: structuredClone(policy),
    onDecision: result => { decision = result; }
  });
  assert.equal(await hook(x402Context()), undefined);
  assert.equal(decision.status, 'PASS');
  assert.equal(decision.paymentExecuted, false);
});

test('x402 pre-signing hook aborts before payload creation when selected amount exceeds policy', async () => {
  const hook = createPayGuardX402Hook({ intent: structuredClone(policy) });
  const result = await hook(x402Context({ ...safeCandidate, amount: '2001' }));
  assert.equal(result.abort, true);
  assert.match(result.reason, /^PayGuard BLOCK:/);
});

test('x402 pre-signing hook treats incomplete policy as abort, never as consent', async () => {
  const incomplete = structuredClone(policy);
  delete incomplete.allowedPayTo;
  const hook = createPayGuardX402Hook({ intent: incomplete });
  const result = await hook(x402Context());
  assert.equal(result.abort, true);
  assert.match(result.reason, /^PayGuard REVIEW:/);
});

test('x402 pre-signing hook aborts malformed or missing SDK context', async () => {
  const hook = createPayGuardX402Hook({ intent: structuredClone(policy) });
  const result = await hook({});
  assert.equal(result.abort, true);
  assert.match(result.reason, /^PayGuard BLOCK:/);
});

test('registerPayGuardX402 attaches the hook to an x402 client and returns the client', async () => {
  let registered;
  const fakeClient = {
    onBeforePaymentCreation(hook) { registered = hook; return this; }
  };
  assert.equal(registerPayGuardX402(fakeClient, { intent: structuredClone(policy) }), fakeClient);
  assert.equal(typeof registered, 'function');
  assert.equal(await registered(x402Context()), undefined);
  assert.throws(() => registerPayGuardX402({}, { intent: structuredClone(policy) }), /onBeforePaymentCreation/);
});


test('x402 audit callback cannot mutate the SDK requirement or change the policy verdict', async () => {
  const hook = createPayGuardX402Hook({
    intent: structuredClone(policy),
    onDecision(result, snapshot) {
      result.status = 'PASS';
      snapshot.selectedRequirements.amount = '1';
    }
  });
  const result = await hook(x402Context({ ...safeCandidate, amount: '2001' }));
  assert.equal(result.abort, true);
  assert.match(result.reason, /^PayGuard BLOCK:/);
});

test('x402 hook snapshots policy so later external mutations cannot loosen it', async () => {
  const mutablePolicy = structuredClone(policy);
  const hook = createPayGuardX402Hook({ intent: mutablePolicy });
  mutablePolicy.maxAmountAtomic = '999999';
  const result = await hook(x402Context({ ...safeCandidate, amount: '2001' }));
  assert.equal(result.abort, true);
  assert.match(result.reason, /^PayGuard BLOCK:/);
});

test('x402 audit callback errors fail closed', async () => {
  const hook = createPayGuardX402Hook({
    intent: structuredClone(policy),
    onDecision() { throw new Error('audit unavailable'); }
  });
  await assert.rejects(hook(x402Context()), /audit unavailable/);
});
import { x402Client } from '@x402/core/client';

test('x402 SDK real integration: 1. Valid payment and valid policy: PASS; scheme executes once', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, { intent: structuredClone(policy) });

  const payload = await client.createPaymentPayload({
    x402Version: 2,
    resource: { url: resource },
    accepts: [structuredClone(safeCandidate)]
  });
  assert.equal(schemeCalls, 1);
  assert.equal(payload.accepted.payTo, safeCandidate.payTo);
});

test('x402 SDK real integration: 2. Amount exceeds policy: BLOCK; scheme executes zero times', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, { intent: structuredClone(policy) });

  await assert.rejects(
    client.createPaymentPayload({
      x402Version: 2,
      resource: { url: resource },
      accepts: [{ ...structuredClone(safeCandidate), amount: '2001' }]
    }),
    /Payment creation aborted: PayGuard BLOCK:/
  );
  assert.equal(schemeCalls, 0);
});

test('x402 SDK real integration: 3. Wrong recipient: BLOCK; scheme executes zero times', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, { intent: structuredClone(policy) });

  await assert.rejects(
    client.createPaymentPayload({
      x402Version: 2,
      resource: { url: resource },
      accepts: [{ ...structuredClone(safeCandidate), payTo: '0xcccccccccccccccccccccccccccccccccccccccc' }]
    }),
    /Payment creation aborted: PayGuard BLOCK:/
  );
  assert.equal(schemeCalls, 0);
});

test('x402 SDK real integration: 4. Wrong asset: BLOCK; scheme executes zero times', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, { intent: structuredClone(policy) });

  await assert.rejects(
    client.createPaymentPayload({
      x402Version: 2,
      resource: { url: resource },
      accepts: [{ ...structuredClone(safeCandidate), asset: '0xcccccccccccccccccccccccccccccccccccccccc' }]
    }),
    /Payment creation aborted: PayGuard BLOCK:/
  );
  assert.equal(schemeCalls, 0);
});

test('x402 SDK real integration: 5. Wrong network: BLOCK; scheme executes zero times', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, { intent: structuredClone(policy) });

  await assert.rejects(
    client.createPaymentPayload({
      x402Version: 2,
      resource: { url: resource },
      accepts: [{ ...structuredClone(safeCandidate), network: 'eip155:1' }]
    }),
    /Payment creation aborted: PayGuard BLOCK:/
  );
  assert.equal(schemeCalls, 0);
});

test('x402 SDK real integration: 6. Incomplete policy: REVIEW; scheme executes zero times', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  const incompletePolicy = structuredClone(policy);
  delete incompletePolicy.allowedPayTo;
  registerPayGuardX402(client, { intent: incompletePolicy });

  await assert.rejects(
    client.createPaymentPayload({
      x402Version: 2,
      resource: { url: resource },
      accepts: [structuredClone(safeCandidate)]
    }),
    /Payment creation aborted: PayGuard REVIEW:/
  );
  assert.equal(schemeCalls, 0);
});

test('x402 SDK real integration: 7. Missing resource: BLOCK or REVIEW; scheme executes zero times', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, { intent: structuredClone(policy) });

  await assert.rejects(
    client.createPaymentPayload({
      x402Version: 2,
      accepts: [structuredClone(safeCandidate)]
    }),
    /Payment creation aborted: PayGuard (BLOCK|REVIEW):/
  );
  assert.equal(schemeCalls, 0);
});

test('x402 SDK real integration: 8. Missing resource URL: BLOCK or REVIEW; scheme executes zero times', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, { intent: structuredClone(policy) });

  await assert.rejects(
    client.createPaymentPayload({
      x402Version: 2,
      resource: {},
      accepts: [structuredClone(safeCandidate)]
    }),
    /Payment creation aborted: PayGuard (BLOCK|REVIEW):/
  );
  assert.equal(schemeCalls, 0);
});

test('x402 SDK real integration: 9. Malformed resource URL: BLOCK or REVIEW; scheme executes zero times', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, { intent: structuredClone(policy) });

  await assert.rejects(
    client.createPaymentPayload({
      x402Version: 2,
      resource: { url: 'not-a-valid-url' },
      accepts: [structuredClone(safeCandidate)]
    }),
    /Payment creation aborted: PayGuard (BLOCK|REVIEW):/
  );
  assert.equal(schemeCalls, 0);
});

test('x402 SDK real integration: 10. HTTP resource URL: reject according to the existing HTTPS policy', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, { intent: structuredClone(policy) });

  await assert.rejects(
    client.createPaymentPayload({
      x402Version: 2,
      resource: { url: 'http://api.example.com/report' },
      accepts: [structuredClone(safeCandidate)]
    }),
    /Payment creation aborted: PayGuard BLOCK:/
  );
  assert.equal(schemeCalls, 0);
});

test('x402 SDK real integration: 11. Audit callback failure: fail closed; scheme executes zero times', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, {
    intent: structuredClone(policy),
    onDecision() {
      throw new Error('audit sink failed');
    }
  });

  await assert.rejects(
    client.createPaymentPayload({
      x402Version: 2,
      resource: { url: resource },
      accepts: [structuredClone(safeCandidate)]
    }),
    /audit sink failed/
  );
  assert.equal(schemeCalls, 0);
});

test('x402 SDK real integration: PayGuard does not mutate original payment requirements or selected requirements', async () => {
  let schemeCalls = 0;
  const scheme = {
    scheme: 'exact',
    async createPaymentPayload(version, requirements) {
      schemeCalls++;
      return { x402Version: version, payload: { signed: 'TEST_SIG' } };
    }
  };
  const client = new x402Client().register('eip155:*', scheme).setSpendControls(false);
  registerPayGuardX402(client, {
    intent: structuredClone(policy),
    onDecision(decision, snapshot) {
      snapshot.selectedRequirements.amount = '999';
      snapshot.resourceUrl = 'https://tampered.example';
    }
  });

  const originalCandidate = { ...structuredClone(safeCandidate), extra: { metadataKey: 'test-value' } };
  const paymentRequired = {
    x402Version: 2,
    resource: { url: resource },
    accepts: [originalCandidate]
  };

  const prSnapshot = JSON.stringify(paymentRequired);
  const candidateSnapshot = JSON.stringify(originalCandidate);

  await client.createPaymentPayload(paymentRequired);

  assert.equal(schemeCalls, 1);
  assert.equal(JSON.stringify(paymentRequired), prSnapshot, 'paymentRequired must not be mutated');
  assert.equal(JSON.stringify(originalCandidate), candidateSnapshot, 'originalCandidate must not be mutated');
});


test('plugin exposes payguard_inspect_calldata and dispatches correctly', async () => {
  const tool = plugin.tools.find(t => t.name === 'payguard_inspect_calldata');
  assert.ok(tool, 'payguard_inspect_calldata tool must be registered');
  assert.equal(typeof tool.handler, 'function');

  // Test valid transfer through invokeTool
  const TOKEN = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
  const RECIPIENT = '0x2222222222222222222222222222222222222222';
  const transferData = '0xa9059cbb' + RECIPIENT.replace('0x', '').padStart(64, '0') + BigInt(5000000).toString(16).padStart(64, '0');

  const res = await plugin.invokeTool('payguard_inspect_calldata', {
    to: TOKEN,
    data: transferData
  });

  assert.equal(res.verdict, 'PASS');
  assert.equal(res.operation, 'ERC20_TRANSFER');
  assert.equal(res.details.recipient, RECIPIENT.toLowerCase());

  // Test unlimited approval returns REVIEW
  const SPENDER = '0x111111125421ca6dc452d289314280a0f8842a65';
  const approveData = '0x095ea7b3' + SPENDER.replace('0x', '').padStart(64, '0') + 'f'.repeat(64);
  const approveRes = await plugin.invokeTool('payguard_inspect_calldata', {
    to: TOKEN,
    data: approveData
  });

  assert.equal(approveRes.verdict, 'REVIEW');
  assert.equal(approveRes.operation, 'ERC20_APPROVE');
  assert.ok(approveRes.reasons.includes('UNLIMITED_ALLOWANCE_UINT256_MAX'));

  // Test malformed input fails closed with BLOCK
  const badRes = await plugin.invokeTool('payguard_inspect_calldata', null);
  assert.equal(badRes.verdict, 'BLOCK');
  assert.equal(badRes.operation, 'MALFORMED_INPUT');
});

test('URL Sentinel detects Unicode bidirectional (Bidi) controls in raw URL (U+202E RLO)', async () => {
  // Test RLO character in path segment spoofing an extension
  const maliciousUrl = 'https://paybox.sh/download/\u202Ecod.exe';
  const report = await analyzeUrlSecurity({ url: maliciousUrl });

  assert.equal(report.verdict, 'SUSPICIOUS');
  assert.equal(report.riskLevel, 'HIGH');
  const bidiCheck = report.checks.find(c => c.id === 'unicode_bidi_override');
  assert.ok(bidiCheck, 'Should have unicode_bidi_override check');
  assert.equal(bidiCheck.severity, 'high');
  assert.equal(bidiCheck.status, 'fail');
  assert.ok(bidiCheck.detail.includes('U+202E'), 'Should detail the detected codepoint U+202E');
});

test('URL Sentinel detects Bidi controls in raw URL before URL parsing error', async () => {
  // Bidi character directly in authority/host
  const bidiHostUrl = 'https://paybox.sh\u202Etxt.exe/checkout';
  const report = await analyzeUrlSecurity({ url: bidiHostUrl });

  assert.equal(report.verdict, 'SUSPICIOUS');
  assert.equal(report.riskLevel, 'HIGH');
  const bidiCheck = report.checks.find(c => c.id === 'unicode_bidi_override');
  assert.ok(bidiCheck, 'Should capture unicode_bidi_override even if WHATWG parser rejects it');
  assert.equal(bidiCheck.severity, 'high');
  assert.equal(bidiCheck.status, 'fail');
  assert.ok(bidiCheck.detail.includes('U+202E'));
});

test('URL Sentinel detects various Bidi control characters (U+061C, U+200E, U+200F, U+2066-U+2069)', async () => {
  // Test Arabic letter mark U+061C
  const r1 = await analyzeUrlSecurity({ url: 'https://paybox.sh/page?\u061Ctest=1' });
  const c1 = r1.checks.find(c => c.id === 'unicode_bidi_override');
  assert.ok(c1 && c1.detail.includes('U+061C'), 'Should detect U+061C');

  // Test LRM U+200E and RLM U+200F
  const r2 = await analyzeUrlSecurity({ url: 'https://paybox.sh/\u200Esafe/\u200Flink' });
  const c2 = r2.checks.find(c => c.id === 'unicode_bidi_override');
  assert.ok(c2 && c2.detail.includes('U+200E') && c2.detail.includes('U+200F'), 'Should detect U+200E and U+200F');

  // Test isolate controls U+2066 (LRI), U+2067 (RLI), U+2068 (FSI), U+2069 (PDI)
  const r3 = await analyzeUrlSecurity({ url: 'https://paybox.sh/\u2066dir\u2067sub\u2068doc\u2069.pdf' });
  const c3 = r3.checks.find(c => c.id === 'unicode_bidi_override');
  assert.ok(c3 && c3.detail.includes('U+2066') && c3.detail.includes('U+2067') && c3.detail.includes('U+2068') && c3.detail.includes('U+2069'), 'Should detect isolate controls');
});

test('URL Sentinel detects Unicode compatibility / full-width confusables via NFKC normalization', async () => {
  // Full-width characters in domain name: ｐａｙｂｏｘ.sh (ｐａｙｂｏｘ.sh)
  const fullwidthUrl = 'https://\uFF50\uFF41\uFF59\uFF42\uFF4F\uFF58.sh/checkout';
  const report = await analyzeUrlSecurity({ url: fullwidthUrl });

  assert.equal(report.verdict, 'SUSPICIOUS');
  assert.equal(report.riskLevel, 'HIGH');
  const confusableCheck = report.checks.find(c => c.id === 'unicode_compatibility_confusable');
  assert.ok(confusableCheck, 'Should flag unicode_compatibility_confusable');
  assert.equal(confusableCheck.severity, 'high');
  assert.equal(confusableCheck.status, 'fail');
});

test('URL Sentinel does not falsely flag legitimate ASCII or valid Punycode IDN URLs for Bidi', async () => {
  const normalReport = await analyzeUrlSecurity({ url: 'https://paybox.sh/docs/overview' });
  assert.ok(!normalReport.checks.some(c => c.id === 'unicode_bidi_override'));
  assert.ok(!normalReport.checks.some(c => c.id === 'unicode_compatibility_confusable'));

  // Valid Punycode domain
  const punycodeReport = await analyzeUrlSecurity({ url: 'https://xn--e1afmkfd.xn--p1ai/path' });
  assert.ok(!punycodeReport.checks.some(c => c.id === 'unicode_bidi_override'));
  assert.ok(!punycodeReport.checks.some(c => c.id === 'unicode_compatibility_confusable'));
  assert.ok(punycodeReport.checks.some(c => c.id === 'idn_punycode'), 'Valid punycode still flagged with idn_punycode warning');
});

test('plugin exposes payguard_check_token_security and dispatches correctly', async () => {
  const tool = plugin.tools.find(t => t.name === 'payguard_check_token_security');
  assert.ok(tool, 'payguard_check_token_security tool must be registered');
  assert.equal(typeof tool.handler, 'function');

  // Test malformed input fails closed
  const badRes = await plugin.invokeTool('payguard_check_token_security', null);
  assert.equal(badRes.verdict, 'UNVERIFIED');
  assert.ok(badRes.reasonCodes.includes('MALFORMED_INPUT'));

  // Test unsupported chain
  const sepoliaRes = await plugin.invokeTool('payguard_check_token_security', {
    chainId: 84532,
    contractAddress: '0x036CbD53842c5426634e7929541eC2318f3dCF7e'
  });
  assert.equal(sepoliaRes.verdict, 'UNVERIFIED');
  assert.ok(sepoliaRes.reasonCodes.includes('UNSUPPORTED_CHAIN'));

  // Test invalid contract address
  const badAddrRes = await plugin.invokeTool('payguard_check_token_security', {
    chainId: 8453,
    contractAddress: 'not-an-address'
  });
  assert.equal(badAddrRes.verdict, 'UNVERIFIED');
  assert.ok(badAddrRes.reasonCodes.includes('INVALID_CONTRACT_ADDRESS'));
});

test('plugin exposes payguard_check_address_security and dispatches correctly', async () => {
  const tool = plugin.tools.find(t => t.name === 'payguard_check_address_security');
  assert.ok(tool, 'payguard_check_address_security tool must be registered');
  assert.equal(typeof tool.handler, 'function');

  // Test malformed input fails closed
  const badRes = await plugin.invokeTool('payguard_check_address_security', null);
  assert.equal(badRes.verdict, 'UNVERIFIED');
  assert.ok(badRes.reasonCodes.includes('MALFORMED_INPUT'));

  // Test unsupported chain
  const sepoliaRes = await plugin.invokeTool('payguard_check_address_security', {
    chainId: 84532,
    address: '0x1111111111111111111111111111111111111111'
  });
  assert.equal(sepoliaRes.verdict, 'UNVERIFIED');
  assert.ok(sepoliaRes.reasonCodes.includes('UNSUPPORTED_CHAIN'));

  // Test invalid address
  const badAddrRes = await plugin.invokeTool('payguard_check_address_security', {
    chainId: 8453,
    address: 'invalid-address'
  });
  assert.equal(badAddrRes.verdict, 'UNVERIFIED');
  assert.ok(badAddrRes.reasonCodes.includes('INVALID_ADDRESS'));
});

test('plugin registers the composite read-only security assessment tool', async () => {
  const tool = plugin.tools.find(item => item.name === 'payguard_run_security_assessment');
  assert.ok(tool, 'composite agent assessment tool must be registered');
  assert.equal(typeof tool.handler, 'function');
  const result = await plugin.invokeTool('payguard_run_security_assessment', {
    url: 'https://example.org'
  });
  assert.equal(result.report.overallStatus, 'UNVERIFIED');
  assert.equal(result.plan[0].toolName, 'payguard_analyze_url');
  assert.equal(result.report.evidence.length, 1);
});
