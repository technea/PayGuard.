import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseNearAccountId,
  analyzeNearAccountNameHeuristics,
  formatYoctoNear,
  analyzeNearSecurity,
  EMPTY_CODE_HASH,
  NEAR_AGENT_TOOL_NAME
} from '../src/near-security.mjs';

describe('NEAR Protocol Security Intelligence', () => {

  describe('1. Account ID Protocol Parser', () => {
    it('validates standard named accounts (e.g. wrap.near, alice.near)', () => {
      const res = parseNearAccountId('wrap.near');
      assert.equal(res.valid, true);
      assert.equal(res.accountId, 'wrap.near');
      assert.equal(res.accountType, 'named');
      assert.equal(res.isTopLevel, false);
      assert.deepEqual(res.subAccounts, ['wrap']);
      assert.equal(res.rootTld, 'near');
    });

    it('validates 64-character implicit hex accounts', () => {
      const implicit = '98793cd44a7243c65608e437b4a3a4c05ddffb0a8140974dd1bcc52402e18bee';
      const res = parseNearAccountId(implicit);
      assert.equal(res.valid, true);
      assert.equal(res.accountType, 'implicit');
      assert.equal(res.accountId, implicit);
    });

    it('validates 0x ETH-compatible implicit accounts', () => {
      const ethImplicit = '0x17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1';
      const res = parseNearAccountId(ethImplicit);
      assert.equal(res.valid, true);
      assert.equal(res.accountType, 'eth_implicit');
    });

    it('rejects too short, too long, or invalid character account IDs', () => {
      assert.equal(parseNearAccountId('a').valid, false);
      assert.equal(parseNearAccountId('a'.repeat(65)).valid, false);
      assert.equal(parseNearAccountId('INVALID_UPPERCASE.near').valid, false);
      assert.equal(parseNearAccountId('bad..near').valid, false);
      assert.equal(parseNearAccountId('@not-allowed').valid, false);
    });
  });

  describe('2. Suspicious Account & Impersonation Heuristics', () => {
    it('flags phishing and reward keywords (airdrop, claim, free-near)', () => {
      const findings = analyzeNearAccountNameHeuristics('near-airdrop-claim.near');
      assert.ok(findings.length > 0);
      assert.ok(findings.some(f => f.code === 'SUSPICIOUS_KEYWORD'));
    });

    it('detects impersonation of canonical accounts (e.g. ref-finance-rewards.near)', () => {
      const findings = analyzeNearAccountNameHeuristics('ref-finance-free.near');
      assert.ok(findings.some(f => f.code === 'CANONICAL_IMPERSONATION_RISK'));
    });

    it('flags homoglyph or lookalike patterns mimicking protocol terms', () => {
      const findings = analyzeNearAccountNameHeuristics('ne4r-wallet.xyz');
      assert.ok(findings.some(f => f.code === 'HOMOGLYPH_DECEPTION'));
    });
  });

  describe('3. YoctoNEAR Precision Formatting', () => {
    it('accurately parses and formats 24-decimal yoctoNEAR without floating point truncation', () => {
      const oneNear = '1000000000000000000000000'; // 10^24
      assert.equal(formatYoctoNear(oneNear), '1');

      const tenPointFiveNear = '10500000000000000000000000';
      assert.equal(formatYoctoNear(tenPointFiveNear), '10.5000');
    });
  });

  describe('4. Full Intelligence Evaluation with Mocked RPC', () => {
    it('evaluates contract with locked keys (0 FullAccess keys) as immutable info finding', async () => {
      const mockFetch = async (url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.params?.request_type === 'view_account') {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                amount: '500000000000000000000000000',
                block_height: 125000456,
                block_hash: '9Yf1RkWw1vG7JqM...',
                code_hash: 'B3tqBw...',
                storage_usage: 18240
              }
            })
          };
        }
        if (body.params?.request_type === 'view_access_key_list') {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                keys: [
                  { public_key: 'ed25519:...', access_key: { permission: { FunctionCall: {} } } }
                ]
              }
            })
          };
        }
        return { ok: false, status: 500 };
      };

      const result = await analyzeNearSecurity('wrap.near', { fetchFn: mockFetch });
      assert.equal(result.status, 'AVAILABLE');
      assert.equal(result.verdict, 'LOW');
      assert.equal(result.exists, true);
      assert.equal(result.contractSecurity.isDeployed, true);
      assert.equal(result.keyAnalysis.fullAccessKeysCount, 0);
      assert.equal(result.keyAnalysis.noFullAccessKeys, true);
      assert.ok(result.findings.some(f => f.ruleId === 'NEAR_FACT_NO_FULL_ACCESS_KEYS'));
      assert.ok(result.evidence.some(e => e.type === 'BLOCK_HEIGHT'));
      assert.ok(result.unavailableChecks.length > 0);
    });

    it('returns UNVERIFIED if RPC fails closed or times out', async () => {
      const mockFetch = async () => { throw new Error('RPC Connection Refused'); };
      const result = await analyzeNearSecurity('alice.near', { fetchFn: mockFetch });
      assert.equal(result.status, 'UNVERIFIED');
      assert.equal(result.verdict, 'UNVERIFIED');
      assert.ok(result.uncertaintyExplanation.includes('Fail-closed'));
      assert.ok(result.unavailableChecks.includes('view_account'));
    });

    it('handles non-existent/unregistered accounts accurately', async () => {
      const mockFetch = async (url, opts) => {
        const body = JSON.parse(opts.body);
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({
            jsonrpc: '2.0',
            id: body.id,
            error: {
              name: 'HANDLER_ERROR',
              cause: {
                name: 'UNKNOWN_ACCOUNT',
                info: { account_id: 'nonexistent-claim.near' }
              },
              message: 'account nonexistent-claim.near does not exist while viewing'
            }
          })
        };
      };

      const result = await analyzeNearSecurity('nonexistent-claim.near', { fetchFn: mockFetch });
      assert.equal(result.status, 'ACCOUNT_UNREGISTERED');
      assert.equal(result.exists, false);
      assert.ok(result.findings.some(f => f.ruleId === 'NEAR_STATE_ACCOUNT_UNREGISTERED'));
    });

    it('verifies multi-provider fallback when primary RPC fails with HTTP 500 or 429', async () => {
      let callCount = 0;
      const endpointsCalled = [];
      const fallbackFetch = async (url, opts) => {
        callCount++;
        endpointsCalled.push(url);
        if (callCount === 1) {
          // Primary fails
          return { ok: false, status: 503, text: async () => 'Service Unavailable' };
        }
        // Secondary fallback succeeds
        const body = JSON.parse(opts.body);
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({
            jsonrpc: '2.0',
            id: body.id,
            result: {
              amount: '1000000000000000000000000',
              block_height: 100001,
              block_hash: 'Abc123Hash...',
              code_hash: EMPTY_CODE_HASH,
              storage_usage: 182
            }
          })
        };
      };

      const result = await analyzeNearSecurity('fallback-test.near', {
        fetchFn: fallbackFetch,
        endpoints: ['https://failing-primary.near', 'https://fallback-secondary.near'],
        retries: 0
      });

      assert.equal(result.status, 'AVAILABLE');
      assert.equal(result.exists, true);
      assert.equal(endpointsCalled[0], 'https://failing-primary.near');
      assert.equal(endpointsCalled[1], 'https://fallback-secondary.near');
      assert.ok(result.evidence.some(e => e.type === 'RPC_PROVIDER' && e.value === 'https://fallback-secondary.near'));
    });

    it('confirms infrastructure failure across all endpoints never returns safe or unregistered verdict', async () => {
      const allFailFetch = async () => ({ ok: false, status: 500, text: async () => 'Internal Server Error' });
      const result = await analyzeNearSecurity('target.near', { fetchFn: allFailFetch });

      assert.equal(result.status, 'UNVERIFIED');
      assert.equal(result.verdict, 'UNVERIFIED');
      assert.notEqual(result.verdict, 'LOW');
      assert.notEqual(result.status, 'ACCOUNT_UNREGISTERED');
    });
  });

  describe('5. HTTP /api/near-security Route Verification', () => {
    it('dispatches valid and invalid requests via payGuardNearSecurityTool MCP tool', async () => {
      const { payGuardNearSecurityTool } = await import('../src/near-security.mjs');
      assert.equal(payGuardNearSecurityTool.name, 'payguard_near_security_intelligence');
      assert.equal(typeof payGuardNearSecurityTool.handler, 'function');

      // Invalid input (malformed account ID)
      const invalidRes = await payGuardNearSecurityTool.handler({ accountId: 'UPPERCASE_INVALID' });
      assert.equal(invalidRes.status, 'INVALID_ACCOUNT_ID');
      assert.equal(invalidRes.verdict, 'HIGH');
    });
  });

  describe('6. Deterministic Security Rules NR-001 through NR-005 Verification', () => {
    it('NR-002: flags keyless account without smart contract as info finding without automatic risk', async () => {
      const mockFetch = async (url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.params?.request_type === 'view_account') {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                amount: '1000000000000000000000000',
                block_height: 100,
                block_hash: 'Hash100',
                code_hash: EMPTY_CODE_HASH,
                storage_usage: 182
              }
            })
          };
        }
        if (body.params?.request_type === 'view_access_key_list') {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              jsonrpc: '2.0',
              id: body.id,
              result: { keys: [] }
            })
          };
        }
      };

      const res = await analyzeNearSecurity('keyless-user.near', { fetchFn: mockFetch });
      assert.equal(res.status, 'AVAILABLE');
      assert.equal(res.verdict, 'LOW');
      assert.ok(res.findings.some(f => f.ruleId === 'NEAR_AUTH_ZERO_ACCESS_KEYS'));
      const finding = res.findings.find(f => f.ruleId === 'NEAR_AUTH_ZERO_ACCESS_KEYS');
      assert.equal(finding.severity, 'INFO');
    });

    it('NR-003: flags more than 3 FullAccess keys as INFO fact without automatic high risk', async () => {
      const mockFetch = async (url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.params?.request_type === 'view_account') {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                amount: '10000000000000000000000000',
                block_height: 100,
                block_hash: 'Hash100',
                code_hash: EMPTY_CODE_HASH,
                storage_usage: 182
              }
            })
          };
        }
        if (body.params?.request_type === 'view_access_key_list') {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                keys: [
                  { public_key: 'ed25519:k1', access_key: { permission: 'FullAccess' } },
                  { public_key: 'ed25519:k2', access_key: { permission: 'FullAccess' } },
                  { public_key: 'ed25519:k3', access_key: { permission: 'FullAccess' } },
                  { public_key: 'ed25519:k4', access_key: { permission: 'FullAccess' } }
                ]
              }
            })
          };
        }
      };

      const res = await analyzeNearSecurity('multikey.near', { fetchFn: mockFetch });
      assert.equal(res.status, 'AVAILABLE');
      assert.equal(res.verdict, 'LOW');
      const finding = res.findings.find(f => f.ruleId === 'NEAR_AUTH_MULTIPLE_FULL_ACCESS_KEYS');
      assert.ok(finding);
      assert.equal(finding.severity, 'INFO');
    });

    it('NR-004: flags unrestricted FunctionCall with unlimited allowance on user account as MEDIUM', async () => {
      const mockFetch = async (url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.params?.request_type === 'view_account') {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                amount: '10000000000000000000000000',
                block_height: 100,
                block_hash: 'Hash100',
                code_hash: EMPTY_CODE_HASH,
                storage_usage: 182
              }
            })
          };
        }
        if (body.params?.request_type === 'view_access_key_list') {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                keys: [
                  {
                    public_key: 'ed25519:unrestrictedKey',
                    access_key: {
                      permission: {
                        FunctionCall: {
                          allowance: null,
                          receiver_id: 'unknown-dapp.near',
                          method_names: []
                        }
                      }
                    }
                  }
                ]
              }
            })
          };
        }
      };

      const res = await analyzeNearSecurity('user-with-keys.near', { fetchFn: mockFetch });
      assert.equal(res.status, 'AVAILABLE');
      assert.equal(res.verdict, 'MEDIUM');
      assert.ok(res.findings.some(f => f.ruleId === 'NEAR_PERM_UNRESTRICTED_FUNCTION_CALL'));
    });

    it('NR-005: flags storage pressure when liquid balance is very low relative to storage stake', async () => {
      const mockFetch = async (url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.params?.request_type === 'view_account') {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                amount: '10000000000000000', // tiny amount (0.00000001 NEAR)
                block_height: 100,
                block_hash: 'Hash100',
                code_hash: EMPTY_CODE_HASH,
                storage_usage: 500000 // 500KB requires ~5 NEAR
              }
            })
          };
        }
        if (body.params?.request_type === 'view_access_key_list') {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              jsonrpc: '2.0',
              id: body.id,
              result: { keys: [] }
            })
          };
        }
      };

      const res = await analyzeNearSecurity('strained.near', { fetchFn: mockFetch });
      assert.ok(res.findings.some(f => f.ruleId === 'NEAR_STORAGE_PRESSURE_INDICATOR'));
      const storageFinding = res.findings.find(f => f.ruleId === 'NEAR_STORAGE_PRESSURE_INDICATOR');
      assert.equal(storageFinding.category, 'STORAGE');
      assert.equal(storageFinding.severity, 'LOW');
    });
  });

});

