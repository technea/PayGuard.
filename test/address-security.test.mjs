import test from 'node:test';
import assert from 'node:assert/strict';
import {
  checkAddressSecurity,
  evaluateAddressSecurityData,
  clearAddressCache,
  getAddressCacheSize,
  isValidEvmAddress,
  normalizeChainId,
  SUPPORTED_CHAIN_ID
} from '../src/address-security.mjs';

const MOCK_SAFE_ADDRESS = '0x1111111111111111111111111111111111111111';
const MOCK_BAD_ADDRESS = '0x2222222222222222222222222222222222222222';
const MOCK_CHAIN_ID = '8453';

function createMockFetch(status, payload, options = {}) {
  const { delayMs = 0, isNetworkError = false, rawText } = options;
  return async () => {
    if (delayMs > 0) {
      await new Promise(r => setTimeout(r, delayMs));
    }
    if (isNetworkError) {
      throw new Error('Connection refused (mock network failure)');
    }
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => (rawText !== undefined ? rawText : JSON.stringify(payload))
    };
  };
}

test('1. Clean address with all zero flags returns PASS with LOW risk and AVAILABLE dataStatus', async () => {
  clearAddressCache();
  const mockPayload = {
    code: 1,
    message: 'ok',
    result: {
      cybercrime: '0',
      money_laundering: '0',
      number_of_malicious_contracts_created: '0',
      gas_abuse: '0',
      financial_crime: '0',
      darkweb_transactions: '0',
      reinit: '0',
      phishing_activities: '0',
      contract_address: '0',
      fake_kyc: '0',
      blacklist_doubt: '0',
      fake_standard_interface: '0',
      stealing_attack: '0',
      blackmail_activities: '0',
      sanctioned: '0',
      malicious_mining_activities: '0',
      mixer: '0',
      fake_token: '0',
      honeypot_related_address: '0'
    }
  };

  const res = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: createMockFetch(200, mockPayload)
  });

  assert.equal(res.verdict, 'PASS');
  assert.equal(res.riskLevel, 'LOW');
  assert.equal(res.findings.length, 0);
  assert.equal(res.reasonCodes.length, 0);
  assert.equal(res.dataStatus, 'AVAILABLE');
  assert.equal(res.address, MOCK_SAFE_ADDRESS.toLowerCase());
});

test('2. Phishing activity or stealing attack flags BLOCK with CRITICAL risk', async () => {
  clearAddressCache();
  const resPhishing = evaluateAddressSecurityData({
    phishing_activities: '1'
  }, '8453', MOCK_BAD_ADDRESS.toLowerCase());

  assert.equal(resPhishing.verdict, 'BLOCK');
  assert.equal(resPhishing.riskLevel, 'CRITICAL');
  assert.ok(resPhishing.reasonCodes.includes('PHISHING_ACTIVITIES'));

  const resStealing = evaluateAddressSecurityData({
    stealing_attack: '1'
  }, '8453', MOCK_BAD_ADDRESS.toLowerCase());

  assert.equal(resStealing.verdict, 'BLOCK');
  assert.equal(resStealing.riskLevel, 'CRITICAL');
  assert.ok(resStealing.reasonCodes.includes('STEALING_ATTACK'));
});

test('3. Sanctioned address flags BLOCK with CRITICAL risk', async () => {
  clearAddressCache();
  const res = evaluateAddressSecurityData({
    sanctioned: '1'
  }, '8453', MOCK_BAD_ADDRESS.toLowerCase());

  assert.equal(res.verdict, 'BLOCK');
  assert.equal(res.riskLevel, 'CRITICAL');
  assert.ok(res.reasonCodes.includes('SANCTIONED_ADDRESS'));
});

test('4. Blacklist doubt, honeypot affiliate, or fake token flags BLOCK with HIGH risk', async () => {
  clearAddressCache();
  const res = evaluateAddressSecurityData({
    blacklist_doubt: '1',
    honeypot_related_address: '1',
    fake_token: '1'
  }, '8453', MOCK_BAD_ADDRESS.toLowerCase());

  assert.equal(res.verdict, 'BLOCK');
  assert.equal(res.riskLevel, 'HIGH');
  assert.ok(res.reasonCodes.includes('BLACKLIST_SUSPICION'));
  assert.ok(res.reasonCodes.includes('HONEYPOT_AFFILIATE'));
  assert.ok(res.reasonCodes.includes('FAKE_TOKEN_ISSUER'));
});

test('5. Mixer usage, darkweb transactions, or gas abuse returns REVIEW with MEDIUM risk', async () => {
  clearAddressCache();
  const res = evaluateAddressSecurityData({
    mixer: '1',
    darkweb_transactions: '1',
    gas_abuse: '1'
  }, '8453', MOCK_BAD_ADDRESS.toLowerCase());

  assert.equal(res.verdict, 'REVIEW');
  assert.equal(res.riskLevel, 'MEDIUM');
  assert.ok(res.reasonCodes.includes('MIXER_USAGE'));
  assert.ok(res.reasonCodes.includes('DARKWEB_TRANSACTIONS'));
  assert.ok(res.reasonCodes.includes('GAS_ABUSE'));
});

test('6. Number of malicious contracts created is evaluated properly', async () => {
  clearAddressCache();
  // 1 contract -> HIGH
  const res1 = evaluateAddressSecurityData({
    number_of_malicious_contracts_created: '1'
  }, '8453', MOCK_BAD_ADDRESS.toLowerCase());
  assert.equal(res1.verdict, 'BLOCK');
  assert.equal(res1.riskLevel, 'HIGH');
  assert.ok(res1.reasonCodes.includes('MALICIOUS_CONTRACTS_CREATED'));

  // 4 contracts -> CRITICAL
  const res4 = evaluateAddressSecurityData({
    number_of_malicious_contracts_created: '4'
  }, '8453', MOCK_BAD_ADDRESS.toLowerCase());
  assert.equal(res4.verdict, 'BLOCK');
  assert.equal(res4.riskLevel, 'CRITICAL');
});

test('7. Unsupported Base Sepolia returns UNVERIFIED with UNSUPPORTED_CHAIN', async () => {
  const res = await checkAddressSecurity({
    chainId: '84532',
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: () => { throw new Error('Must not reach fetch on unsupported chain'); }
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.equal(res.riskLevel, 'UNKNOWN');
  assert.ok(res.reasonCodes.includes('UNSUPPORTED_CHAIN'));
  assert.equal(res.dataStatus, 'UNSUPPORTED');
});

test('8. Empty result or null response fails closed with UNVERIFIED', async () => {
  clearAddressCache();
  const mockPayload = {
    code: 1,
    message: 'ok',
    result: {}
  };

  const res = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: createMockFetch(200, mockPayload)
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.equal(res.riskLevel, 'UNKNOWN');
  assert.ok(res.reasonCodes.includes('EMPTY_RESULT'));
  assert.equal(res.dataStatus, 'EMPTY_RESULT');
});

test('9. Request timeout triggers UNVERIFIED with REQUEST_TIMEOUT', async () => {
  clearAddressCache();
  const abortingFetch = async (url, init) => {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => resolve({ ok: true }), 500);
      if (init?.signal) {
        init.signal.addEventListener('abort', () => {
          clearTimeout(timer);
          const err = new Error('The operation was aborted');
          err.name = 'AbortError';
          reject(err);
        });
      }
    });
  };

  const res = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: abortingFetch,
    timeoutMs: 50
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('REQUEST_TIMEOUT'));
  assert.equal(res.dataStatus, 'UNAVAILABLE');
});

test('10. Network failure triggers UNVERIFIED with NETWORK_ERROR', async () => {
  clearAddressCache();
  const res = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: createMockFetch(500, null, { isNetworkError: true })
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('NETWORK_ERROR'));
  assert.equal(res.dataStatus, 'UNAVAILABLE');
});

test('11. HTTP 429 rate limit triggers UNVERIFIED with RATE_LIMITED', async () => {
  clearAddressCache();
  const res = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: createMockFetch(429, { message: 'Too Many Requests' })
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('RATE_LIMITED'));
  assert.equal(res.dataStatus, 'RATE_LIMITED');
});

test('12. HTTP 500 upstream failure triggers UNVERIFIED with UPSTREAM_ERROR', async () => {
  clearAddressCache();
  const res = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: createMockFetch(500, { message: 'Internal Server Error' })
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('UPSTREAM_ERROR'));
  assert.equal(res.dataStatus, 'UNAVAILABLE');
});

test('13. Malformed JSON triggers UNVERIFIED with MALFORMED_JSON', async () => {
  clearAddressCache();
  const res = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: createMockFetch(200, null, { rawText: '<html>Bad Gateway</html>' })
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('MALFORMED_JSON'));
  assert.equal(res.dataStatus, 'ERROR');
});

test('14. Invalid address format returns UNVERIFIED with INVALID_ADDRESS', async () => {
  const res = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: '0xinvalid_address',
    fetchImpl: () => { throw new Error('Must not reach fetch'); }
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('INVALID_ADDRESS'));
  assert.equal(res.dataStatus, 'MALFORMED_INPUT');
});

test('15. Oversized response payload (>64KB) is rejected with OVERSIZED_RESPONSE', async () => {
  clearAddressCache();
  const bigString = 'x'.repeat(70000);
  const res = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: createMockFetch(200, null, { rawText: bigString })
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('OVERSIZED_RESPONSE'));
  assert.equal(res.dataStatus, 'ERROR');
});

test('16. In-memory cache hit avoids repeat fetch; error responses are not cached', async () => {
  clearAddressCache();
  let callCount = 0;
  const mockPayload = {
    code: 1,
    result: {
      phishing_activities: '0'
    }
  };

  const countedFetch = async () => {
    callCount++;
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify(mockPayload)
    };
  };

  // First call
  const first = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: countedFetch
  });
  assert.equal(first.verdict, 'PASS');
  assert.equal(callCount, 1);
  assert.equal(first.cached, undefined);

  // Second call
  const second = await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: countedFetch
  });
  assert.equal(second.verdict, 'PASS');
  assert.equal(callCount, 1, 'Should not fetch again');
  assert.equal(second.cached, true);

  // Transient error test
  clearAddressCache();
  let errCalls = 0;
  const errFetch = async () => {
    errCalls++;
    return { ok: false, status: 500, text: async () => 'err' };
  };

  await checkAddressSecurity({
    chainId: MOCK_CHAIN_ID,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: errFetch
  });
  assert.equal(errCalls, 1);
  assert.equal(getAddressCacheSize(), 0);
});

test('17. Verified endpoint construction format', async () => {
  let requestedUrl = '';
  const inspectFetch = async (url) => {
    requestedUrl = url;
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ code: 1, result: {} })
    };
  };

  await checkAddressSecurity({
    chainId: 8453,
    address: MOCK_SAFE_ADDRESS,
    fetchImpl: inspectFetch
  });

  assert.equal(
    requestedUrl,
    `https://api.gopluslabs.io/api/v1/address_security/${MOCK_SAFE_ADDRESS.toLowerCase()}?chain_id=8453`
  );
});
