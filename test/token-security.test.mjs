import test from 'node:test';
import assert from 'node:assert/strict';
import {
  checkTokenSecurity,
  evaluateTokenSecurityData,
  clearTokenCache,
  getTokenCacheSize,
  isValidEvmAddress,
  normalizeChainId,
  SUPPORTED_CHAIN_ID
} from '../src/token-security.mjs';

const MOCK_USDC_ADDRESS = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
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

test('1. Valid Base USDC-style response returns PASS with expected metadata and findings', async () => {
  clearTokenCache();
  const mockPayload = {
    code: 1,
    message: 'OK',
    result: {
      [MOCK_USDC_ADDRESS.toLowerCase()]: {
        token_name: 'USD Coin',
        token_symbol: 'USDC',
        is_honeypot: '0',
        cannot_buy: '0',
        cannot_sell_all: '0',
        buy_tax: '0.00',
        sell_tax: '0.00',
        slippage_modifiable: '0',
        transfer_pausable: '0',
        owner_change_balance: '0',
        is_open_source: '1',
        is_proxy: '1',
        is_mintable: '0',
        trust_list: '1'
      }
    }
  };

  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: createMockFetch(200, mockPayload)
  });

  assert.equal(res.verdict, 'PASS');
  assert.equal(res.riskLevel, 'LOW');
  assert.equal(res.tokenName, 'USD Coin');
  assert.equal(res.tokenSymbol, 'USDC');
  assert.ok(res.reasonCodes.includes('UPGRADEABLE_PROXY'));
  assert.ok(res.reasonCodes.includes('RECOGNIZED_TRUST_LIST'));
  assert.equal(res.dataStatus, 'AVAILABLE');
});

test('2. Honeypot indicator flags BLOCK with critical risk', async () => {
  clearTokenCache();
  const mockPayload = {
    code: 1,
    result: {
      [MOCK_USDC_ADDRESS.toLowerCase()]: {
        token_name: 'Honeypot Coin',
        token_symbol: 'HONEY',
        is_honeypot: '1',
        buy_tax: '0.00',
        sell_tax: '0.99'
      }
    }
  };

  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: createMockFetch(200, mockPayload)
  });

  assert.equal(res.verdict, 'BLOCK');
  assert.equal(res.riskLevel, 'CRITICAL');
  assert.ok(res.reasonCodes.includes('HONEYPOT_DETECTED'));
  assert.ok(res.reasonCodes.includes('EXCESSIVE_SELL_TAX'));
});

test('3. High buy/sell tax triggers BLOCK or REVIEW properly', async () => {
  clearTokenCache();
  // 30% tax triggers BLOCK
  const resBlock = evaluateTokenSecurityData({
    token_name: 'Tax Token',
    buy_tax: '0.30',
    sell_tax: '0.10'
  }, '8453', MOCK_USDC_ADDRESS.toLowerCase());

  assert.equal(resBlock.verdict, 'BLOCK');
  assert.ok(resBlock.reasonCodes.includes('EXCESSIVE_BUY_TAX'));
  assert.ok(resBlock.reasonCodes.includes('HIGH_SELL_TAX'));

  // 8% tax triggers REVIEW
  const resReview = evaluateTokenSecurityData({
    token_name: 'Moderate Tax',
    buy_tax: '0.08',
    sell_tax: '0.04'
  }, '8453', MOCK_USDC_ADDRESS.toLowerCase());

  assert.equal(resReview.verdict, 'REVIEW');
  assert.equal(resReview.riskLevel, 'MEDIUM');
  assert.ok(resReview.reasonCodes.includes('HIGH_BUY_TAX'));
});

test('4. Transfer pausable indicator returns REVIEW', async () => {
  clearTokenCache();
  const res = evaluateTokenSecurityData({
    token_name: 'Pausable Token',
    transfer_pausable: '1'
  }, '8453', MOCK_USDC_ADDRESS.toLowerCase());

  assert.equal(res.verdict, 'REVIEW');
  assert.ok(res.reasonCodes.includes('TRANSFER_PAUSABLE'));
});

test('5. Owner balance modification indicator flags BLOCK with critical risk', async () => {
  clearTokenCache();
  const res = evaluateTokenSecurityData({
    token_name: 'Scam Token',
    owner_change_balance: '1'
  }, '8453', MOCK_USDC_ADDRESS.toLowerCase());

  assert.equal(res.verdict, 'BLOCK');
  assert.equal(res.riskLevel, 'CRITICAL');
  assert.ok(res.reasonCodes.includes('OWNER_CAN_CHANGE_BALANCE'));
});

test('6. Unverified source code flags REVIEW rather than blocking outright', async () => {
  clearTokenCache();
  const res = evaluateTokenSecurityData({
    token_name: 'Closed Source',
    is_open_source: '0'
  }, '8453', MOCK_USDC_ADDRESS.toLowerCase());

  assert.equal(res.verdict, 'REVIEW');
  assert.ok(res.reasonCodes.includes('CLOSED_SOURCE_BYTECODE'));
});

test('7. Unsupported Base Sepolia returns UNVERIFIED with UNSUPPORTED_CHAIN', async () => {
  const res = await checkTokenSecurity({
    chainId: '84532',
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: () => { throw new Error('Must not reach fetch on unsupported chain'); }
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.equal(res.riskLevel, 'UNKNOWN');
  assert.ok(res.reasonCodes.includes('UNSUPPORTED_CHAIN'));
  assert.equal(res.dataStatus, 'UNSUPPORTED');
});

test('8. Unindexed token in GoPlus database returns UNVERIFIED with EMPTY_RESULT', async () => {
  clearTokenCache();
  const mockPayload = {
    code: 1,
    message: 'OK',
    result: {}
  };

  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: createMockFetch(200, mockPayload)
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.equal(res.riskLevel, 'UNKNOWN');
  assert.ok(res.reasonCodes.includes('UNINDEXED_TOKEN'));
  assert.equal(res.dataStatus, 'EMPTY_RESULT');
});

test('9. Empty result or null token data fails closed with UNVERIFIED', async () => {
  clearTokenCache();
  const mockPayload = {
    code: 1,
    message: 'OK',
    result: null
  };

  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: createMockFetch(200, mockPayload)
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('UNINDEXED_TOKEN'));
});

test('10. Request timeout triggers UNVERIFIED with REQUEST_TIMEOUT', async () => {
  clearTokenCache();
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

  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: abortingFetch,
    timeoutMs: 50
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('REQUEST_TIMEOUT'));
  assert.equal(res.dataStatus, 'UNAVAILABLE');
});

test('11. Network failure triggers UNVERIFIED with NETWORK_ERROR', async () => {
  clearTokenCache();
  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: createMockFetch(500, null, { isNetworkError: true })
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('NETWORK_ERROR'));
  assert.equal(res.dataStatus, 'UNAVAILABLE');
});

test('12. HTTP 429 rate limit triggers UNVERIFIED with RATE_LIMITED', async () => {
  clearTokenCache();
  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: createMockFetch(429, { message: 'Too Many Requests' })
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('RATE_LIMITED'));
  assert.equal(res.dataStatus, 'RATE_LIMITED');
});

test('13. HTTP 500 upstream failure triggers UNVERIFIED with UPSTREAM_ERROR', async () => {
  clearTokenCache();
  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: createMockFetch(500, { message: 'Internal Server Error' })
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('UPSTREAM_ERROR'));
  assert.equal(res.dataStatus, 'UNAVAILABLE');
});

test('14. Malformed JSON triggers UNVERIFIED with MALFORMED_JSON', async () => {
  clearTokenCache();
  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: createMockFetch(200, null, { rawText: '<html>Internal Error</html>' })
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('MALFORMED_JSON'));
  assert.equal(res.dataStatus, 'ERROR');
});

test('15. Missing response fields do not crash and evaluate safely', async () => {
  clearTokenCache();
  const res = evaluateTokenSecurityData({}, '8453', MOCK_USDC_ADDRESS.toLowerCase());
  // An object with zero findings defaults to PASS
  assert.equal(res.verdict, 'PASS');
  assert.equal(res.findings.length, 0);
});

test('16. Invalid contract address format returns UNVERIFIED with INVALID_CONTRACT_ADDRESS', async () => {
  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: '0xinvalid_address',
    fetchImpl: () => { throw new Error('Must not reach fetch'); }
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('INVALID_CONTRACT_ADDRESS'));
  assert.equal(res.dataStatus, 'MALFORMED_INPUT');
});

test('17. Oversized response payload (>64KB) is rejected with OVERSIZED_RESPONSE', async () => {
  clearTokenCache();
  const bigString = 'x'.repeat(70000);
  const res = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: createMockFetch(200, null, { rawText: bigString })
  });

  assert.equal(res.verdict, 'UNVERIFIED');
  assert.ok(res.reasonCodes.includes('OVERSIZED_RESPONSE'));
  assert.equal(res.dataStatus, 'ERROR');
});

test('18. In-memory cache hit avoids repeat fetch; error responses are not cached', async () => {
  clearTokenCache();
  let callCount = 0;
  const mockPayload = {
    code: 1,
    result: {
      [MOCK_USDC_ADDRESS.toLowerCase()]: {
        token_name: 'Cacheable Token',
        is_honeypot: '0'
      }
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

  // First call: populates cache
  const first = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: countedFetch
  });
  assert.equal(first.verdict, 'PASS');
  assert.equal(callCount, 1);
  assert.equal(first.cached, undefined);

  // Second call: hits cache
  const second = await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: countedFetch
  });
  assert.equal(second.verdict, 'PASS');
  assert.equal(callCount, 1, 'Should not have called fetch again');
  assert.equal(second.cached, true);

  // Transient error test: errors must not be cached
  clearTokenCache();
  let errorCalls = 0;
  const errFetch = async () => {
    errorCalls++;
    return {
      ok: false,
      status: 500,
      text: async () => 'error'
    };
  };

  await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: errFetch
  });
  assert.equal(errorCalls, 1);
  assert.equal(getTokenCacheSize(), 0, 'Error responses must not be cached');

  await checkTokenSecurity({
    chainId: MOCK_CHAIN_ID,
    contractAddress: MOCK_USDC_ADDRESS,
    fetchImpl: errFetch
  });
  assert.equal(errorCalls, 2, 'Should retry fetch on previous error');
});

test('19. Address validation helper & Chain ID normalizer behave accurately', () => {
  assert.equal(isValidEvmAddress(MOCK_USDC_ADDRESS), true);
  assert.equal(isValidEvmAddress('0x0000000000000000000000000000000000000000'), true);
  assert.equal(isValidEvmAddress('0x123'), false);
  assert.equal(isValidEvmAddress('not-an-address'), false);
  assert.equal(isValidEvmAddress(null), false);

  assert.equal(normalizeChainId(8453), '8453');
  assert.equal(normalizeChainId('8453'), '8453');
  assert.equal(normalizeChainId('eip155:8453'), '8453');
  assert.equal(normalizeChainId(''), '');
});
