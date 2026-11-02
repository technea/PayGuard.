# PayGuard — Demo Script (3–4 Minutes)

**Audience:** Vibeathon judges, technical evaluators, developers
**Format:** Terminal + code walkthrough
**Prerequisites:** Node.js 20+, PayGuard installed, `npm test` passing

> [!IMPORTANT]
> All examples use synthetic addresses and controlled inputs. No real private keys are used. No transactions are broadcast. No real funds are at risk.

---

## Setup (30 seconds)

```bash
cd PayGuard
node --version    # Must be v20+
npm test          # Confirm 143/143 pass
npm run build     # Confirm "6 tools exposed"
```

---

## Demo Scene 1 — Phishing URL Detection (45 seconds)

**Narrative:** *"An AI agent receives a URL to a payment page. Before connecting a wallet or approving anything, it calls PayGuard's URL Sentinel."*

```bash
node --input-type=module --eval "
import { analyzeUrlSecurity } from './src/plugin.mjs';

// Lookalike domain: 'payb0x' instead of 'paybox'
// Plus Unicode Bidi control character U+202E in the raw URL
const result = await analyzeUrlSecurity({
  url: 'https://payb\u00F30x-support.xyz/wallet-recovery',
  expectedDomain: 'paybox.com'
});

console.log('Verdict:', result.verdict);
console.log('Risk:', result.riskLevel);
console.log('Findings:');
result.checks.forEach(c => console.log(' -', c.id, '→', c.severity));
console.log('URL was opened?', result.urlFetched ?? false);
console.log('Payment executed?', result.paymentExecuted);
"
```

**Expected output:**
```
Verdict: SUSPICIOUS
Risk: HIGH
Findings:
 - trusted_domain_mismatch → high
 - possible_lookalike_domain → high
 - wallet_secret_language → high
URL was opened? false
Payment executed? false
```

**Talking points:**
- The URL was **never fetched** — analysis is local only
- "payb0x" is one character from "paybox" — Levenshtein distance detection caught it
- "wallet-recovery" in the path triggered the wallet-secret language check
- `paymentExecuted: false` confirms no financial action was taken

---

## Demo Scene 2 — Unlimited ERC-20 Approval Detection (45 seconds)

**Narrative:** *"A DeFi protocol asks a user to approve unlimited token spending. The agent inspects the calldata before sending it to the wallet."*

```bash
node --input-type=module --eval "
import { inspectCalldata } from './src/calldata-inspector.mjs';

// ERC-20 approve(spender, uint256.max) — unlimited allowance
// Selector: 0x095ea7b3
// Spender: 0xdeadbeef... (not in any allowlist)
// Amount: 0xffff...ffff (2^256 - 1)
const result = inspectCalldata({
  to:    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
  value: '0',
  data:  '0x095ea7b3' +
         '000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' +
         'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
});

console.log('Operation:', result.operation);
console.log('Verdict:', result.verdict);
console.log('Risk Level:', result.riskLevel);
console.log('Is Unlimited?', result.details.isUnlimited);
console.log('Raw Amount:', result.details.rawAmount.slice(0, 20) + '...');
console.log('Risk factors:', result.reasons);
"
```

**Expected output:**
```
Operation: ERC20_APPROVE
Verdict: REVIEW
Risk Level: MEDIUM
Is Unlimited? true
Raw Amount: 11579208923731619...
Risk factors: [ 'UNLIMITED_ALLOWANCE_UINT256_MAX' ]
```

**Talking points:**
- The selector `0x095ea7b3` was decoded as `approve(address,uint256)`
- The amount `2^256 - 1` was identified as the maximum possible allowance
- Verdict is `REVIEW` (not automatic BLOCK) — the agent surfaces this to the user
- With a `policy.allowedSpenders` configured, an unapproved spender would yield `BLOCK`

---

## Demo Scene 3 — Suspicious Token Security Assessment (45 seconds)

**Narrative:** *"A user wants to buy a new token they saw mentioned online. Before interacting, the agent checks its security profile."*

```bash
node --input-type=module --eval "
import { evaluateTokenSecurityData } from './src/token-security.mjs';

// Simulate a GoPlus response for a honeypot token
// (using the pure evaluation function — no live API call needed for demo)
const mockGoPlusData = {
  is_honeypot: '1',
  cannot_sell_all: '1',
  buy_tax: '0.0',
  sell_tax: '0.99',
  is_open_source: '0',
  token_name: 'FakeYield',
  token_symbol: 'FYLD'
};

const result = evaluateTokenSecurityData(mockGoPlusData, '8453', '0xfaketoken...');

console.log('Token:', result.tokenName, '(' + result.tokenSymbol + ')');
console.log('Verdict:', result.verdict);
console.log('Risk Level:', result.riskLevel);
console.log('Findings:');
result.findings.forEach(f =>
  console.log(' [' + f.severity.toUpperCase() + '] ' + f.code + ': ' + f.message)
);
"
```

**Expected output:**
```
Token: FakeYield (FYLD)
Verdict: BLOCK
Risk Level: CRITICAL
Findings:
 [CRITICAL] HONEYPOT_DETECTED: Token is identified as a honeypot; users cannot sell their tokens.
 [HIGH] CANNOT_SELL_ALL: Token holders are restricted from selling their full balance.
 [HIGH] EXCESSIVE_SELL_TAX: Excessive sell tax detected: 99.0%.
 [MEDIUM] CLOSED_SOURCE_BYTECODE: Contract source code is unverified...
```

**Talking points:**
- Honeypot + 99% sell tax + closed source = immediate `BLOCK` verdict
- Structured findings let the agent explain *why* it's blocking
- In production, this calls the live GoPlus API with a 3s timeout and 64 KB limit

---

## Demo Scene 4 — Address Reputation Checking (30 seconds)

**Narrative:** *"Before sending funds to a new counterparty, the agent checks the recipient's address reputation."*

```bash
node --input-type=module --eval "
import { evaluateAddressSecurityData } from './src/address-security.mjs';

// Simulate a response for a sanctioned, phishing address
const mockResult = {
  phishing_activities: '1',
  sanctioned: '1',
  number_of_malicious_contracts_created: '5',
  mixer: '0',
  darkweb_transactions: '0'
};

const result = evaluateAddressSecurityData(
  mockResult, '8453', '0xbadactor...'
);

console.log('Verdict:', result.verdict);
console.log('Risk:', result.riskLevel);
result.findings.forEach(f =>
  console.log('[' + f.severity.toUpperCase() + ']', f.code)
);
"
```

**Expected output:**
```
Verdict: BLOCK
Risk: CRITICAL
[CRITICAL] PHISHING_ACTIVITIES
[CRITICAL] SANCTIONED_ADDRESS
[CRITICAL] MALICIOUS_CONTRACTS_CREATED
```

---

## Demo Scene 5 — Pre-Signing Abort in Action (45 seconds)

**Narrative:** *"Now let's see what happens when the inspection result propagates into PayGuard's transaction flow."*

```bash
node --input-type=module --eval "
import { createBaseSmartWalletClient } from './src/smart-wallet.mjs';

const client = createBaseSmartWalletClient();

// Attempt to request a transaction with an unauthorized spender
// The inspection happens BEFORE any wallet prompt
const result = await client.requestTransaction(
  {
    to:    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
    value: '0',
    data:  '0x095ea7b3' +
           '000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' +
           'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
  },
  {
    policy: {
      allowedSpenders: ['0x1111111111111111111111111111111111111111'],
      maxAllowance: '1000000'
    },
    provider: null  // No wallet in this demo environment
  }
);

console.log('Aborted before wallet?', result.aborted);
console.log('Verdict:', result.verdict);
console.log('Operation:', result.operation);
console.log('Reasons:', result.reasons);
console.log('txHash:', result.txHash);  // null — never reached wallet
"
```

**Expected output:**
```
Aborted before wallet? true
Verdict: BLOCK
Operation: ERC20_APPROVE
Reasons: [ 'SPENDER_NOT_IN_ALLOWLIST', 'UNLIMITED_ALLOWANCE_UINT256_MAX', 'ALLOWANCE_EXCEEDS_POLICY_MAX' ]
txHash: null
```

**Talking points:**
- `requestTransaction()` calls `inspectCalldata()` **first**, before any wallet interaction
- The unauthorized spender + unlimited allowance + policy cap exceeded = three simultaneous violations
- `txHash: null` confirms the wallet was **never asked to sign anything**
- This is real enforcement within PayGuard's controlled signing path

---

## Closing (15 seconds)

```bash
# Confirm test coverage for everything shown
npm test

# 143 tests | 0 failures | ~4 seconds
```

**Final talking points:**
- Every scenario shown has corresponding test coverage in `test/`
- No real funds, keys, or transactions involved at any point
- All modules work offline with injectable mocks — no live API required for testing
- The MCP stdio server exposes all 6 tools to any Claude/Cursor/MCP client with two lines of config
