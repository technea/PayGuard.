# PayGuard — Demo Script (3–4 Minutes)

**Audience:** Judges, technical evaluators, Web3 developers
**Format:** Terminal walkthrough + code execution
**Prerequisites:** Node.js 20+, `npm test` passing, `npm run build` completed (7 tools)

> [!IMPORTANT]
> All examples use public test contracts, known addresses, or synthetic inputs. No private keys are required. No real funds are at risk.

---

## Setup (30 seconds)

```bash
cd PayGuard
node --version    # Must be v20+
npm test          # Confirm the suite passes
npm run build     # Confirm "7 tools exposed"
```

---

## Demo Scene 1 — Phishing URL & Homoglyph Detection (45 seconds)

**Narrative:** *"An autonomous agent or human is presented with a Base ecosystem checkout URL. Before connecting a wallet, PayGuard inspects the link purely in-memory without making outbound network requests (eliminating SSRF)."*

```bash
node --input-type=module --eval "
import { analyzeUrlSecurity } from './src/plugin.mjs';

// Lookalike Cyrillic 'a' (U+0430) spoofing 'base.org'
const result = await analyzeUrlSecurity({
  url: 'https://b\u0430se.org/bridge',
  expectedDomain: 'base.org'
});

console.log('Target URL:', result.normalizedUrl);
console.log('Verdict:', result.verdict);
console.log('Risk Level:', result.riskLevel);
console.log('Findings:', result.checks.map(c => c.id));
console.log('Was URL fetched over network?', result.urlFetched);
"
```

**Expected output:**
- `Verdict: SUSPICIOUS`
- `Risk Level: HIGH`
- `Findings: [ 'HOMOGLYPH_DETECTED', 'DOMAIN_MISMATCH' ]`
- `Was URL fetched over network?: false` (100% In-Memory)

---

## Demo Scene 2 — Unlimited ERC-20 Allowance Trap (45 seconds)

**Narrative:** *"A malicious dApp presents an approve transaction to an agent. Instead of approving a safe amount, it requests uint256.max (unlimited allowance). PayGuard decodes the calldata and flags the risk before signing."*

```bash
node --input-type=module --eval "
import { inspectCalldata } from './src/calldata-inspector.mjs';

// approve(spender, 2^256 - 1)
const result = inspectCalldata({
  to: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', // USDC on Base
  value: '0',
  data: '0x095ea7b3' +
        '000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' +
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
});

console.log('Method:', result.decoded.method);
console.log('Verdict:', result.verdict);
console.log('Risk Level:', result.riskLevel);
console.log('Warning:', result.warnings[0].message);
"
```

**Expected output:**
- `Method: approve`
- `Verdict: REVIEW`
- `Risk Level: HIGH`
- `Warning: Unlimited token allowance requested (uint256.max)`

---

## Demo Scene 3 — Base Wallet Token Scanner & Impersonation (60 seconds)

**Narrative:** *"Attackers often deploy lookalike tokens with official symbols (like USDC or VIRTUAL) to impersonate genuine projects. PayGuard's Base Wallet Token Scanner scans wallet holdings, checks GoPlus honeypot parameters, and verifies whether contracts match official canonical deployments."*

```bash
node --input-type=module --eval "
import { scanBaseWalletTokens } from './src/wallet-token-scanner.mjs';

// Scan the public Base WETH contract holdings
const result = await scanBaseWalletTokens({
  walletAddress: '0x4200000000000000000000000000000000000006'
});

console.log('Status:', result.status);
console.log('Discovery Mode:', result.discoveryMode);
console.log('Holdings Audited:', result.tokensScannedCount);
result.tokens.forEach(t => {
  console.log(\` - \${t.symbol} (\${t.contractAddress.slice(0, 10)}...): \${t.securityStatus} | Official: \${t.isVerifiedOfficial} | Impersonation: \${t.isImpersonation}\`);
});
"
```

**Expected output:**
- `Status: SUCCESS`
- `Discovery Mode: REGISTRY_AND_CUSTOM_PARTIAL` (Honest status reporting)
- Displays audited canonical Base assets and security verdicts.

---

## Demo Scene 4 — Interactive Security Console (30 seconds)

Start the local server and show the UI:

```bash
npm start
```

Navigate to `http://localhost:8080/dashboard`:
- Test live presets in URL Sentinel.
- Test Calldata Inspector with unlimited allowance traps.
- Test Token Security with live Base contracts.
- Scan any Base wallet in the Base Wallet Scanner tab.
