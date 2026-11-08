# PayGuard AI Security Agent

## Phase F — Synthetic Offline Benchmark

**Status:** Deterministic regression harness.  
**Dataset:** Hand-authored synthetic fixtures only.  
**External provider calls:** None.

---

## 1. Purpose

Phase F adds a reproducible local benchmark for the deterministic security evaluators and the intent-to-transfer correlation layer.

The benchmark catches regressions in known input/output behavior. It is not a substitute for a curated real-world threat dataset, independent labeling, or a production evaluation.

## 2. Run

```bash
npm run benchmark
```

The command prints a JSON report and exits non-zero if a fixture does not produce its expected evidence status.

## 3. Fixture coverage

The current synthetic fixture set covers:
- trusted-domain URL match and phishing-style lookalike URL;
- clean and honeypot-flagged token provider payloads;
- clean and phishing-flagged address provider payloads;
- standard ERC-20 transfer, unlimited approval, and unsupported calldata selector;
- x402 payment-policy match and recipient-policy mismatch;
- matching and mismatched payment-intent-to-transfer recipient correlation.

All token/address inputs are synthetic GoPlus-shaped payloads. No live provider is queried.

## 4. Report metrics

The output includes:
- fixture match rate;
- synthetic risk detection rate;
- synthetic false-positive rate;
- false-positive and false-negative fixture IDs;
- missed-risk and unresolved fixture IDs.

These metrics describe only this small synthetic fixture set. They must not be presented as real-world precision, recall, detection rate, false-positive rate, coverage, or security guarantees.

An unsupported selector is expected to remain UNVERIFIED, not be mislabeled as malicious or safe.

## 5. Extension rules

When adding fixtures:
1. Give each case a stable ID and category.
2. State the expected evidence status before running the evaluator.
3. Keep all fixtures offline and synthetic unless a separately reviewed, legally safe dataset is approved.
4. Add an explicit expected UNVERIFIED case whenever the correct outcome is uncertainty.
5. Do not use synthetic benchmark numbers in grant applications as production detection metrics.

The benchmark is a regression tool and a starting point for a future independently labeled Base threat dataset.
