#!/usr/bin/env node
/**
 * @module run-agent-benchmark
 * @section Offline benchmark CLI
 * Runs synthetic deterministic fixtures only; it does not query live providers.
 */

import { runSyntheticBenchmark } from "../src/agent/benchmark.mjs";

const result = await runSyntheticBenchmark();
process.stdout.write(JSON.stringify(result, null, 2) + "\n");

if (result.summary.missedRiskCases.length > 0 ||
    result.summary.falsePositiveCases.length > 0 ||
    result.summary.fixtureMatchRate < 1) {
  process.exitCode = 1;
}
