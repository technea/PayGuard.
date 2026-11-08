/**
 * @module agent/investigation
 * @section Integrated PayGuard investigation entry point
 * Runs an explicit bounded plan against the existing PayGuard plugin handlers.
 * Tool selection remains caller-controlled; no network route, model, or autonomous planner is added.
 */

import { runInvestigation } from "./runner.mjs";
import { createPayGuardToolExecutor } from "./payguard-executor.mjs";
import plugin from "../plugin.mjs";

/**
 * Execute a caller-supplied plan using PayGuard's current read-only tool handlers.
 */
export async function runPayGuardInvestigation({
  subject = null,
  checks,
  options = {},
  targetPlugin = plugin
} = {}) {
  const executeTool = createPayGuardToolExecutor(targetPlugin);
  return runInvestigation({
    subject,
    checks,
    options,
    executeTool
  });
}
