/**
 * @module agent/payguard-executor
 * @section Runtime adapter for existing PayGuard tools
 * Connects the bounded investigation runner to the existing read-only plugin handlers.
 * This adapter does not register a new MCP tool or expose a network endpoint.
 */

import plugin from "../plugin.mjs";

/**
 * Create an executor backed by the seven existing PayGuard plugin tools.
 * A plugin-compatible target may be injected for deterministic tests or host integration.
 */
export function createPayGuardToolExecutor(targetPlugin = plugin) {
  if (!targetPlugin || typeof targetPlugin.invokeTool !== "function") {
    throw new TypeError("targetPlugin must expose invokeTool(name, input).");
  }

  return async function executePayGuardTool(toolName, input) {
    return targetPlugin.invokeTool(toolName, input);
  };
}
