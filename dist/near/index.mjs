/**
 * PayGuard — NEAR Protocol Security Intelligence Agent (Entry Point)
 */

export * from "./types.mjs";
export * from "./providers/fastnear-rpc.mjs";
export * from "./modules/account-intelligence.mjs";
export * from "./modules/detection-engine.mjs";
export * from "./agent/workflow.mjs";

import { runNearSecurityAgent } from "./agent/workflow.mjs";

export const NEAR_SECURITY_AGENT_TOOL_NAME = "payguard_near_security_intelligence";
export const NEAR_SECURITY_AGENT_TOOL_DESCRIPTION =
  "Investigate NEAR accounts and smart contracts using FastNear RPC. Evaluates account existence, code hash, access keys, and impersonation risks. Read-only and non-custodial.";

export const NEAR_SECURITY_AGENT_INPUT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["accountId"],
  properties: {
    accountId: {
      type: "string",
      description: "NEAR account identifier (e.g. 'alice.near', 'wrap.near', or 64-char implicit address)"
    }
  }
};

export const payGuardNearSecurityTool = Object.freeze({
  id: NEAR_SECURITY_AGENT_TOOL_NAME,
  name: NEAR_SECURITY_AGENT_TOOL_NAME,
  title: NEAR_SECURITY_AGENT_TOOL_NAME,
  description: NEAR_SECURITY_AGENT_TOOL_DESCRIPTION,
  inputSchema: NEAR_SECURITY_AGENT_INPUT_SCHEMA,
  input_schema: NEAR_SECURITY_AGENT_INPUT_SCHEMA,
  outputSchema: { type: "object" },
  output_schema: { type: "object" },
  handler: runNearSecurityAgent,
  execute: runNearSecurityAgent,
  run: runNearSecurityAgent
});

export default runNearSecurityAgent;

