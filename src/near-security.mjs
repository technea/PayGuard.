/**
 * Bridge module forwarder preserving existing imports and compatibility
 */

export * from "./near/index.mjs";
export { runNearSecurityAgent as analyzeNearSecurity } from "./near/index.mjs";
export { validateNearAccountId as parseNearAccountId } from "./near/index.mjs";
export { formatYoctoToNear as formatYoctoNear } from "./near/index.mjs";
export { callFastNearRpc as callNearRpc } from "./near/index.mjs";
export { NEAR_SECURITY_AGENT_TOOL_NAME as NEAR_AGENT_TOOL_NAME } from "./near/index.mjs";
export { NEAR_SECURITY_AGENT_TOOL_DESCRIPTION as NEAR_AGENT_TOOL_DESCRIPTION } from "./near/index.mjs";
export { NEAR_SECURITY_AGENT_INPUT_SCHEMA as NEAR_AGENT_INPUT_SCHEMA } from "./near/index.mjs";
