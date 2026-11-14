/**
 * PayGuard NEAR Security CommonJS Bridge
 */
let nearModule = null;
async function getNearModule() {
  if (!nearModule) {
    nearModule = await import('./near/index.mjs');
  }
  return nearModule;
}

const payGuardNearSecurityTool = Object.freeze({
  id: "payguard_near_security_intelligence",
  name: "payguard_near_security_intelligence",
  title: "payguard_near_security_intelligence",
  description: "Investigate NEAR accounts and smart contracts using FastNear RPC. Evaluates account existence, code hash, access keys, and impersonation risks. Read-only and non-custodial.",
  inputSchema: {
    type: "object",
    additionalProperties: false,
    required: ["accountId"],
    properties: {
      accountId: {
        type: "string",
        description: "NEAR account identifier (e.g. 'alice.near', 'wrap.near', or 64-char implicit address)"
      }
    }
  },
  handler: async (input, options) => {
    const mod = await getNearModule();
    return mod.runNearSecurityAgent(input, options);
  },
  execute: async (input, options) => {
    const mod = await getNearModule();
    return mod.runNearSecurityAgent(input, options);
  },
  run: async (input, options) => {
    const mod = await getNearModule();
    return mod.runNearSecurityAgent(input, options);
  }
});

async function analyzeNearSecurity(input, options) {
  const mod = await getNearModule();
  return mod.runNearSecurityAgent(input, options);
}

module.exports = {
  payGuardNearSecurityTool,
  analyzeNearSecurity,
  NEAR_AGENT_TOOL_NAME: "payguard_near_security_intelligence",
  NEAR_AGENT_TOOL_DESCRIPTION: "Investigate NEAR accounts and smart contracts using FastNear RPC. Evaluates account existence, code hash, access keys, and impersonation risks. Read-only and non-custodial.",
  NEAR_AGENT_INPUT_SCHEMA: payGuardNearSecurityTool.inputSchema,
  default: analyzeNearSecurity
};
