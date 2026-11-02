import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const distDir = new URL('../dist/', import.meta.url);
const srcFile = new URL('../src/plugin.mjs', import.meta.url);
const srcCalldataFile = new URL('../src/calldata-inspector.mjs', import.meta.url);
const srcTokenSecurityFile = new URL('../src/token-security.mjs', import.meta.url);
const srcAddressSecurityFile = new URL('../src/address-security.mjs', import.meta.url);
const destPluginMjs = new URL('../dist/plugin.mjs', import.meta.url);
const destIndexMjs = new URL('../dist/index.mjs', import.meta.url);
const destIndexJs = new URL('../dist/index.js', import.meta.url);
const destPluginJs = new URL('../dist/plugin.js', import.meta.url);
const destIndexCjs = new URL('../dist/index.cjs', import.meta.url);
const destPluginCjs = new URL('../dist/plugin.cjs', import.meta.url);
const destCalldataMjs = new URL('../dist/calldata-inspector.mjs', import.meta.url);
const destCalldataCjs = new URL('../dist/calldata-inspector.cjs', import.meta.url);
const destTokenSecurityMjs = new URL('../dist/token-security.mjs', import.meta.url);
const destTokenSecurityCjs = new URL('../dist/token-security.cjs', import.meta.url);
const destAddressSecurityMjs = new URL('../dist/address-security.mjs', import.meta.url);
const destAddressSecurityCjs = new URL('../dist/address-security.cjs', import.meta.url);
const destDts = new URL('../dist/index.d.ts', import.meta.url);
const rootIndexJs = new URL('../index.js', import.meta.url);
const rootIndexCjs = new URL('../index.cjs', import.meta.url);

await mkdir(distDir, { recursive: true });

// 1. Read source
const srcContent = await readFile(srcFile, 'utf8');
const calldataContent = await readFile(srcCalldataFile, 'utf8');
const tokenSecurityContent = await readFile(srcTokenSecurityFile, 'utf8');
const addressSecurityContent = await readFile(srcAddressSecurityFile, 'utf8');

// Verify that the source is self-contained with no external npm imports
const importMatches = [...srcContent.matchAll(/^(?:import|export)\s+.*?\s+from\s+['"]([^'"]+)['"]/gm)].map(m => m[1]);
const unbundledImports = importMatches.filter(spec => !spec.startsWith('.') && !spec.startsWith('/') && !spec.startsWith('node:'));

if (unbundledImports.length > 0) {
  console.error('Build verification failed! Found unbundled external dependencies:', unbundledImports);
  process.exit(1);
}

// 2. Write ESM bundles (plugin.mjs, index.mjs, index.js, plugin.js, calldata-inspector.mjs, token-security.mjs, address-security.mjs)
const esmShebangContent = srcContent.startsWith('#!') ? srcContent : `#!/usr/bin/env node\n${srcContent}`;
await writeFile(destPluginMjs, esmShebangContent, 'utf8');
await writeFile(destIndexMjs, esmShebangContent, 'utf8');
await writeFile(destIndexJs, esmShebangContent, 'utf8');
await writeFile(destPluginJs, esmShebangContent, 'utf8');
await writeFile(destCalldataMjs, calldataContent, 'utf8');
await writeFile(destTokenSecurityMjs, tokenSecurityContent, 'utf8');
await writeFile(destAddressSecurityMjs, addressSecurityContent, 'utf8');

// 3. Generate CommonJS bundles (index.cjs, plugin.cjs, calldata-inspector.cjs, token-security.cjs, address-security.cjs)
function toCommonJS(esmCode) {
  let cjs = esmCode
    .replace(/^import\s+.*?\s+from\s+['"]\.\/calldata-inspector\.mjs['"];?/gm, "const { inspectCalldata } = require('./calldata-inspector.cjs');")
    .replace(/^import\s+.*?\s+from\s+['"]\.\/token-security\.mjs['"];?/gm, "const { checkTokenSecurity } = require('./token-security.cjs');")
    .replace(/^import\s+.*?\s+from\s+['"]\.\/address-security\.mjs['"];?/gm, "const { checkAddressSecurity } = require('./address-security.cjs');")
    .replace(/^export\s+async\s+function\s+([a-zA-Z0-9_$]+)/gm, 'async function $1')
    .replace(/^export\s+function\s+([a-zA-Z0-9_$]+)/gm, 'function $1')
    .replace(/^export\s+const\s+([a-zA-Z0-9_$]+)/gm, 'const $1')
    .replace(/^export\s+default\s+([a-zA-Z0-9_$]+);?/gm, '');

  cjs = `#!/usr/bin/env node\n/**\n * PayGuard PayBox Plugin - Standalone CJS Bundle\n */\n` + cjs;
  cjs += `\n
const cjsExport = Object.assign({}, plugin, {
  default: plugin,
  plugin: plugin,
  tools: tools,
  payGuardTool: payGuardTool,
  payGuardUrlSentinelTool: payGuardUrlSentinelTool,
  payGuardThreatReportTool: payGuardThreatReportTool,
  payGuardCalldataInspectorTool: payGuardCalldataInspectorTool,
  payGuardTokenSecurityTool: payGuardTokenSecurityTool,
  payGuardAddressSecurityTool: payGuardAddressSecurityTool,
  evaluatePaymentIntent: evaluatePaymentIntent,
  createPayGuardX402Hook: createPayGuardX402Hook,
  registerPayGuardX402: registerPayGuardX402,
  analyzeUrlSecurity: analyzeUrlSecurity,
  prepareThreatReport: prepareThreatReport,
  payGuardInspectCalldata: payGuardInspectCalldata,
  payGuardCheckTokenSecurity: payGuardCheckTokenSecurity,
  payGuardCheckAddressSecurity: payGuardCheckAddressSecurity,
  startMcpServer: startMcpServer
});
module.exports = cjsExport;
`;
  return cjs;
}

function toCalldataCJS(esmCode) {
  let cjs = esmCode
    .replace(/^export\s+async\s+function\s+([a-zA-Z0-9_$]+)/gm, 'async function $1')
    .replace(/^export\s+function\s+([a-zA-Z0-9_$]+)/gm, 'function $1')
    .replace(/^export\s+const\s+([a-zA-Z0-9_$]+)/gm, 'const $1')
    .replace(/^export\s+default\s+([a-zA-Z0-9_$]+);?/gm, '');
  cjs += `\nmodule.exports = { inspectCalldata, UINT256_MAX, SELECTORS, default: inspectCalldata };\n`;
  return cjs;
}

function toTokenSecurityCJS(esmCode) {
  let cjs = esmCode
    .replace(/^export\s+async\s+function\s+([a-zA-Z0-9_$]+)/gm, 'async function $1')
    .replace(/^export\s+function\s+([a-zA-Z0-9_$]+)/gm, 'function $1')
    .replace(/^export\s+const\s+([a-zA-Z0-9_$]+)/gm, 'const $1')
    .replace(/^export\s+default\s+([a-zA-Z0-9_$]+);?/gm, '');
  cjs += `\nmodule.exports = { checkTokenSecurity, evaluateTokenSecurityData, clearTokenCache, getTokenCacheSize, isValidEvmAddress, normalizeChainId, SUPPORTED_CHAIN_ID, default: checkTokenSecurity };\n`;
  return cjs;
}

function toAddressSecurityCJS(esmCode) {
  let cjs = esmCode
    .replace(/^export\s+async\s+function\s+([a-zA-Z0-9_$]+)/gm, 'async function $1')
    .replace(/^export\s+function\s+([a-zA-Z0-9_$]+)/gm, 'function $1')
    .replace(/^export\s+const\s+([a-zA-Z0-9_$]+)/gm, 'const $1')
    .replace(/^export\s+default\s+([a-zA-Z0-9_$]+);?/gm, '');
  cjs += `\nmodule.exports = { checkAddressSecurity, evaluateAddressSecurityData, clearAddressCache, getAddressCacheSize, isValidEvmAddress, normalizeChainId, SUPPORTED_CHAIN_ID, GOPLUS_ADDRESS_SECURITY_ENDPOINT, default: checkAddressSecurity };\n`;
  return cjs;
}

const cjsContent = toCommonJS(srcContent);
await writeFile(destIndexCjs, cjsContent, 'utf8');
await writeFile(destPluginCjs, cjsContent, 'utf8');
await writeFile(destCalldataCjs, toCalldataCJS(calldataContent), 'utf8');
await writeFile(destTokenSecurityCjs, toTokenSecurityCJS(tokenSecurityContent), 'utf8');
await writeFile(destAddressSecurityCjs, toAddressSecurityCJS(addressSecurityContent), 'utf8');

// 4. Generate TypeScript declaration
const dtsContent = `export interface PayGuardPlugin {
  id: string;
  name: string;
  version: string;
  category: string;
  protocol: string;
  description: string;
  tools: readonly any[];
  invokeTool(name: string, input: any): Promise<any> | any;
  execute(name: string, input: any): Promise<any> | any;
  run(name: string, input: any): Promise<any> | any;
}
export declare const plugin: PayGuardPlugin;
export default plugin;
export declare const tools: readonly any[];
export declare const payGuardTool: any;
export declare const payGuardUrlSentinelTool: any;
export declare const payGuardThreatReportTool: any;
export declare const payGuardCalldataInspectorTool: any;
export declare const payGuardTokenSecurityTool: any;
export declare const payGuardAddressSecurityTool: any;
export declare function evaluatePaymentIntent(input: any): any;
export declare function createPayGuardX402Hook(options: { intent: Record<string, unknown>; onDecision?: (result: any, context: any) => void | Promise<void> }): (context: { paymentRequired?: any; selectedRequirements?: any }) => Promise<void | { abort: true; reason: string }>;
export declare function registerPayGuardX402(client: { onBeforePaymentCreation(hook: (context: any) => Promise<any>): any }, options: { intent: Record<string, unknown>; onDecision?: (result: any, context: any) => void | Promise<void> }): any;
export declare function analyzeUrlSecurity(input: any, options?: any): Promise<any>;
export declare function prepareThreatReport(input: any, options?: any): Promise<any>;
export declare function payGuardInspectCalldata(input: any): Promise<any>;
export declare function payGuardCheckTokenSecurity(input: any, options?: any): Promise<any>;
export declare function payGuardCheckAddressSecurity(input: any, options?: any): Promise<any>;
export declare function startMcpServer(targetPlugin?: any): void;
`;
await writeFile(destDts, dtsContent, 'utf8');

// 5. Generate root forwarders
await writeFile(rootIndexJs, `#!/usr/bin/env node\nexport * from "./dist/index.mjs";\nexport { default } from "./dist/index.mjs";\n`, 'utf8');
await writeFile(rootIndexCjs, `#!/usr/bin/env node\nmodule.exports = require("./dist/index.cjs");\n`, 'utf8');

// 6. Dynamic-import smoke test
try {
  const modEsm = await import(destPluginMjs.href);
  if (!modEsm.default || !Array.isArray(modEsm.default.tools)) {
    throw new Error("ESM default export is missing or does not contain a tools array.");
  }
  console.log(`Verified dist/plugin.mjs (${modEsm.default.tools.length} tools exposed).`);
} catch (err) {
  console.error('Dynamic import verification failed on dist/plugin.mjs:', err);
  process.exit(1);
}

console.log('Build completed successfully: bundled ESM, CJS, DTS, and stdio MCP server.');
