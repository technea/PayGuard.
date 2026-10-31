export interface PayGuardPlugin {
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
export declare function evaluatePaymentIntent(input: any): any;
export declare function createPayGuardX402Hook(options: { intent: Record<string, unknown>; onDecision?: (result: any, context: any) => void | Promise<void> }): (context: { paymentRequired?: any; selectedRequirements?: any }) => Promise<void | { abort: true; reason: string }>;
export declare function registerPayGuardX402(client: { onBeforePaymentCreation(hook: (context: any) => Promise<any>): any }, options: { intent: Record<string, unknown>; onDecision?: (result: any, context: any) => void | Promise<void> }): any;
export declare function analyzeUrlSecurity(input: any, options?: any): Promise<any>;
export declare function prepareThreatReport(input: any, options?: any): Promise<any>;
export declare function startMcpServer(targetPlugin?: any): void;
