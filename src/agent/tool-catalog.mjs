/**
 * @module agent/tool-catalog
 * @section Existing PayGuard tool inventory
 * A read-only catalogue of the seven currently registered MCP tools.
 */
import { TOOL_CATALOG } from "./constants.mjs";

export function listAgentCompatibleTools() {
  return Object.entries(TOOL_CATALOG).map(([name, definition]) => ({
    name,
    category: definition.category,
    title: definition.title,
    access: "READ_ONLY",
    defaultRequired: true
  }));
}

export function isKnownPayGuardTool(toolName) {
  return Object.hasOwn(TOOL_CATALOG, toolName);
}

export function getToolDefinition(toolName) {
  const definition = TOOL_CATALOG[toolName];
  return definition ? { name: toolName, ...definition, access: "READ_ONLY" } : null;
}
