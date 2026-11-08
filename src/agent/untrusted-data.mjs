/**
 * @module agent/untrusted-data
 * @section External text isolation
 * Extracts a bounded display-only projection of strings from tool output.
 * The original raw output is never modified; extracted strings remain untrusted data.
 */
import { MAX_UNTRUSTED_TEXT_ENTRIES, MAX_UNTRUSTED_TEXT_LENGTH } from "./constants.mjs";

const CONTROL_OR_FORMAT = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u061C\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g;

export function sanitizeUntrustedText(value, maxLength = MAX_UNTRUSTED_TEXT_LENGTH) {
  if (typeof value !== "string") return "";
  const safe = value.replace(CONTROL_OR_FORMAT, "�");
  return safe.length > maxLength ? safe.slice(0, maxLength) + "…[truncated]" : safe;
}

export function extractUntrustedText(value, options = {}) {
  const maxEntries = Number.isInteger(options.maxEntries) && options.maxEntries > 0
    ? Math.min(options.maxEntries, MAX_UNTRUSTED_TEXT_ENTRIES)
    : MAX_UNTRUSTED_TEXT_ENTRIES;
  const maxLength = Number.isInteger(options.maxLength) && options.maxLength > 0
    ? Math.min(options.maxLength, MAX_UNTRUSTED_TEXT_LENGTH)
    : MAX_UNTRUSTED_TEXT_LENGTH;
  const entries = [];
  const visited = new WeakSet();

  function visit(node, path, depth) {
    if (entries.length >= maxEntries || depth > 12) return;
    if (typeof node === "string") {
      entries.push({ path, text: sanitizeUntrustedText(node, maxLength), trust: "UNTRUSTED_DATA" });
      return;
    }
    if (!node || typeof node !== "object" || visited.has(node)) return;
    visited.add(node);
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length && entries.length < maxEntries; i++) visit(node[i], path + "/" + i, depth + 1);
    } else {
      for (const key of Object.keys(node).sort()) {
        if (entries.length >= maxEntries) break;
        const escaped = key.replace(/~/g, "~0").replace(/\//g, "~1");
        visit(node[key], path + "/" + escaped, depth + 1);
      }
    }
  }

  visit(value, "", 0);
  return entries;
}
