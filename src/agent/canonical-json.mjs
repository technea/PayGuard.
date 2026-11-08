/**
 * @module agent/canonical-json
 * @section Stable serialization and immutable snapshots
 * Produces deterministic JSON for evidence hashing and detached JSON snapshots.
 */

function canonicalize(value, seen) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinit(value)) throw new TypeError("Evidence contains a non-finite number.");
    return value;
  }
  if (typeof value !== "object") throw new TypeError("Evidence must contain JSON-compatible values only.");
  if (seen.has(value)) throw new TypeError("Evidence contains a circular reference.");
  seen.add(value);

  let result;
  if (Array.isArray(value)) {
    result = value.map(item => canonicalize(item, seen));
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("Evidence objects must be plain JSON objects.");
    result = {};
    for (const key of Object.keys(value).sort()) {
      const child = value[key];
      if (child === undefined) throw new TypeError(`Evidence field '${key}' is undefined.`);
      result[key] = canonicalize(child, seen);
    }
  }

  seen.delete(value);
  return result;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value, new WeakSet()));
}

export function cloneJsonValue(value) {
  return JSON.parse(canonicalJson(value));
}
