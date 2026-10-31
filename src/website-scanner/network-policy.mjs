import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

function policyError(message, statusCode = 403) {\n  const error = new TypeError(message);\n  error.statusCode = statusCode;\n  return error;\n}\n\nfunction ipv4ToNumber(address) {
  const parts = address.split(".");
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part))) return null;
  const octets = parts.map(Number);
  if (octets.some(value => value < 0 || value > 255)) return null;
  return (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
}

const BLOCKED_IPV4_RANGES = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10],
  ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]
].map(([base, prefix]) => {
  const value = ipv4ToNumber(base);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { value: value & mask, mask };
});

export function isPublicIPv4(address) {
  const value = ipv4ToNumber(address);
  if (value === null) return false;
  return !BLOCKED_IPV4_RANGES.some(range => (value & range.mask) === range.value);
}

export function validatePublicHostname(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host || host.length > 253 || host.includes("%")) {
    throw policyError("Target hostname is invalid.", 400);
  }
  if (isIP(host) === 6) {
    throw policyError("IPv6 targets are not supported by this initial collector; request rejected safely.", 422);
  }
  if (isIP(host) === 4) {
    if (!isPublicIPv4(host)) throw policyError("Target resolves to a non-public IPv4 address; request blocked.");
    return host;
  }
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) {
    throw policyError("Target must use a fully qualified public DNS hostname.", 400);
  }
  if (["localhost", "local", "internal", "test", "invalid", "example"].some(suffix =>
    host === suffix || host.endsWith("." + suffix)
  )) {
    throw policyError("Non-public or reserved hostname suffixes are not allowed.");
  }
  return host;
}

export async function resolvePublicIPv4(hostname, resolver = lookup) {
  const host = validatePublicHostname(hostname);
  if (isIP(host) === 4) return [{ address: host, family: 4 }];

  let records;
  try {
    records = await resolver(host, { all: true, verbatim: true, family: 4 });
  } catch {
    const error = new Error("Target hostname could not be resolved to a public IPv4 address.");
    error.statusCode = 422;
    throw error;
  }

  if (!Array.isArray(records) || records.length === 0) {
    const error = new Error("Target hostname has no supported public IPv4 address.");
    error.statusCode = 422;
    throw error;
  }

  if (records.some(record => record.family !== 4 || !isPublicIPv4(record.address))) {
    const error = new Error("Target hostname resolves to a non-public or unsupported address; request blocked.");
    error.statusCode = 403;
    throw error;
  }

  return records;
}
