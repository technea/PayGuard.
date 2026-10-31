import { SECURITY_HEADERS } from "./constants.mjs";

function addFinding(findings, finding) {
  findings.push({
    id: finding.id,
    category: "http_security_headers",
    severity: finding.severity,
    confidence: "high",
    title: finding.title,
    evidence: finding.evidence,
    remediation: finding.remediation
  });
}

export function analyzeSecurityHeaders(headers, pageUrl) {
  const findings = [];
  const isHttps = pageUrl.protocol === "https:";

  for (const rule of SECURITY_HEADERS) {
    if (rule.name === "strict-transport-security" && !isHttps) continue;
    const value = headers[rule.name];

    if (!value) {
      addFinding(findings, {
        ...rule,
        evidence: `The supplied response snapshot does not include the ${rule.name} header.`
      });
      continue;
    }

    if (rule.name === "x-content-type-options" && value.trim().toLowerCase() !== "nosniff") {
      addFinding(findings, {
        ...rule,
        evidence: `The supplied header value is '${value.slice(0, 160)}', not 'nosniff'.`
      });
    }
  }

  const frameOptions = headers["x-frame-options"];
  const csp = headers["content-security-policy"];
  const hasFrameAncestors = typeof csp === "string" && /(?:^|;)\s*frame-ancestors\s+[^;]+/i.test(csp);
  if (!frameOptions && !hasFrameAncestors) {
    addFinding(findings, {
      id: "missing_clickjacking_protection",
      severity: "low",
      title: "No clickjacking protection was observed",
      evidence: "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive appears in the supplied response headers.",
      remediation: "Use Content-Security-Policy frame-ancestors to define trusted embedding origins. X-Frame-Options may be retained for legacy browser support."
    });
  }

  return findings;
}
