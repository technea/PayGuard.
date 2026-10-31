import { analyzeSecurityHeaders } from "./header-analysis.mjs";
import { analyzeHtmlSnapshot } from "./html-analysis.mjs";
import { validateWebsiteSnapshot } from "./input-validation.mjs";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function highestSeverity(findings) {
  return SEVERITY_ORDER.find(severity => findings.some(finding => finding.severity === severity)) || "none";
}

/**
 * Analyze a caller-supplied website response snapshot without making network
 * requests. This module never visits the target, follows redirects, or runs
 * active vulnerability tests.
 */
export function analyzeWebsiteSnapshot(input) {
  const snapshot = validateWebsiteSnapshot(input);
  const findings = [
    ...analyzeSecurityHeaders(snapshot.responseHeaders, snapshot.finalUrl),
    ...analyzeHtmlSnapshot(snapshot.html, snapshot.finalUrl)
  ];

  if (snapshot.finalUrl.origin !== snapshot.targetUrl.origin) {
    findings.push({
      id: "cross_origin_redirect",
      category: "redirect_chain",
      severity: "low",
      confidence: "high",
      title: "The supplied final URL has a different origin",
      evidence: "The supplied finalUrl origin differs from targetUrl. The redirect chain itself has not been independently verified.",
      remediation: "Confirm that the cross-origin destination is expected and controlled by the website owner."
    });
  }

  return {
    scanner: "payguard-passive-website-snapshot",
    scannerVersion: "0.1.0",
    scanMode: "passive_snapshot",
    networkRequestsMade: 0,
    target: snapshot.targetUrl.origin,
    finalUrl: snapshot.finalUrl.toString(),
    redirectCount: snapshot.redirects.length,
    assessment: findings.length > 0 ? "FINDINGS_OBSERVED" : "NO_OBVIOUS_ISSUES_IN_SUPPLIED_SNAPSHOT",
    highestSeverity: highestSeverity(findings),
    findingCount: findings.length,
    findings,
    limitations: [
      "Analysis is limited to caller-supplied HTML, response headers and URL metadata; PayGuard did not retrieve or independently verify them.",
      "A missing header or heuristic signal is not proof that a website is malicious.",
      "This passive snapshot analysis does not test authentication, authorization, server-side code, APIs, business logic or exploitability.",
      "No active scan, crawling, DNS lookup, TLS handshake or vulnerability exploitation was performed."
    ],
    analyzedAt: new Date().toISOString()
  };
}

export { validateWebsiteSnapshot } from "./input-validation.mjs";
