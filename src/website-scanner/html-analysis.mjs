function extractAttribute(tag, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = tag.match(new RegExp(`\\b${escaped}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return match ? (match[1] ?? match[2] ?? match[3] ?? "") : null;
}

function add(findings, id, severity, title, evidence, remediation, confidence = "medium") {
  findings.push({
    id,
    category: "html_content",
    severity,
    confidence,
    title,
    evidence,
    remediation
  });
}

export function analyzeHtmlSnapshot(html, pageUrl) {
  const findings = [];
  if (!html) return findings;

  const forms = html.match(/<form\b[^>]*>/gi) || [];
  let passwordForms = 0;
  let insecureFormTargets = 0;
  let externalFormTargets = 0;

  for (const tag of forms) {
    const action = extractAttribute(tag, "action");
    if (action === null || action === "") continue;

    let destination;
    try {
      destination = new URL(action, pageUrl);
    } catch {
      continue;
    }

    if (destination.protocol === "http:" && pageUrl.protocol === "https:") {
      insecureFormTargets++;
    }
    if (destination.origin !== pageUrl.origin) externalFormTargets++;
  }

  const passwordInputs = html.match(/<input\b[^>]*\btype\s*=\s*(?:"password"|'password'|password)(?:\s|\/?>)/gi) || [];
  passwordForms = passwordInputs.length;

  if (passwordForms > 0 && pageUrl.protocol !== "https:") {
    add(
      findings,
      "password_input_on_http",
      "high",
      "Password input appears on a non-HTTPS page",
      `The supplied HTML contains ${passwordForms} password input(s), while the page URL uses HTTP.`,
      "Serve the entire login flow over HTTPS and redirect HTTP requests to HTTPS."
    );
  }

  if (insecureFormTargets > 0) {
    add(
      findings,
      "https_page_posts_to_http",
      "high",
      "A form on the HTTPS page targets HTTP",
      `The supplied HTML contains ${insecureFormTargets} form action(s) that resolve to HTTP.`,
      "Submit forms only to HTTPS endpoints and verify the destination origin."
    );
  }

  if (externalFormTargets > 0) {
    add(
      findings,
      "external_form_destination",
      "medium",
      "A form submits to a different origin",
      `The supplied HTML contains ${externalFormTargets} form action(s) whose origin differs from the page origin.`,
      "Confirm that every cross-origin form destination is an intended, trusted service. This signal alone does not prove malicious behaviour."
    );
  }

  const mixedResourceMatches = html.match(/(?:src|href)\s*=\s*(?:"http:\/\/[^"]*"|'http:\/\/[^']*'|http:\/\/[^\s>]+)/gi) || [];
  if (pageUrl.protocol === "https:" && mixedResourceMatches.length > 0) {
    add(
      findings,
      "mixed_content_references",
      "medium",
      "HTTP resources are referenced by an HTTPS page",
      `The supplied HTML contains ${mixedResourceMatches.length} HTTP src/href reference(s).`,
      "Load required scripts, stylesheets, images and other resources over HTTPS, or remove resources that are no longer needed."
    );
  }

  const inlineScripts = html.match(/<script\b(?![^>]*\bsrc\s*=)[^>]*>/gi) || [];
  if (inlineScripts.length > 0) {
    add(
      findings,
      "inline_script_present",
      "info",
      "Inline JavaScript is present",
      `The supplied HTML contains ${inlineScripts.length} inline script block(s). This is an inventory signal, not proof of a vulnerability.`,
      "Prefer nonce- or hash-based Content Security Policy controls where practical."
    );
  }

  return findings;
}
