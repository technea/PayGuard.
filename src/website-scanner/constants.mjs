export const MAX_HTML_BYTES = 256 * 1024;
export const MAX_REDIRECTS = 10;
export const MAX_HEADER_COUNT = 100;
export const MAX_HEADER_VALUE_LENGTH = 8_192;

export const SECURITY_HEADERS = Object.freeze([
  {
    name: "strict-transport-security",
    id: "missing_hsts",
    severity: "medium",
    title: "HTTP Strict Transport Security is not configured",
    remediation: "Configure Strict-Transport-Security with an appropriate max-age. Add includeSubDomains only after confirming every subdomain supports HTTPS."
  },
  {
    name: "content-security-policy",
    id: "missing_csp",
    severity: "medium",
    title: "Content Security Policy is not configured",
    remediation: "Define a restrictive Content-Security-Policy based on the resources the site actually needs. Test it in report-only mode before enforcement."
  },
  {
    name: "x-content-type-options",
    id: "missing_nosniff",
    severity: "low",
    title: "MIME-sniffing protection is not configured",
    remediation: "Set X-Content-Type-Options: nosniff."
  },
  {
    name: "referrer-policy",
    id: "missing_referrer_policy",
    severity: "low",
    title: "Referrer Policy is not configured",
    remediation: "Set a deliberate Referrer-Policy, commonly strict-origin-when-cross-origin."
  },
  {
    name: "permissions-policy",
    id: "missing_permissions_policy",
    severity: "low",
    title: "Permissions Policy is not configured",
    remediation: "Set a Permissions-Policy that disables browser capabilities the application does not need."
  }
]);
