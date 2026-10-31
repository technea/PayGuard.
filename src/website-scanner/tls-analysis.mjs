const WEAK_TLS_PROTOCOLS = new Set(["TLSv1", "TLSv1.1"]);
const EXPIRY_WARNING_MS = 30 * 24 * 60 * 60 * 1000;

function addFinding(findings, finding) {
  findings.push({
    source: "tls_handshake",
    evidenceType: "observed_connection_metadata",
    ...finding
  });
}

/**
 * Converts metadata from Node's verified TLS socket into deterministic,
 * evidence-backed findings. It never accepts a caller-supplied "secure" flag.
 */
export function analyzeTlsConnection(metadata, now = Date.now()) {
  if (metadata === undefined || metadata === null) return {
    status: "not_observed",
    protocol: null,
    certificate: null,
    findings: []
  };

  const findings = [];
  const protocol = typeof metadata.protocol === "string" ? metadata.protocol : null;
  const certificate = metadata.certificate && typeof metadata.certificate === "object"
    ? metadata.certificate
    : null;

  if (metadata.authorized === false) {
    addFinding(findings, {
      id: "tls_certificate_validation_failed",
      category: "tls_certificate",
      severity: "high",
      confidence: "high",
      title: "TLS certificate validation failed",
      evidence: typeof metadata.authorizationError === "string"
        ? metadata.authorizationError.slice(0, 300)
        : "The TLS client did not authorize the peer certificate.",
      remediation: "Install a valid certificate for this hostname from a trusted certificate authority and correct the certificate chain."
    });
  }

  if (protocol && WEAK_TLS_PROTOCOLS.has(protocol)) {
    addFinding(findings, {
      id: "deprecated_tls_protocol",
      category: "tls_configuration",
      severity: "high",
      confidence: "high",
      title: "The server negotiated a deprecated TLS protocol",
      evidence: `Negotiated protocol: ${protocol}`,
      remediation: "Disable TLS 1.0 and TLS 1.1. Prefer TLS 1.3 and retain TLS 1.2 only where compatibility requires it."
    });
  } else if (protocol && !["TLSv1.2", "TLSv1.3"].includes(protocol)) {
    addFinding(findings, {
      id: "unrecognized_tls_protocol",
      category: "tls_configuration",
      severity: "medium",
      confidence: "medium",
      title: "The negotiated TLS protocol could not be classified",
      evidence: `Negotiated protocol: ${protocol}`,
      remediation: "Review the server's TLS configuration and allow only currently supported protocol versions."
    });
  }

  if (certificate) {
    const validTo = Date.parse(certificate.valid_to || "");
    const validFrom = Date.parse(certificate.valid_from || "");
    if (Number.isFinite(validTo)) {
      if (validTo <= now) {
        addFinding(findings, {
          id: "tls_certificate_expired",
          category: "tls_certificate",
          severity: "high",
          confidence: "high",
          title: "The TLS certificate is expired",
          evidence: `Certificate notAfter: ${new Date(validTo).toISOString()}`,
          remediation: "Renew and deploy the certificate, then verify that the complete certificate chain is served."
        });
      } else if (validTo - now <= EXPIRY_WARNING_MS) {
        addFinding(findings, {
          id: "tls_certificate_expiring_soon",
          category: "tls_certificate",
          severity: "medium",
          confidence: "high",
          title: "The TLS certificate expires within 30 days",
          evidence: `Certificate notAfter: ${new Date(validTo).toISOString()}`,
          remediation: "Renew the certificate before its expiry and confirm automated renewal is functioning."
        });
      }
    }

    if (Number.isFinite(validFrom) && validFrom > now) {
      addFinding(findings, {
        id: "tls_certificate_not_yet_valid",
        category: "tls_certificate",
        severity: "high",
        confidence: "high",
        title: "The TLS certificate is not yet valid",
        evidence: `Certificate notBefore: ${new Date(validFrom).toISOString()}`,
        remediation: "Check certificate issuance dates and server clock synchronization, then deploy a currently valid certificate."
      });
    }
  }

  const cipherName = typeof metadata.cipher?.name === "string"
    ? metadata.cipher.name.slice(0, 120)
    : null;

  return {
    status: metadata.authorized === true ? "verified" : metadata.authorized === false ? "verification_failed" : "incomplete",
    protocol,
    cipher: cipherName,
    certificate: certificate ? {
      subject: typeof certificate.subject?.CN === "string" ? certificate.subject.CN.slice(0, 253) : null,
      issuer: typeof certificate.issuer?.CN === "string" ? certificate.issuer.CN.slice(0, 253) : null,
      validFrom: Number.isFinite(Date.parse(certificate.valid_from || "")) ? new Date(certificate.valid_from).toISOString() : null,
      validTo: Number.isFinite(Date.parse(certificate.valid_to || "")) ? new Date(certificate.valid_to).toISOString() : null,
      fingerprint256: typeof certificate.fingerprint256 === "string" ? certificate.fingerprint256.slice(0, 128) : null
    } : null,
    findings
  };
}
