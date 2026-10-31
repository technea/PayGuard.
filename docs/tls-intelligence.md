# TLS and Certificate Intelligence

The passive website collector records TLS metadata only for HTTPS connections it actually establishes. Node's standard TLS verification remains enabled; PayGuard does not disable certificate verification or silently accept invalid certificates.

The TLS analyzer reports:
- Certificate verification failures returned by the TLS client.
- Negotiated deprecated TLS 1.0 / 1.1 protocols.
- Expired, not-yet-valid and certificates expiring within 30 days.
- A limited certificate summary (subject/issuer common name, validity dates and SHA-256 fingerprint).

The analyzer does not independently perform a second TLS handshake, enumerate supported protocol versions, test cipher suites, inspect certificate transparency logs, or verify revocation status. A successful connection means the runtime accepted the certificate for this hostname at scan time; it is not a guarantee of overall website safety.

HTTP targets have no TLS observation. Missing TLS metadata must be represented as `not_observed`, never as a passing TLS result.
