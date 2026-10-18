# Issuer public-key resolution

Shared assertion-key resolution for issuer registration and credential signature verification. Resolving a key establishes no application trust: presentation policy evaluates its original trust profile independently after cryptographic verification.

The adapter uses the pinned core DID resolver. Network resolution is disabled by default. Presentation-policy deployments must explicitly configure `DID_RESOLUTION_BASE_URL` with deployment-owned internal mirror URLs and/or `DID_WEB_ALLOWED_HOSTS` with exact permitted HTTPS authorities. Token claims never configure these routes. The core resolver bounds response size/depth, denies redirects, and enforces public address policy for direct egress.

Only public assertion-method keys whose controller matches the resolved DID are returned. Credential verification requires exactly one key matching the issuer-owned JWT `kid`; ambiguous, private, or foreign-controller material fails closed. Existing policy-governed keys retain precedence. Failed cryptographic authentication remains retryable in Flow; this change does not relax that gate.
