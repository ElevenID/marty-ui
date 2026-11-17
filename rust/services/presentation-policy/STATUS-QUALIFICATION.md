# External credential status qualification

Public HTTPS is the default. Credential/request JSON and trust profile documents cannot grant private-address access or TLS trust.

An isolated development/test deployment may set both `PRESENTATION_POLICY_STATUS_FIXTURE_ORIGIN` (one canonical HTTPS origin, including its explicit port if needed, without a trailing slash) and `PRESENTATION_POLICY_STATUS_FIXTURE_CA_FILE` (a PEM certificate bundle, at most 256 KiB). Missing pairs, invalid origins/certificates and beta/production use fail startup. The runtime reads the CA once. Only that exact origin receives private-address permission and CA-only trust; other destinations retain the public-address policy and normal roots. TLS hostname verification, DNS address pinning, proxy bypass, redirect refusal and request/body limits remain enforced. This configuration grants transport permission, not status signer authority.

The opt-in loopback probe generates temporary TLS keys/certificates, starts only its owned loopback listener, and runs the explicitly ignored Rust test. It needs Python with `cryptography`, Cargo and the locked Rust build dependencies already available. From the service directory:

```sh
cargo test --offline --locked -p marty-presentation-policy --lib --no-run
python tests/fixtures/status_https_probe.py
```

The probe uses an unusable proxy setting in the Cargo child only. It verifies real HTTPS for valid/revoked signed JWTs and rejects default private access, redirects, content/type bounds, expired/bad signatures, a wrong CA and a hostname mismatch. It checks exact request counts and closes the owned server; generated private keys are never recorded in source or reports. Do not run against an existing installation.

This is transport/codec evidence. Complete native presentation acceptance, mdoc CWT status and identifier-list handling, qualified product artifacts and unchanged official verifier reruns are separate requirements. Test-only registration or loopback trust does not establish production issuer or registrar authority.
