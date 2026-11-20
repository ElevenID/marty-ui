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

## Current dependency candidate

Production manifests, the standalone feature probe, both lockfiles and the KMS
custody guard agree on Core `955d51730ae4b3f1dda2e6cea99903c1ba27c51d` from
`ElevenID/marty-core#443`. Cargo resolution retains every registry package
version and checksum from the accepted-main merge. The source pin remains a
review candidate while Core #443 is unmerged: protected Core integration, a
repin to the accepted checkpoint and the consumer's required checks must precede
normal integration of these status changes. Local verifier and transport tests
do not establish official-suite or deployed-product acceptance.
