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

## Accepted Core dependency

Production manifests, the standalone feature probe, both lockfiles and the KMS
custody guard agree on accepted Core `64601c9513850e3eb60b00f6aa893cae8d9e4b0d`.
`ElevenID/marty-core#445` merged through the normal protected queue on
2026-11-20. Its tree `eb4c1c179bfdf2c993278c6d8e2cac4a14f0f668` exactly matches
the reviewed Core candidate and retains the authenticated status work accepted
in `ElevenID/marty-core#443`.

Core consumes accepted SD-JWT fork `ba5a9a154ae530ddcfcc5b52adf3da71e91b1929`
from `ElevenID/sd-jwt-rust#47`. The additive Core digest-selection APIs retain
SHA-256 in existing entrypoints. This source pin does not change product
profiles, request shapes, admitted algorithms or opaque external-signing
boundaries. Both lockfiles preserve registry package versions and checksums,
and the selected Core feature sets remain unchanged.

The consumer's required checks and normal protected integration remain its
acceptance gates. Local verifier and transport tests do not establish
official-suite or deployed-product acceptance.
