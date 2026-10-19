# Self-host KMS credential renewal candidate

This source-level procedure is for an isolated KMS-only installation. It has
not crossed a real credential-expiry boundary and is not yet a supported
continuous-runtime or public cutover procedure. Keep the old generation until
the renewed installation passes its business and custody journeys. Neither
generation may contain local private keys.

Stage the workload TLS set with the Rust `selfhost-renew` profile against the
existing Raft OpenBao issuer and version-one Transit signers. Stage the
Keycloak set with `scripts/provision_selfhost_keycloak_kms.py` using
`SELFHOST_KEYCLOAK_MODE=renew`. Assemble a new
complete generation with `scripts/stage_selfhost_renewed_secrets.py`. Each
candidate directory must be empty and private. The assembly verifies the
same file inventory and modes, unchanged static inputs and public CA, and
changed certificates and scoped tokens. It refuses CA rollover; that needs
a separate trust-overlap procedure.

Make a private copy of the installed Compose env file, changing only
`SELFHOST_SECRET_DIR` to the assembled generation. Keep the current env file,
Compose file, and old secret root unchanged. On a Linux host with Docker and
access to the same isolated project, invoke
`scripts/activate_selfhost_renewed_secrets.py` with:

```text
--project-name <owned marty-selfhost-* project>
--compose-file <absolute rendered Compose file>
--current-env <absolute private original env file>
--renewed-env <absolute private candidate env file>
--current-secrets <absolute original secret directory>
--renewed-secrets <absolute assembled secret directory>
--bao-addr <HTTPS OpenBao address>
--bao-ca <absolute OpenBao CA file>
--bao-token-file <absolute private renewal-operator token file>
--log-dir <absolute empty private 0700 directory>
--report <absolute new file inside log-dir>
```

The command validates the generation, both live token sets, exact scoped
policies and signer/JWE access, and the Compose model before changing the
owned project. It recreates only that project, checks all expected services
and renewed secret mounts, and writes a private result report. On failure
after recreation starts, it attempts to recreate the prior **KMS-only**
generation and reports `rolled_back`; a failed rollback is an incident that
requires operator recovery. The command is not a zero-downtime switch and
does not itself run the issue/present/verify/revoke, session, database custody,
or expiry-crossing checks. Run those independently before accepting the
generation. Do not use an old local-key installation as the rollback target.
