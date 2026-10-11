# Exact-bundle signing-key runtime continuation (unqualified)

`scripts/probe_selfhost_installed_signing_keys.py` is opt-in. The downstream,
unqualified prepared-consumer workflow runs it after a successful opt-in Stack
release against an exact same-SHA
bundle; it is also available locally. It
accepts the same exact archive, lock, transaction, receipt, descriptor,
extracted root, source SHA, and run ID as the [scoped migration
probe](selfhost-scoped-installed-migration-probe.md). It is not part of an
ordinary CI or release gate and always reports `qualification: unqualified`.

The same downstream workflow first runs
`scripts/probe_selfhost_installed_bootstrap.py` against the verified extracted
bundle. It starts one owned, digest-pinned disposable OpenBao with no host
ports, invokes the shipped bootstrap helper, checks three distinct scoped
tokens in an external private temporary directory, and verifies cleanup of
both owned containers. Its separate sanitized report is also unqualified.
The helper runs its Linux CLI container as the invoking user and replaces
placeholder token files through private atomic writes. A successful handoff
does not qualify the production Compose stack, login, or an issuer journey.

The script first repeats that probe's exact-bundle and disposable migration
checks. It takes `signing-keys` only from the verified image lock, pulls its
exact `services` digest for Linux amd64, and checks the selected local image's
platform and repository-digest association. A closed Compose overlay starts
only the shared-services image as `signing_keys` on the existing private
disposable network, without source builds, host ports, persistent volumes, or
the OpenBao root token. It uses three distinct generated API credentials,
its own OpenBao token with the reviewed credential-service and
signing-keys-managed policies, and a separate verify-only signing-grant
token minted by the disposable bootstrap. The grant token cannot mint HMACs;
the probe does not exercise a signing operation. After health, it reads the migration-seeded public JWKS for the
fixture organization and confirms that another organization has no keys.
The complete overlay is torn down even if the runtime read fails.

This proves a bounded installed-image startup and public-key data read, **not**
full-stack readiness, Gateway authentication, a customer verification or
issuance journey, third-party image provenance, a fresh independent install,
or release eligibility. `/health` alone is insufficient evidence: the JWKS
read is what exercises the service's Redis-backed document store.
