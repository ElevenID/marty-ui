# Exact-bundle signing-key runtime continuation (unqualified)

`scripts/probe_selfhost_installed_signing_keys.py` is opt-in. The downstream,
unqualified prepared-consumer workflow runs it after a successful opt-in Stack
release against an exact same-SHA
bundle; it is also available locally. It
accepts the same exact archive, lock, transaction, receipt, descriptor,
extracted root, source SHA, and run ID as the [scoped migration
probe](selfhost-scoped-installed-migration-probe.md). It is not part of an
ordinary CI or release gate and always reports `qualification: unqualified`.

The script first repeats that probe's exact-bundle and disposable migration
checks. It takes `signing-keys` only from the verified image lock, pulls its
exact `services` digest for Linux amd64, and checks the selected local image's
platform and repository-digest association. A closed Compose overlay starts
only the shared-services image as `signing_keys` on the existing private
disposable network, without source builds, host ports, persistent volumes, or
the OpenBao root token. It uses a generated API key distinct from the scoped
OpenBao token. After health, it reads the migration-seeded public JWKS for the
fixture organization and confirms that another organization has no keys.
The complete overlay is torn down even if the runtime read fails.

This proves a bounded installed-image startup and public-key data read, **not**
full-stack readiness, Gateway authentication, a customer verification or
issuance journey, third-party image provenance, a fresh independent install,
or release eligibility. `/health` alone is insufficient evidence: the JWKS
read is what exercises the service's Redis-backed document store.
