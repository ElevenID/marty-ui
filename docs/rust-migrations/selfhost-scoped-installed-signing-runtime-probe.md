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

Before either runtime probe, the consumer also renders the complete extracted
Compose model with isolated state and secret roots. The unqualified
`check_selfhost_installed_runtime_plan.py` reuses the archive, descriptor,
receipt, image, and mount preflight; it then checks all 31 current roles across
the default and opt-in beta-tunnel profiles, every dependency reference and
condition, one-shot/health prerequisites, secret/config references, and acyclic
startup order. Its sanitized report binds the ZIP, lock, transaction, source,
and producer run. This is a fail-closed static runtime plan, not evidence that
the complete stack started or that its business journey passed.

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

The same opt-in consumer now follows this witness with a separate
[Organization runtime probe](selfhost-scoped-installed-organization-runtime-probe.md).
It reuses the exact bundle and disposable migrations but does not turn either
probe into a release gate or a full-stack qualification.
