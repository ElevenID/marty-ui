# Exact-bundle Organization runtime continuation (unqualified)

`scripts/probe_selfhost_installed_organization.py` is an opt-in continuation
of the prepared consumer, after exact producer/artifact binding, extracted
runtime DAG planning, bootstrap handoff, and the signing/JWKS probe. It accepts
the same archive, image lock, transaction, receipt, descriptor, extracted root,
source SHA, and run ID arguments as the
[migration probe](selfhost-scoped-installed-migration-probe.md). It is not an
ordinary CI or release gate and always reports `qualification: unqualified`.

The probe repeats the exact-bundle checks and runs the scoped migrations twice
on a private, disposable PostgreSQL/Redis/OpenBao network. It selects
`organization` solely from the verified image lock's `services` repository
digest, pulls its Linux/amd64 image, and checks the selected local platform and
repository-digest association. A closed Compose overlay starts the baked
Organization dispatcher and secret loader with the migrated DB, Redis database
2, and a generated service token distinct from the migration and OpenBao
secrets. It adds no source build, host port, persistent volume, operator mount,
or OpenBao root token. The rendered topology and secret paths are checked
exactly before startup. Both the overlay and migration fixture tear down their
owned project even when a runtime read fails.

After health, the probe reads `GET /v1/organizations` with the generated
`x-service-token` and requires the migrated Marty organization ID/name/status;
the same DB-backed route must reject missing and incorrect service tokens with
401. This is a bounded installed-image startup, seeded data read, and HTTP
service-authentication witness. The absent Event Stream peer may be reported
as degraded: it is optional to Organization readiness and this probe makes no
event-delivery claim. It does not prove Organization gRPC consumers, Gateway
authentication, a complete Compose stack, an issuer/customer journey, third-
party provenance, an independent customer install, or release eligibility.
An opt-in current-main Stack release must first produce a unique prepared ZIP
and qualified Stack transaction; stale or missing artifacts fail closed.
