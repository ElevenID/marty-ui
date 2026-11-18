# Shared migration bootstrap behavior freeze

This is the historical behavior reference for the former Python `db-migrate`
job. The active owner on this branch is the shared Rust bootstrap engine.
The former Python owner was `services/run_all_migrations.py`; its exact Git
blob is recorded in `contracts/migration-bootstrap-python-reference.json`.
At the freeze, Python had `SERVICES = []`: service Alembic migrations were
already owned by their Rust jobs. The shared job creates schemas,
prepares OpenBao keys, and publishes managed identity state.

## Inputs and order

`scripts/run-migrations-with-secrets.sh` loads file secrets and requires a
database password and a non-placeholder organization administrator email. It
runs Rust, then executes `marty-notification --migrate` only after Rust
returns success. Compose `db-migrate` uses this image in beta and self-host
production; the Kubernetes job is `k8s/oracle/06-db-migrate.yaml`. The local
beta runner invokes Rust explicitly for apply and a copied-database
`--verify-only` pass.

The Python job requires `DATABASE_URL` and removes `+asyncpg` to use a
synchronous connection. It reads `MARTY_MIGRATION_PROFILE` from the released
`marty-common` wheel for summary logging. Unknown names currently get dev
settings; this job has no profile-dependent migration services left. Apply
mode then:

1. Creates `organization_service`, `auth_service`,
   `credential_template_service`, `issuance_service`,
   `presentation_policy_service`, `notification_service`,
   `device_registration_service`, and `revocation_profile_service` schemas in
   one PostgreSQL transaction.
2. Requires `BAO_ADDR` and a token; ensures the Transit mount and a
   non-exportable `aes256-gcm96` notification webhook envelope key.
3. If `MARTY_KMS_BOOTSTRAP_ENABLED` permits, derives Gateway Redis DB 2 (or
   configured `REDIS_DB_GATEWAY`), pings it up to five times at one-second
   intervals, ensures the Transit mount and flow envelope key, and reads or
   creates seven standard Marty asymmetric keys. Existing unsafe symmetric
   keys fail. Missing Transit-mount management rights (HTTP 400/403) are
   tolerated only when later key reads/creates still succeed.
4. Seeds the managed signing registry, exact-DID and legacy DID documents,
   credential JWKS, did:web slug, and six issuer profiles into Redis. It
   preserves customer services, key-purpose bindings, and nonduplicate
   profiles. It backfills mixed legacy DID methods by controller. Canvas LTI
   has an assertion method but is excluded from credential JWKS.

`MARTY_ORG_ID` and `MARTY_ORG_SLUG` select those OpenBao/Redis identifiers;
this Python job does not create an organization PostgreSQL row. Issuer DID,
URL, and domain use `MARTY_ISSUER_DID`, `MARTY_ISSUER_BASE_URL`,
`ISSUER_BASE_URL`, `PUBLIC_API_URL`, and `PUBLIC_DOMAIN` fallbacks. The optional
disposable ICAO keys require an exact project, loopback port, default org,
localhost DID/URL tuple, and precreated non-exportable OpenBao keys. They are
not external CSCA or DSC files.

The token preference differs today: the notification envelope preparation
prefers `OPENBAO_SERVICE_TOKEN` to `BAO_TOKEN`, while identity bootstrap
prefers `BAO_TOKEN` to `OPENBAO_SERVICE_TOKEN`; either may come from a `_FILE`
variable. Freeze this observed behavior before choosing a single Rust custody
policy. `MARTY_KMS_BOOTSTRAP_ENABLED=false`, absent `REDIS_URL`, or absent
`BAO_ADDR` skip identity bootstrap, but notification key preparation still
requires OpenBao in apply mode. The protected beta/self-host profiles require
the enabled path.

`--verify-only` currently performs no schema or KMS/DID checks because the
service migration list is empty. It validates the database URL's presence and
prints profile settings, then exits zero. A Rust port may add meaningful
verification, but changing this behavior must be explicit and tested.

## Corpus and Rust replay

Run `py -3.12 scripts/check_migration_bootstrap_reference.py -- <Rust binary> --reference-json` and
`py -3.12 -m pytest tests/test_migration_bootstrap_reference.py -q`.
The removed Python producer used in-memory PostgreSQL, OpenBao, and Redis adapters. No live
endpoint or secret is contacted. Its 18 JSON cases cover clean and repeated
apply, preservation of customer profiles and bindings, legacy DID backfill,
valid precreated disposable keys and an invalid tuple, token precedence,
disabled or missing Redis bootstrap, conflicting purpose bindings,
unsafe/missing notification KEK, Redis retry exhaustion, partial Redis write
followed by retry, verify-only, missing DB or token, and schema failure.
Deterministic type-correct EC, RSA, and Ed25519 public keys exercise the real
Python PEM-to-JWK conversion. Effects capture writes and retry boundaries;
incidental read order and wall-clock timestamps are excluded.

`scripts/check_migration_bootstrap_reference.py -- <candidate command>` sends
each `{name,input}` case, including its complete synthetic environment, to a
candidate process on stdin. Ambient database, Redis, and OpenBao variables
are removed from the candidate environment. The candidate emits
`{exit_codes,effects,state,error_tags}` JSON. Its adapters must be simulated;
the contract supplies only `.test` URLs. Compare exact effects and final
state, then separately test real Rust image composition and one-shot startup.
The JSON result is a historical behavior fixture. Current tests assert the
shell's `set -e`, password/admin guards, and Rust-before-notification order.

The frozen corpus records full effect order and partial-write recovery
without introducing a network dependency.
`services/common/*.py` adapters are excluded from the Rust service build and
have no repo-local runtime importers outside themselves; their tests remain
reference cases until a separate consumer and contract deletion review.
