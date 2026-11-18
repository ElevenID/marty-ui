# Shared migration bootstrap Rust port

This isolated branch implements the shared bootstrap owner in
`marty-signing-keys`. It remains outside the beta and production release paths
until the signed v1.1.244 boundary and review gates complete. The migration
image and guarded shell now invoke the Rust binary; the superseded Python
runner and its image wheel dependencies are deleted on this branch.

`bootstrap_engine::run` is the single orchestration path. Its live adapter
uses PostgreSQL, OpenBao Transit, and Redis. The in-memory adapter runs the
same engine against the frozen language-neutral JSON corpus, recording
ordered side effects and final state. Both use shared registry, DID/JWKS,
issuer-profile, and public-JWK projections. The one-shot binary is
`marty-migration-bootstrap`; `--reference-json` reads a synthetic case from
stdin and has no live endpoint access. Normal apply reads runtime environment
and `_FILE` secrets; `--verify-only` retains the Python owner's current
database-URL-only check.

Build with Rust 1.95 and compare all reference cases:

```text
cargo +1.95 build --manifest-path rust/Cargo.toml -p marty-signing-keys --bin marty-migration-bootstrap
py -3.12 scripts/check_migration_bootstrap_reference.py -- rust/target/debug/marty-migration-bootstrap --reference-json
cargo +1.95 test --manifest-path rust/Cargo.toml -p marty-signing-keys --lib bootstrap
```

The release image builds `marty-migration-bootstrap` and `marty-notification`
in Rust 1.95, copies them into Debian slim, and contains no Python interpreter
or wheels. The shell retains file-secret loading, password/admin guards, and
bootstrap-before-notification ordering. The local beta runner invokes the
same Rust binary for copied-database rehearsal, verify-only, and live apply.
This branch does not modify CI/CD workflow files or the separate pure-KMS
hardening work.

The corpus intentionally does not exercise a real PostgreSQL/OpenBao/Redis
installation. Adapter-specific tests, disposable live acceptance, and beta
acceptance remain release gates. No real CSCA or DSC files are required;
the disposable ICAO fixture is a precreated, non-exportable OpenBao key pair
scoped to the protected local acceptance tuple.

The historical Python source and producer were removed after the corpus was
committed. `scripts/check_migration_bootstrap_reference.py` compares the
active Rust binary with the immutable JSON fixture. Current KMS hardening
translates only two intentional differences in the expected result: standard
OpenBao keys now have tenant-bound names, and the managed service is derived
from live inventory instead of persisted with a mounted-token marker. The
comparison still checks ordered effects, state, failures and retry behavior
in all 18 cases. The Python
`scripts/passport_disposable_identity.py` remains demo/test tooling and is not
copied into the migration image. The separate `issuance-migrations` Compose
job already uses the Rust `marty-issuance-service migrate` owner.

## Historical local acceptance on 2026-10-11

The migration image built with `docker build -f services/Dockerfile.migrations`.
The final image had no `python` or `pip` command and no `.py` or `.whl` under
`/app`. Against isolated PostgreSQL 16, Redis 7, and OpenBao 2.5.2 containers,
the Rust apply created eight shared schemas, nine standard Transit keys,
the signing registry, DID documents, JWKS, and six issuer profiles. A second
apply through the guarded shell completed notification SQL migrations. The
disposable ICAO tuple with two precreated nonexportable EC keys succeeded;
an invalid disposable project failed closed. `--verify-only` returned zero
with `DATABASE_URL` and one without it. The corpus comparison matched all
18 cases. These are local gates; beta deployment and soak remain separate.
