# Shared migration bootstrap Rust port

This isolated branch implements the shared bootstrap owner in
`marty-signing-keys`. It is held outside the beta and production release paths
until the signed v1.1.244 boundary and review gates complete. The existing
Python owner and shell invocation are still active.

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

The first follow-up after signed v1.1.244 is to build this binary into the
shared migration image, switch the guarded shell wrapper from Python to the
Rust binary, and run local, release-image, beta, and notification sequencing
gates. Once those pass, remove the superseded Python bootstrap files and
wheel dependencies. This branch does not modify CI/CD workflow files or the
separate pure-KMS hardening work.

The corpus intentionally does not exercise a real PostgreSQL/OpenBao/Redis
installation. Adapter-specific tests and beta acceptance remain release gates
before deleting the Python runtime. No real CSCA or DSC files are required;
the disposable ICAO fixture is a precreated, non-exportable OpenBao key pair
scoped to the protected local acceptance tuple.
