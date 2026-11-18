# Native KMS custody acceptance

The Rust `marty-selfhost-acceptance` target `native_kms_schema_contract` owns the
source-built database checks formerly run by the retired
`probe_kms_native_service_migrations.py` and `probe_kms_profile_runtime_schema.py`
Python scripts. The contracts CI lane compiles the exact native targets,
resolves their executables from Cargo's artifact log, and explicitly runs
`native_owners_preserve_kms_only_custody --ignored --exact --nocapture`.
A missing executable, zero executed owner tests, or failed cleanup fails the gate.

The test creates an owned disposable, digest-pinned PostgreSQL container with a
loopback-only port. Auth, Organization, Credential Template, Presentation Policy,
Flow, and Verification each receive a fresh database. Existing native repository
and migration contracts run against those databases. Verification's migration
binary runs twice and its public session columns must exist. Every native owner
must create tables and columns and pass the private-key schema and JSON/text
content scans. The shared scans live in `scripts/sql/kms-private-key-*.sql` and
are also used by maintained Python migration/installed-runtime qualification.

Deployment and Compliance Profile binaries each start twice against another
fresh database. Each startup must reach native readiness. System seed rows must
exist, exactly one migration receipt per owner must remain, and both owners
must pass the custody scans. Negative database fixtures prove the scans reject
private-key storage names, private JSON fields, nested private JWKs, and PEM
material in JSON or text.

This is source-built acceptance, not signed-release, installed-stack, or external
OpenBao qualification. It does not export keys or authorize local signing.
One-off JSON receipts are no longer generated. Existing local audit receipts and
the KMS release worker's historical records remain evidence of those runs.

# Read-only secret declaration preflight

The Rust bundle crate owns `check-selfhost-secret-closure`, replacing the unused
`check_selfhost_install_secret_closure.py` entry point while retaining arbitrary
input paths:

```sh
cargo run --locked --manifest-path rust/Cargo.toml -p marty-selfhost-bundle \
  --bin check-selfhost-secret-closure -- \
  --compose /path/to/compose.yml --catalog /path/to/secrets.json \
  --stack /path/to/stack.json --example-dir /path/to/example-files
```

It validates declared/referenced Compose secrets, catalog ownership and required
stack equality, isolated secret file paths, and regular non-symlink example
files. It reads declarations and filenames only, never example/operator secret
contents, and starts no services. Success emits the existing unqualified,
names-only receipt. Rust tests exercise source declarations, arbitrary copied
install inputs and rejection cases, and the actual extracted bundle.
This repository tool is not currently a separately distributed customer binary;
shipping an operator preflight remains a distribution requirement.
