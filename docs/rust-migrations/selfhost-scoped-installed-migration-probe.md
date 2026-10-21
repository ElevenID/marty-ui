# Scoped installed-bundle migration probe (unqualified)

`scripts/probe_selfhost_installed_migrations.py` is an opt-in experiment. The
downstream `selfhost-prepared-consumer.yml` workflow runs the signing-runtime
continuation, which includes this migration probe exactly once, against a
successful, first-attempt, opt-in Stack release preparation from the same
protected-main source SHA. It is not a release or ordinary CI gate and reports
`qualification: unqualified`.

Supply the already-downloaded prepared ZIP, image lock, transaction, receipt,
descriptor, and the extracted ZIP root from the same run:

```sh
python scripts/probe_selfhost_installed_migrations.py \
  --archive /path/to/selfhost.zip \
  --image-lock /path/to/selfhost-images.json \
  --transaction /path/to/release-transaction.json \
  --receipt /path/to/preparation-receipt.json \
  --descriptor /path/to/product-descriptor.json \
  --install-root /path/to/extracted-bundle-root \
  --source-sha FULL_40_CHARACTER_SOURCE_SHA \
  --run-id NUMERIC_RUN_ID
```

Dispatch `Stack release` on `main` with `prepare_selfhost_lock` explicitly
enabled. Its successful completion triggers the read-only-cache consumer for
that exact run; other Stack releases have no prepared bundle and skip the
probe. The consumer rejects a rerun, an artifact from another source SHA, or a
preparation from an older `main` commit. It downloads only the exact unqualified bundle and its
qualified Stack transaction, checks the archive before extraction, and uploads
a sanitized unqualified migration-and-signing probe report for 30 days. If no prepared artifact
exists for the current `main` SHA, a new opt-in preparation is required. This
does not publish a self-host product or change Stack release qualification.

The probe rechecks the exact ZIP, descriptor, receipt, lock, and extracted
inventory. It takes the migrations, Rust services, PostgreSQL, and Redis images
only from the bundle lock and requires the Issuance runtime and migration
roles to resolve to the same services image. The separate OpenBao 2.5.2 pin
has an explicit Linux amd64, disposable self-host migration scope and is
checked against the registry index.
All six Compose services select `linux/amd64`; before startup the probe pulls
each distinct exact reference for that platform and checks the selected local
image's OS, architecture, and repository-digest association.
The disposable project has an internal network, no host ports or persistent
volumes, and no source builds. A root token is available only to OpenBao and
the one-shot bootstrap container; the migration receives distinct scoped
credential-service and Notification tokens. The bootstrap verifies allowed and
denied capabilities before writing those tokens to disposable files. It also
creates a distinct verify-only signing-grant token for the later opt-in
Signing Keys consumer and a separate managed Signing Keys OpenBao token; the
migration container never mounts either token. Migration
and native Rust schema migrations then run twice. Each pass verifies the native
schema owners, the notification ledger and signing registry, and scans the
assembled database for private-key tables, columns, and content before project
teardown.

This proves neither an operational external OpenBao deployment nor full stack
startup, login, issuer readiness, customer installation, provenance of third-party
images, or release eligibility. No operator credentials or secrets are needed;
the fixture generates disposable values and destroys the project afterward.

The collected `test_actual_scoped_openbao_bootstrap` test (opt in with
`MARTY_RUN_SCOPED_OPENBAO_PROBE=1`) checks the public certificate contains no
private key and all five bootstrap tokens are nonempty and distinct from each
other and the disposable root token. It replaces the standalone HTTPS diagnostic;
installed migration qualification continues to use the maintained probe above.
