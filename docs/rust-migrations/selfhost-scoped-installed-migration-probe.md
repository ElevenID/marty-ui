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
inventory. It takes the migrations, PostgreSQL, and Redis images only from the
bundle lock. The separate OpenBao 2.5.2 pin has an explicit Linux amd64,
disposable self-host migration scope and is checked against the registry index.
All five Compose services select `linux/amd64`; before startup the probe pulls
each distinct exact reference for that platform and checks the selected local
image's OS, architecture, and repository-digest association.
The disposable project has an internal network, no host ports or persistent
volumes, and no source builds. A root token is available only to OpenBao and
the one-shot bootstrap container; the migration receives distinct scoped
credential-service and Notification tokens. The bootstrap verifies allowed and
denied capabilities before writing those tokens to disposable files. Migration
then runs twice, with ledger and signing-registry checks, before project teardown.

This proves neither an operational external OpenBao deployment nor full stack
startup, login, issuer readiness, customer installation, provenance of third-party
images, or release eligibility. No operator credentials or secrets are needed;
the fixture generates disposable values and destroys the project afterward.
