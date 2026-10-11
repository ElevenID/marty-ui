# Local draft: scoped installed-bundle migration probe

`scripts/probe_selfhost_installed_migrations.py` is an opt-in, local-only
experiment. It is not called from CI or release workflows and always reports
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

The probe rechecks the exact ZIP, descriptor, receipt, lock, and extracted
inventory. It takes the migrations, PostgreSQL, and Redis images only from the
bundle lock. The separate OpenBao 2.5.2 pin has an explicit Linux amd64,
disposable self-host migration scope and is checked against the registry index.
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
