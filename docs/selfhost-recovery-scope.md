# Self-host recovery scope preflight

Before an upgrade or restore rehearsal, render the complete Compose model from
the exact extracted bundle. From a matching Marty UI qualification checkout,
run `scripts/check_selfhost_recovery_scope.py` against that model and the
intended `SELFHOST_STATE_DIR`. This Python checker is not bundled for customers.
The existing
prepared-consumer and runtime-DAG checks must first verify the bundle, image
lock, and complete service model. This check records the Compose model hash and
rejects any writable bind or named volume outside the reviewed Postgres, Redis,
and Applicant state paths. The selected state root and its three data
subdirectories must be direct paths, without symlinks.

```bash
docker compose --env-file .env.selfhost.production.local \
  -f docker-compose.yml --profile beta-tunnel \
  config --no-env-resolution --no-path-resolution --no-consistency \
  --format json > compose-model.json
python /path/to/marty-ui/scripts/check_selfhost_recovery_scope.py \
  --compose-model compose-model.json --state-root "$SELFHOST_STATE_DIR" \
  > recovery-scope.json
```

The report is explicitly **unqualified**. It proves only the reviewed writable
Compose mount boundary. It does not snapshot a running PostgreSQL database,
capture Redis consistency, export OpenBao, preserve operator secrets, restore
state, or show that an older release can upgrade safely. Keep OpenBao state or
its protected export, environment settings, and the secret directory in the
recovery plan. A disposable exact-artifact upgrade, restore, and business
journey must pass before claiming customer recovery support.
