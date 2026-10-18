# Disposable self-host state recovery rehearsal

`scripts/rehearse_selfhost_state_recovery.py` is an opt-in, local rehearsal of
the three writable bind mounts in the self-host Compose contract: Postgres,
Redis, and Applicant. It uses fresh temporary state and Docker containers with
unique names. It never reads or changes the operator's state tree.

Supply **complete rendered Compose JSON models** from the source and target
bundle versions. Render each with an absolute `SELFHOST_STATE_DIR` under a
disposable directory; pass those same two paths as `--source-state-root` and
`--target-state-root`. The script rejects any other writable mount, changed
mount target, symlink/junction state path, or unversioned Postgres/Redis image.
It takes the two images from each model, inserts a probe in Postgres, Redis AOF,
and the Applicant JSON file, stops both containers, copies each state tree to a
backup and then a fresh restore tree, starts the target images, and verifies
the three probes. A passing JSON report records the model hashes, version
labels, image references, and exact scope checked.

Example invocation after rendering the two bundle models:

```powershell
python scripts/rehearse_selfhost_state_recovery.py `
  --source-model C:\scratch\source-compose.json `
  --target-model C:\scratch\target-compose.json `
  --source-state-root C:\scratch\source-state `
  --target-state-root C:\scratch\target-state `
  --source-version SOURCE_BUNDLE_VERSION --target-version TARGET_BUNDLE_VERSION `
  --output C:\scratch\state-rehearsal.json
```

Use exact published bundle models and immutable image references for release
evidence. Version arguments label inputs; the report does not prove their
authenticity. The exercise starts only Postgres and Redis, not the application
stack, and therefore does **not** qualify schema migrations, the clean-install
business journey, live backup, or rollback. OpenBao state/export, operator
secrets, and environment remain separate recovery inputs and are not restored
by this script. A complete outside-party upgrade/recovery claim requires those
inputs plus a target-version application start and business journey after
restore.

For a local container smoke test of the state mechanics:

```powershell
$env:MARTY_RUN_DOCKER_RECOVERY_TEST = '1'
pytest tests/test_rehearse_selfhost_state_recovery.py -q
```

## Coordinated restored-stack verification

`scripts/verify_selfhost_restored_journey.py` is the next check after a
**quiesced, coordinated** copy of PostgreSQL, Redis, Applicant, OpenBao Raft,
operator secrets and environment into one isolated `recovery-*` root. Preserve
ownership and modes when copying OpenBao state: its TLS bootstrap rejects
copied identity files with altered ownership. Render the restored Compose
models with new disposable project names and loopback ports, then start only
the 28 local services selected by `run_selfhost_business_journey.py`; do not
start the tunnel roles. The verifier does not start or tear down containers.

Pass the recovery root, its `state`, `openbao-state`, `secrets`,
`install/selfhost-prepared`, `selfhost.env`, the isolated app/OpenBao project
names, clean exact-source and pinned integration checkouts, their commit SHAs,
and a new output path under the recovery root. Supply the same eight
`SELFHOST_*` fixture variables required by the fresh installed journey,
pointing their URLs to the restored loopback ports. The optional
`--compose-override` is for a clearly identified local candidate image; the
report records its use and the verifier's own digest. Omit the override and
run the verifier from the exact release source for signed-image qualification.

The verifier requires the exact 28-service closure, unsealed Raft, the public
issue/present/verify/revoke journey, Keycloak issuance and refresh, and both
database custody scans. Its mode-0600 JSON report remains `unqualified`:
the tool cannot establish backup provenance, a consistent source recovery
point, off-host retention, signed image identity, or cutover/rollback by
itself. Establish those independently before claiming supported recovery.
