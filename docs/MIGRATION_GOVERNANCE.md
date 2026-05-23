# Migration Governance

This document defines how Marty UI should use migrations now that we support both:

- **reset-friendly beta/dev databases**, where experimental setup is common
- **persistent self-host / production databases**, where upgrade safety matters more than convenience

## The short version

Keep using migrations, but stop treating every migration as the same kind of thing.

Use four lanes:

1. **Schema migrations** — DDL only
2. **Stable system seeds** — Marty platform records that must exist everywhere
3. **Environment/demo/test fixtures** — resettable sample data
4. **Runtime / external bootstraps** — Keycloak, OpenBao, DID/JWKS/KMS setup

## Profile model

`MARTY_MIGRATION_PROFILE` should describe the environment intent, not just whether demo data is skipped.

Current normalized profiles:

- `dev`
- `beta`
- `experiments`
- `test`
- `production`
- `selfhost-production`

General expectations:

| Profile | Demo seeds | Beta seeds | Experiment seeds | Test seeds | Experimental data fixes | Persistent? |
|---|---:|---:|---:|---:|---:|---:|
| `dev` | yes | yes | yes | yes | yes | no |
| `beta` | yes | yes | no | no | yes | no |
| `experiments` | yes | yes | yes | no | yes | no |
| `test` | no | no | no | yes | no | no |
| `production` | no | no | no | no | no | yes |
| `selfhost-production` | no | no | no | no | no | yes |

`experiments` is the preferred lane for beta-only feature demos that should not
bleed into production or self-hosted upgrade paths. The Canvas LMS/LTI demo for
`beta.elevenidllc.com` uses this lane and the `tunnel-beta-experiments` stack.
The older `beta` profile remains for compatibility with resettable beta data.

## Lane rules

### 1. Schema migrations

Schema migrations should:

- create or alter tables, indexes, constraints, enums, and views
- be forward-only once released to a persistent environment
- avoid environment-specific behavior when possible

Schema migrations should **not**:

- embed demo/test/sample data
- rely on beta-only domains or secrets
- perform runtime bootstrap work against external systems

### 2. Stable system seeds

Stable system seeds are records that are part of the platform itself, for example:

- Marty default organization
- Verified Member Badge credential template
- OpenBadgeLogin presentation policy
- Marty login trust profile
- Marty deployment profile
- Marty login flow
- default revocation profile

Stable system seeds may live in migrations **or** deterministic bootstrap code, but they must be:

- idempotent
- centrally documented
- safe for fresh DB creation
- safe for re-run in automation
- verifiable by health/readiness checks

If a stable system record is wrong in a persistent environment, **add a forward repair migration**.

### 3. Environment/demo/test fixtures

Demo, beta, and test fixtures should move toward explicit seed packs/scripts.

Examples:

- demo organizations
- demo vendor catalog data
- beta-only fixture data
- seeded test users or test-only helper records

These are allowed to be reset, re-created, or replaced as beta/dev workflows change.

Best practice:

- keep them out of persistent production upgrade history
- make them re-runnable after a reset
- scope them clearly by profile

The first extracted explicit seed pack is `scripts/seed_demo_vendor_fixtures.py`,
wrapped by `make seed-demo-vendor-fixtures` and now used by the dev/beta reset
targets as a bridge while older demo-only Alembic revisions are phased out.
Those reset targets set `MARTY_USE_EXPLICIT_DEMO_SEED_PACK=1` during migration
execution so the historical demo-only revisions are intentionally bypassed and
the explicit seed pack becomes the source of truth for resettable demo state.

### 4. Runtime / external bootstraps

External bootstrap tasks do not belong in core DB migration history.

Examples:

- Keycloak realm/config updates
- OpenBao transit setup
- Redis signing registry population
- DID document and JWKS publication

These should stay in runtime/bootstrap scripts or startup orchestration with explicit verification.

## Promotion rule

Before a feature reaches a persistent environment:

- beta migrations may be edited, squashed, replaced, or removed
- beta DBs may be reset to a new clean baseline

After a feature reaches persistent self-host / production:

- do **not** rewrite applied migrations
- do **not** rely on resets to fix shipped data
- add forward-only repair migrations instead

## Reset vs upgrade policy

### Reset-friendly environments (`dev`, `beta`, most `test`)

Preferred flow:

1. drop DB/volumes
2. run schema migrations
3. run stable system seeds/bootstrap
4. run profile seed pack (for example `make seed-demo-vendor-fixtures` for demo vendor fixtures)
5. run readiness checks

### Persistent environments (`production`, `selfhost-production`)

Preferred flow:

1. run forward migrations only
2. apply idempotent repair migrations if needed
3. verify stable system artifacts explicitly
4. never depend on destructive reset as the fix path

## Writing good stable seed migrations

Use these rules:

- prefer upsert or `INSERT ... WHERE NOT EXISTS`
- update stale fields intentionally rather than assuming the row is absent
- avoid destructive rewrites of user-owned data
- avoid hardcoded beta domains when a runtime/base URL should be derived from config
- keep stable IDs in a shared canonical module when adding new runtime-facing logic

## Choosing the right tool

When adding a change, ask:

1. Is this **schema**? → Alembic schema migration
2. Is this a **stable platform record** required everywhere? → idempotent stable seed migration or deterministic bootstrap
3. Is this **demo/beta/test fixture data**? → profile seed pack/script
4. Is this **external system configuration**? → runtime/bootstrap script

## Testing requirements

For migration-related work, test the right path:

### For resettable environments

- fresh DB reset succeeds
- profile seed pack succeeds
- rerunning seed pack is safe

### For persistent environments

- upgrade from previous release succeeds
- no duplicate stable system records appear
- expected stable records exist after upgrade
- readiness check catches missing critical artifacts

## Known repo-specific cautions

- Stable Marty IDs are architectural glue across services today; do not change them casually.
- Some historical migrations include beta URLs. New work should avoid baking environment-specific hostnames into persistent data when a template or derived runtime URL is more appropriate.
- `run_all_migrations.py` currently also performs KMS/DID bootstrap. Treat that as orchestration/bootstrap behavior, not as a reason to overload every Alembic revision with runtime concerns.

## Go-forward rule of thumb

If the database is expected to be reset regularly, optimize for **clean baseline + seed pack**.

If the database is expected to survive upgrades, optimize for **immutable history + forward repair**.
