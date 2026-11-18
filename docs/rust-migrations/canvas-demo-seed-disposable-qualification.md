# Canvas demo seed Rust qualification

The Rust seeder is packaged at `/usr/local/bin/marty-canvas-demo-seed` in the migrations image. Its intended journey covers Canvas LMS, platform, binding, badge template, signed AGS, wallet, and mirror operations. The Make target now invokes this runner; full isolated and beta journeys remain release gates.

## Disposable project

Run this on a dedicated Linux Docker daemon with at least 32 GB RAM and 20 GB free disk for the full Marty dependency graph and Canvas LMS. The `up` command refuses a daemon with any unrelated running container. The overlay gives the test its own Compose project, network, Canvas container names, and volumes. Only the gateway, Canvas LMS, and Keycloak publish loopback ports (`18000`, `18088`, and `18180`). The local issuance bridge serves Canvas metadata on the same localhost port inside issuance. The harness refuses a project name outside `marty-canvas-disposable-*`, validates local endpoints before `up` or `seed`, and checks the Canvas container's Compose project label before seeding. It never joins the beta or self-host production network.

1. Copy `config/canvas/disposable-seed.env.example` to `.env.canvas-disposable.local` and keep the latter untracked. Set only credentials created inside this disposable stack. In particular, create an organization actor key with Canvas integration read/write scopes there and replace `MARTY_API_KEY`. Do not copy a beta or production key.
2. Run `bash scripts/qualify-canvas-seed-disposable.sh config` to validate the Compose model.
3. Run `bash scripts/qualify-canvas-seed-disposable.sh up`. Compose starts the gateway's dependent services, database migrations, OpenBao bootstrap, issuance, signing keys, Canvas LMS, and Canvas Credentials sandbox. Wait for their health. The Canvas image is resource intensive; allow at least the capacity documented in `docs/canvas-real-test-environment.md`.
4. On the same isolated host, run the UI from `ui/` with `VITE_API_URL=http://localhost:18000 npm run dev -- --host 127.0.0.1`, using Node 24 and the pinned dependencies. Create the disposable organization actor key with Canvas integration, application, and credential scopes through the local organization console. Replace the placeholder `MARTY_API_KEY` in the env file. Check that the migration-created OpenBao issuer profile resolves through the signing registry with an active key reference. No external CA or physical signer files are required for this local demo.
5. Run `bash scripts/qualify-canvas-seed-disposable.sh seed`. The script requires internal gateway, issuance, signing registry, Canvas, and wallet URLs and rejects database overrides. The wallet claim uses the public OID4VCI offer, token, and credential endpoints; its holder proof comes from the same KMS-backed signing service endpoint used by the Gateway VC-API bridge. Set `SIGNING_KEYS_HOLDER_PROOF_BASE_URL` to a direct, reachable signing-keys service URL when wallet claiming is enabled; the seeder rejects a missing value before changing the demo. It mounts the Docker socket only for this one-shot runner because the Canvas Rails bootstrap uses `docker exec`; the runner exits afterward.
6. Run the seed command a second time to verify idempotence. Capture the CLI summary, Canvas course/learner/tool/quiz, issuer profile, approved AGS policy, issued credential, wallet claim, and mirror delivery/provenance. Replay the same Canvas launch from the browser and retain the local qualification recording. The public YouTube demo is recorded against beta after the signed aggregate deployment.
7. Run `bash scripts/qualify-canvas-seed-disposable.sh down` after evidence capture to remove only this project's containers and volumes.

The example env deliberately contains a placeholder organization actor key. `seed` fails before any mutation until it is replaced. A working isolated organization actor and issuer profile have not yet been provisioned in this worktree, so the complete journey and recording are still pending. This machine's Docker daemon has 16 GB total memory and hosts beta and self-host production; the full run requires a separate runner. Keycloak is exposed on loopback in the overlay, but browser login and actor creation still require qualification on that runner. The migrations image build and `marty-canvas-demo-seed --help` smoke pass; they do not establish functional parity by themselves.

## Release gates

- Run `MARTY_CANVAS_SEED_REQUIRE_DATABASE_TEST=1` and `MARTY_CANVAS_SEED_TEST_DATABASE_URL` against disposable PostgreSQL in the hosted Rust contracts lane. The test checks current and optional legacy schema upsert, rollback, and transition lookup.
- Recheck the image build, disposable two-run journey, local Canvas launch, wallet/mirror result, and demo recording at the exact PR head.
- Obtain independent maintainer review with no P1–P3 findings on the Rust target and Python deletion before merging.

## Retired manual helper scope

The eight unreferenced root `scripts/*.rb` snippets are retired at Git checkpoint
`b78bd98ac`. They performed Canvas admin/pseudonym lookup and initialization,
LTI developer-key and course/tool/learner bootstrap, development key/token minting,
and session inspection. Their hardcoded beta defaults and identifiers are not
current configuration or a supported provisioning contract.

The supported implementation owner remains `rust/crates/canvas-demo-seed`.
Its `assets/canvas_lti_setup.rb` and `assets/mint_canvas_admin_token.rb` are still
embedded by the Rust Rails adapter and used by the actual seed runner; neither
asset is removed. Existing Rails, CLI, disposable ownership and idempotence tests
remain. Removing loose snippets does not declare the pending two-run disposable
journey, browser launch, wallet/mirror behavior or recording complete.

Admin/session troubleshooting remains a potential operator feature, not an
implemented replacement CLI. If needed, add a bounded, authorized diagnostic to
the current owner with explicit disposable/tenant scope and secret-safe output.
Do not recreate standalone credential minting or a hardcoded shared environment
as a shortcut. The seeder's existing controlled token/bootstrap paths remain.
