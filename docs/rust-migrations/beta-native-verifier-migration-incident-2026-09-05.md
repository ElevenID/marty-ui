# Beta native verifier migration checkpoint — 2026-09-05

## Outcome and scope

Aggregate `v1.1.214`, source `24f5d5dc0bb47d3dadb118b4dbe45191c5cf71b1`,
deployed successfully to beta at **2026-09-05T00:37:57Z** on attempt 03.
Local and tunneled UI/services release markers, issuance discovery and nonce
probes passed. All 29 production container invariants were unchanged.
This is deployment evidence, not full credential/demo acceptance or soak completion.

The explicitly authorized dedicated pilot verifier client is restricted to org
`00000000-0000-0000-0000-000000000001` and seeded issuer
`did:web:beta.elevenidllc.com:orgs:marty`, without public DID fallback. Existing
configuration and database governance profiles were preserved. Its secret remains
only in local beta configuration; neither secret nor its hash is published here.
Live Rust probes rejected missing/wrong API keys on all three protected routes,
rejected mismatched verifier/presentation-definition bindings, and accepted a
correctly scoped short-lived session. Full credential acceptance remains required.

## Failure and correction

Attempt 01 stopped during rehearsal because the governance registry was absent.
After provisioning, attempt 02 reached live cutover but the verifier failed
closed: `verification_sessions table is missing`. Compose declared the right
native migration dependency, but the beta runner explicitly ran only UI and
issuance migrations, then started applications with `--no-deps`.

The released Rust migration was run twice against a restored quiesced beta backup
and then applied to beta, reaching revision `202608091200`. Neither the session
table nor its migration history existed previously. No handwritten replacement
SQL or readiness bypass was used. Attempt 03 then passed the unchanged immutable
release wrapper. The release source/artifacts were not rewritten or republished.

The runner correction uses one helper for rehearsal and live migration. Official
mode uses the attested services digest; local mode builds the actual runtime
before rehearsal and pins its image ID in the final Compose override. Rehearsal
runs twice before maintenance; live migration follows the quiesced backup and
precedes application startup. Errors propagate; credentials are passed through
the child environment and the previous process environment is restored.

Regression coverage exercises the actual PowerShell helper for immutable/local
image references, mutable-tag rejection, Docker command construction, failure
propagation and environment restoration, plus the rehearsal/live ordering.
CI requires PowerShell so these executable contracts cannot silently skip.
The focused deployment/soak suite passed 78 tests. The actual helper also ran
against two isolated restored backups (missing schema and already at head):
OCI migration and repeat, local image-ID execution, incompatible-history
rejection and parent-environment restoration all passed. These checks did not
modify the live beta or production databases. A complete local-snapshot rebuild
was not performed as part of this operational correction.

## Evidence and remaining gates

Local retained evidence under the exact release worktree:

- `tests/artifacts/beta-v1.1.214-attempt-02/verification-migration-supplement-audit.json`:
  restored-backup rehearsal, idempotent repeat, live head and production invariant.
- `tests/artifacts/beta-v1.1.214-attempt-03/beta-deployment-audit.json`:
  success; SHA-256 `b223629aece8c869a6c3a5d2b035b6ca5f3a9fcfb9901e78b111b06c6ea82738`.
- Attempt 03 `deployed-demo-manifest.json`: `DEPLOYED_PENDING_EVIDENCE`.
- Attempt 03 `soak/20260905T0040Z.json`: first post-cutover sample passed;
  the recorded `captured_at`, not its filename, is the observation time.

Keep beta on the verified aggregate while completing demos (including Keycloak
theme), full credential/browser acceptance and governed seven-day event-stream /
fourteen-day revocation-profile windows. Do not promote production or count a
single passing sample as a completed soak. Remaining Canvas worker parity,
consumer routing and protected cleanup are still in the migration goal.
