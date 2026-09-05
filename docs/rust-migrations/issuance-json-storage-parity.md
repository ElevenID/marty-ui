# Issuance JSON storage compatibility

## Observed beta failure

Official `v1.1.215` deployed to beta at source
`1866528ab859ea7007ca34671ad80a62131fd79d` on 2026-09-05 at 02:34:56Z.
Release, public/local markers, verifier governance and the deployment's
29-container production invariant passed. The first source-bound soak sample
passed; that is not completion of the governed 7/14-day windows.

The release-bound KMS-switching recording passed the custom ElevenID Keycloak
theme and organization selection, then failed at the native token endpoint with
HTTP 500. The sanitized database error was `COALESCE could not convert type jsonb
to json`. Read-only `information_schema` inspection confirmed the deployed
`issuance_service.issuance_transactions.claims` column is `json`. The Python-owned
model also declares SQLAlchemy `JSON`. The previous Rust PostgreSQL fixture used
`JSONB`, masking the mismatch in the production query's COALESCE and CASE types.

## Rust correction and gates

The token repository retains one atomic, single-use update. Its CASE branches
now return `json`, with an explicit `jsonb` input only for `jsonb_set`. This works
with either stored type. The no-DPoP branch preserves existing JSON text rather
than unnecessarily normalizing claims. No live schema/data rewrite, dependency
change, alternate token path, weakened assertion, or Python deletion is needed.

The same PostgreSQL contract runs against both physical column types, asserts
their actual types, and deterministically tests both DPoP branches before the
existing concurrent-claim tests. It retains nested claims, Unicode, arrays,
booleans, null values and large counters; checks token HMAC storage and nonce
clearing; and rejects a second claim without changing the winner. Existing
tenant projection, authorization-code and client-assertion race checks execute
for both storage types. Only the isolated, newly created test tables are altered.

The new test failed against the unchanged repository on the real `json` shape
and passed after the fix for both shapes. Token HTTP/domain parity tests also
passed. CI, maintainer review and the protected queue remain required before
landing; a new immutable release and unchanged recording must verify the fix in
beta. Do not patch published v1.1.215, migrate its live claims column merely to
fit a test fixture, or count its partial failed recording as acceptance.

## Adjacent findings still requiring executable regression coverage

Read-only beta inspection also confirmed these Python-owned columns are `json`.
Source review found direct JSONB-only operations in their Rust consumers:

| Column | Consumer requiring review and tests |
| --- | --- |
| `canvas_lti_launch_states.metadata` | `canvas_lti_deep_linking_postgres.rs`: direct `jsonb_set(session.metadata, ...)` |
| `canvas_evidence_sync_targets.metadata` | `canvas_management_postgres.rs`: conflict-update COALESCE and concatenation |
| `canvas_platforms.connection_config` | `canvas_management_postgres.rs`: LTI readiness/configuration updates using JSONB operators |

These are open source/schema-review findings, not executed parity passes or
fixed behavior in this token patch. Reproduce each against real-schema fixtures,
fix in the shared Rust repository operations, preserve owner/generation fences
and unrelated fields, and run complete consumer gates before declaring this
storage compatibility work complete. Whole-worker migration, all-consumer
routing, feature-preserving cleanup, full demos and acceptance soak also remain.
