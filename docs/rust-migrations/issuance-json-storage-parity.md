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
passed. Maintainer review, CI and the protected queue passed; PR #785 merged at
`895218b408f20922bda741d51886ec0744a0754f`. A new immutable release and unchanged recording must verify the fix in
beta. Do not patch published v1.1.215, migrate its live claims column merely to
fit a test fixture, or count its partial failed recording as acceptance.

## Adjacent findings subsequently corrected with executable regressions

Read-only beta inspection also confirmed these Python-owned columns are `json`.
Source review found direct JSONB-only operations in their Rust consumers:

| Column | Consumer requiring review and tests |
| --- | --- |
| `canvas_lti_launch_states.metadata` | `canvas_lti_deep_linking_postgres.rs`: direct `jsonb_set(session.metadata, ...)` |
| `canvas_evidence_sync_targets.metadata` | `canvas_management_postgres.rs`: conflict-update COALESCE and concatenation |
| `canvas_platforms.connection_config` | `canvas_management_postgres.rs`: LTI readiness/configuration updates using JSONB operators |

These were open source/schema-review findings when the token patch was authored.
PR #786 subsequently reproduced and corrected them, plus the same target
metadata column's roster-cursor write, and merged at
`fdcdf7e3b72749db29cb9cef3bf97ad1479075e4`. Complete JSON/JSONB contracts preserve
unrelated metadata, capability intent, cursor scheduling and scope/generation
fences. See [executed Canvas storage regressions](canvas-json-storage-parity.md).
The corrections are not yet verified by a new beta release/recording. Whole-worker
migration, all-consumer routing, feature-preserving cleanup, full demos and
acceptance soak remain open.
