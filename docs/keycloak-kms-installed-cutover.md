# Installed KMS-only cutover

## Boundary and decision

The non-public `elevenid-beta` and `marty-selfhost-prod` installations must
be replaced as complete stacks. Do not perform an in-place Keycloak database
swap. Direct runtime inspection on 2026-10-16 found:

| Installation | Running OpenBao storage | Keycloak local key material |
| --- | --- | --- |
| Beta | `inmem` (`server -dev`); its `openbao_data` volume is not the key store | Four `privateKey` and four generated `secret` KeyProvider rows |
| Self-host | `file` on a host bind mount; not Raft | Four `privateKey` and four generated `secret` KeyProvider rows |

The generic Keycloak `component_config` table is required and remains.
The released model instead requires fresh Raft OpenBao, non-exportable remote
keys, scoped tokens, clean Marty and Keycloak databases, and the matched Rust
services. Do not copy private-key rows, old OpenBao state, or local keys. No
database migration script is required. Existing accounts and sessions are
not carried into the new non-public installation; plan operator and test-user
re-enrolment explicitly.

## Prepare the parallel stack

1. Resolve one published Stack transaction, every image by immutable digest,
   the matched Keycloak provider image, and the signed self-host bundle and
   image lock. Reject any unqualified preview or mixed release. The
   `v1.1.248` candidate is not yet a published installed qualification.
2. Create distinct Compose project names, empty PostgreSQL/Redis/applicant
   and OpenBao Raft state roots, and a private secret root. Set unique loopback
   ports for the new OpenBao, Keycloak, Gateway, and edge. Render the full
   Compose model and compare the project, mounts, ports, images, and secret
   references against the approved manifest before starting anything.
   `docker-compose.selfhost.prod.yml` and
   `docker-compose.selfhost.openbao.yml` expose the relevant
   `SELFHOST_*_HOST_PORT` and `SELFHOST_OPENBAO_STATE_DIR` inputs.
3. Keep the old stack running and out of the new project's network. In
   particular, do not stop beta OpenBao: its in-memory KMS state would be
   lost. Do not enable the old fixed-name beta proxy or tunnel containers
   in the parallel project; their `container_name` values collide. Use
   the new loopback edge for pre-switch tests.
4. Initialize fresh OpenBao Raft and remote keys with the matched plugin
   image, scope each workload token, and provision public certificates and
   CA material. Workload TLS private-key files are prohibited. The
   OpenBao-owned HTTPS listener bootstrap key stays confined to OpenBao.
   Start fresh PostgreSQL, run the Rust-only Marty schema, import the checked-in
   clean Keycloak realms, run configurators, and then start native services.
   No old database or KMS volume is mounted in this new project.

The exact published bundle, environment and fixture inputs must pass
`scripts/run_selfhost_business_journey.py`'s preflight. That runner requires
an empty project and state root, but its result alone does not establish KMS
custody or supported publication.

## Acceptance before traffic moves

- Verify OpenBao reports `storage_type=raft`, the expected plugin and
  non-exportable versioned keys, scoped token policies, HTTPS trust, and
  recoverable Raft snapshot/restore. Rehearse recovery against a disposable
  isolated target, including the corresponding database and service state.
- Run `scripts/sql/keycloak-kms-only-verify.sql` against the new Keycloak
  database after both realms have issued and refreshed tokens. Require zero
  private-key fields, PEM markers, private-key-named schema objects and
  generated local secrets. Independently scan the fresh Marty schema and
  representative runtime writes. A clean catalog alone is insufficient.
- Exercise master and `11id` login, PKCE browser session reuse, refresh,
  JWKS, CIBA, rotation, and denial when relevant KMS tokens/keys are lost.
  Verify workload mTLS with only remote signer references and public
  certificate/CA inputs. Exercise native issuance, DIDComm holder decryption,
  integration-secret rotation/recovery, reference-only BYOK, and the
  installed issue/present/revoke journey using the exact release images.
- Record the signed artifact identities, database custody output (counts
  only), Raft status and restore result, negative KMS-loss cases, and the
  installed journey result in the canonical hardening tracker. Do not
  present the synthetic CIBA callback or local mock wallet as physical-device
  acceptance.

AWS, Azure, GCP and physical wallet/device access is not provisioned. Their
real-provider and physical-device gates remain open even if this local
installed acceptance passes.

## Switch, rollback and retirement

After acceptance, switch the external edge to the new loopback edge under a
deployment lock. Keep the old stack, including beta OpenBao, running and
isolated for a short, defined rollback window. If the new journey or custody
gate fails, route traffic back to the unchanged old edge; do not copy old
private-key data into the new stack. Rehearse the actual edge reversal and
record both endpoint identities before declaring the switch supported.

When the new stack and its recovery rehearsal have passed for the full
window, retire the old services and private-key-bearing Keycloak database,
and verify no old key-bearing volume, table or workload key file remains
available in the active deployment. The emergency route back to the old
stack is temporary recovery, not an allowed long-term local-key fallback.

## Evidence already obtained and limits

- Read-only `pg_dump -Fc` from each installed Keycloak database restored
  into network-isolated disposable PostgreSQL 15. Beta source/restore each
  had 16 users; self-host each had five. Both retained the four-plus-four
  local key rows. This proved isolated database restore only, not coordinated
  KMS recovery or a clean cutover.
- The shared read-only SQL verifier rejects both installed databases and
  passed a disposable two-realm remote-provider graph. It also rejected an
  unrelated `private_jwk` component field and `private_key_cache` table.
  A local disposable Keycloak/OpenBao probe passed remote RS256,
  browser/session, CIBA, refresh/JWKS and KMS-loss checks, then the revised
  custody gate. These were locally built images, not the signed installed
  release.
- A database-only beta swap/reversal prototype passed a disposable
  PostgreSQL rehearsal and was then removed from this branch after the
  installed `inmem`/`file` findings. The old beta backup captured an
  `openbao_data` volume that was not beta's active key store; it cannot
  recover a stopped beta OpenBao process. The old restore script also does
  not restore the new Raft/token-volume set. Do not use either old operation
  as evidence of supported rollback.

All disposable database and Keycloak/OpenBao test containers were removed.
A few synthetic temporary backup marker files remain under the OS temporary
directory because automatic approval review rejected their deletion; they
contain no real database or key data.
