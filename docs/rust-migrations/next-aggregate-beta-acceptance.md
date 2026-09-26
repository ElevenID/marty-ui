# Next aggregate beta: acceptance checklist

Source-readiness audit: PR #814 integration branch
`feat/canvas-review-resolution-v1`; record its exact protected merge SHA before
selecting a release. This is a pending checklist, not a release reservation,
deployment authorization for production, or an acceptance claim. Historical
beta 1.1.217 evidence cannot qualify a new candidate. No candidate coordinate is
selected here.

## Protected configuration audit — 2026-09-20

- `stack-release` is restricted to protected branches, requires Burdettadam
  approval, permits self-approval, and satisfies the current protection-only
  release preflight. The current stack-release workflow requires no environment
  variable or secret values.
- `beta-lifecycle` has the required branch policy and Burdettadam reviewer. Its
  `BETA_ORIGIN` and `BETA_AUDIT_ORG_ID` variables, seeded applicant/vendor/admin
  secret names, and repository-scoped `DEMO_RECORDER_DISPATCH_TOKEN` are present.
  The recorder token is fine-grained for `ElevenID/marty-demo-recorder` with only
  **Actions: Read-only**, **Pull requests: Read-only**, and **Metadata: Read-only**
  so it can read the private run/artifact, PR issue comment, and collaborator
  permission without write access.
- `marty-demo-recorder` has the repository-scoped `DEMO_SOURCE_READ_TOKEN`
  required by private release qualification.
- `wallet-conformance` has the required branch policy and Burdettadam reviewer.
  Its bearer token is optional; the required device evidence URL and checksum
  remain dispatch inputs bound to the final release and lifecycle run.
- The legacy `beta-migration-rehearsal` environment still exists without
  values, but no current release, deployment, lifecycle, or conformance workflow
  reads it. Do not repopulate stale `MIGRATION_REHEARSAL_*` instructions. The
  current beta deployment wrapper owns backup and isolated rehearsal inputs and
  must still prove them for the selected release.

1. Land the complete intended source through exact-head maintainer review and
   protected CI, including Linux base/Envoy/Kubernetes consumer gates. Reconcile
   component pins explicitly; do not implicitly select another worker's crypto
   changes. Resolve remaining source-qualification and consumer-acceptance gates
   before claiming whole-goal completion. Keep DIDComm KMS redesign separately
   deferred.
2. Select a fresh unused aggregate coordinate. Use
   `.github/workflows/prepare-stack-tag.yml` and `cd.yml`; retain the source,
   claim/transaction and run identities. Verify annotated tag/source, complete
   checksums, signed manifest/provenance, release assets and all three OCI
   digests. Do not overwrite earlier releases or reuse their acceptance evidence.
3. From a clean released worktree, prepare one aggregate beta deployment using
   `scripts/deploy-local-beta-release.ps1 -OfficialStackRelease`, the reviewed
   recorder revision and fresh artifact paths. Verify backups, isolated
   migration rehearsal, workload identity, actual rendered configuration and
   authcrypt policy/CA pairing. `-PlanOnly` explicitly reports
   `didcomm_configuration_validated=false`; it is not runtime qualification.
   Native passport remains off until the protected passport PR chain and this
   KMS-only selector have merged, the exact beta image digest is available,
   and the runtime gates below pass. The former five-file passport overlay has
   been replaced in the integration branch by managed issuer signing, Transit
   artifact encryption, Transit callback MAC, an existing internal service
   credential handoff, and a beta-only non-physical bureau simulator. **Do not
   provision the old passport key files or select an older profile.** Render
   checks and `-PlanOnly` are not runtime acceptance.
   Resolve an active, organization-scoped `ICAO_EMRTD` X.509 document-signer
   identity created through the existing issuer UI; bind it to the passport
   job and use its managed Signing Keys/KMS reference and published certificate
   for opaque CMS/SOD signing. Configure its active public CSCA trust anchor
   through the existing Rust CSCA lifecycle import and verify the DSC chain
   before accepting a passport job. The integration branch extends the issuer
   UI to enroll a public CSCA lifecycle trust anchor against its managed CSCA
   identity, deriving the KMS key binding server-side. This is not yet merged
   or deployed. A read-only beta check on
   2026-09-26 found no CSCA lifecycle record for the pilot organization; its
   six existing issuer profiles include no `ICAO_EMRTD` document signer. This
   remains a cutover gate: obtain a valid CA/DSC certificate chain whose keys
   remain in KMS, import only the public CSCA material through the governed
   tenant-scoped operator route, and verify the active trust-anchor projection before
   starting passport issuance. Do not treat a created issuer profile or an
   attached DSC alone as proof that the chain gate is ready. The beta bureau
   is a synthetic, non-physical handoff; do not present its tracking result as
   a shipped physical document. Keep artifact encryption keys and callback MAC
   keys inside KMS. Authenticate internal provider calls without new static
   passport bearer-token files. Require signed organization identity on bureau
   callbacks and enforce that identity in job lookup. Inventory beta again
   before adding any bureau provider; do not deploy a duplicate ICAO signer.
   No native cutover or Python retirement is permitted until these gates and
   their language-neutral behavior tests pass.

   The integration branch puts callback HMAC signing on a beta-only signer
   listener; the ordinary Signing Keys and Gateway listeners have no signing
   route. Compose limits the listener to an internal network shared only by
   OpenBao and the bureau, with no published port. Before the remaining apps
   start, deployment attaches the existing OpenBao container and checks the
   live network is internal, has exactly those three running containers, and
   gives OpenBao its required DNS alias. Restore repeats that gate. These
   script and Compose checks have not yet been exercised in a beta deployment.

   The [Signing Keys public-route parity audit](signing-keys-public-parity-2026-09-26.md)
   found 24 Gateway-declared method/path pairs without Rust public handlers.
   Repair and retest those adapters before describing the aggregate beta
   release as feature-complete; the new passport certificate routes alone do
   not satisfy the no-feature-loss gate.
   A read-only Redis inventory on 2026-09-26 found zero beta and production
   managed `cred-issuer-*` bindings or active profiles for `holder_binding`,
   `presentation_signing`, or `oid4vp_request_signing`. The dedicated managed
   prefixes can therefore retain purpose isolation without a current legacy
   generic-prefix migration. Recheck both environments immediately before
   cutover; if that inventory changes, preserve exact tenant-bound live keys
   before retiring Python.

   Certificate-enrollment follow-up: the current UI has a CSR action for a
   signing service, but this source tree has no matching
   `/v1/signing-keys/services/{service_id}/certificate-csr` service route.
   The integration branch redirects the managed-service button to issuer
   identities; do not use the legacy service CSR action for the pilot chain.
   The managed OpenBao signing
   service can be shared by several issuer profiles, while each CSCA/DSC has
   its own KMS key reference. The Rust CSR operation must select the active
   issuer identity tuple, resolve its KMS custody server-side, sign the PKCS#10
   request in KMS, and verify the returned CSR against the current KMS public
   key. It must not accept a caller-supplied key reference or attach a chain
   to the shared service. The integration branch now contains a distinct
   issuer-scoped Rust PKCS#10 CSR route and UI action that verifies the
   signature against the current KMS public key. Before beta acceptance,
   exercise it against beta KMS, complete the CA issuance/chain enrollment
   path, and verify the new
   tenant-scoped operator path for public CSCA lifecycle import; no private key or raw signing
   secret may pass through the UI, repository, or deployment files.

   Read-only beta inventory on 2026-09-26 found the existing pilot
   organization active, no running or stopped ICAO signer or passport bureau
   container, and zero `issuance_service.physical_document_jobs`. There were
   zero active organization API keys. The UI/session flow can be used for
   initial operator acceptance; before claiming API-key acceptance, create an
   organization-scoped key through the existing UI/API mechanism, store its
   one-time value with the governed beta secrets (never in a repo, log, or
   chat), and verify the `credentials:issue` scope maps to passport initiation.
   No new tenant or passport-specific static keyring is required for the
   existing pilot organization. Recheck these counts at actual cutover.
   At cutover, deployment stops and verifies application writers, then requires
   zero in-flight legacy bureau jobs before switching to KMS callback
   verification. The deployment preflight rejects an existing bureau without
   the isolated signer: the current restore script cannot recover such a
   pre-isolation passport snapshot. The inventoried beta has no bureau, so
   this release is eligible for a first passport cutover only; recheck that
   condition before deployment and keep the restore constraint visible.
4. The wrapper requires `BetaOrigin` to equal `https://beta.elevenidllc.com`.
   Retain fixed beta Compose projects/network and labeled-volume ownership checks.
   Capture and compare production's exact before/after identity and state;
   beta isolation checks do not independently prove production unchanged.
   Do not deploy, restore, reset or probe mutating endpoints on production.
5. Preserve the original three deployment evidence files and package them with
   the released `beta-evidence-bundle` utility. Complete private recorder
   `release-qualification.yml`, then public `.github/workflows/e2e-tests.yml`
   with exact run/SHA/receipt hashes. Retain full browser, demo and credential
   lifecycle results, including fresh custom-themed Keycloak/KMS switching
   recordings. Portfolio qualification alone is not all-demo acceptance.
6. Complete `.github/workflows/wallet-conformance.yml` using protected evidence
   URL/hash, verified attachments and exact release/lifecycle lineage. Preserve
   genuine Spruce issuance/login recordings, signed-request capture and the
   seven native-wallet handoffs required by the catalog. Keep the inactive
   Walt.id blocker visible; do not replace device evidence with mocks.
7. Start a new uninterrupted release/source-bound soak. Existing
   `collect_rust_beta_soak_evidence.py` and `verify_rust_beta_soak_window.py`
   implement the governed 7/14-day windows and maximum 26-hour sample gaps for
   event-stream/revocation. Those samples do not cover every newly migrated
   consumer: retain separate native consumer acceptance and failure/recovery
   evidence. A host restart or release change must not be hidden by relabeling
   prior samples. Do not mark the full goal complete on a short health check.

Local unit/configuration/runtime qualification remains useful prerequisite
evidence, not proof of released image provenance, real device behavior or the
completed beta soak. Historical instructions remain in
[beta 1.1.217 follow-up](beta-acceptance-follow-up-1.1.217.md); their old source
coordinates and draft status must not be reused as current deployment state.
