# Next aggregate beta: acceptance checklist

Source-readiness audit: integration `57384f431`. This is a pending checklist,
not a release reservation, deployment authorization for production, or an
acceptance claim. Historical beta 1.1.217 evidence cannot qualify a new candidate.
No candidate coordinate is selected here.

1. Land the complete intended source through exact-head maintainer review and
   protected CI, including Linux base/Envoy/Kubernetes consumer gates. Reconcile
   component pins explicitly; do not implicitly select another worker's crypto
   changes. Resolve remaining consumer migrations before claiming whole-goal
   completion. Keep DIDComm KMS redesign separately deferred.
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
4. Explicitly hold `BetaOrigin` at `https://beta.elevenidllc.com`. The wrapper's
   HTTPS syntax check alone does not establish that an origin is beta. Retain
   fixed beta Compose projects/network and labeled-volume ownership checks.
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
