# Post-deletion Rust passport beta cutover

This is the operative handoff for the first Rust-only aggregate beta release.
Run it from a clean checkout of the exact protected-main source behind the
published signed stack manifest. Keep all receipts and operator session files
outside the checkout. The target is `elevenid-beta`; production is a continuity
check and is never a deployment target.

1. Verify the published stack manifest, annotated tag, OCI digests, and the
   merged Credentials Python deletion lineage. Record the source commit and
   release run. The fence installer checks the signed release and approved
   deployed beta baseline again before it changes beta.
2. Run `scripts/install-passport-beta-fence.ps1` with the signed stack manifest,
   approved beta baseline manifest, and a new absolute Windows receipt path.
   It installs the passport-scoped write fence, verifies direct database write
   rejection, and records the exact old beta and production generation.
3. Dispatch the protected-main `passport-beta-rust-readiness.yml` workflow with
   the merged `marty-credentials` PR #305 head and the fenced receipt's WSL
   path. Download its three artifacts: the exact fence installation receipt,
   fresh cutover snapshot, and Rust readiness report. Keep their bytes intact.
   This producer checks zero passport jobs and active physical Flows on the
   current beta. A read-only query on 2026-10-09 found zero rows in
   `issuance_service.physical_document_jobs`. This is a fail-closed check of
   that observed beta state, with no drain operation or wait. If records appear
   before fencing, prove each record is readable by Rust before changing the
   gate. The workflow does not require an obsolete predeletion run.
4. Pass those artifact paths to `scripts/start-passport-beta-db-maintenance.ps1`
   as `-FenceReceipt`, `-CutoverSnapshot`, and `-CutoverReport`, together with
   the signed stack manifest. The operator verifies the protected run, artifact
   attestations, source, fence, old writer, current Docker and database identity,
   and unchanged production before stopping old beta applications. Retain the
   maintenance receipt and adjacent durable intent.
5. Run `scripts/run-passport-beta-native-db-gates.ps1` with the same stack and
   fence receipt, the maintenance receipt, and a new native receipt path. It
   rechecks the sealed readiness inputs and stopped generation before native
   migrations. The aggregate operator consumes these three receipts.
6. Run `scripts/run-passport-beta-aggregate-deploy.ps1` once with the signed
   manifest, fence, maintenance, and native receipts; the private application
   and Flow output paths; selected issuer chain and ceremony files; distinct
   CSCA and DSC operator sessions; and the governed Flow session. It creates
   managed issuer profiles and the Marty CSCA/DSC chain through the staged
   Gateway and KMS, proves the chain, then switches to the signed Rust owner.
   The aggregate receipt must bind the source, service images, references,
   native migration, KMS proof, and production postflight.
7. Complete public beta Flow, passport lifecycle, D-12 recording and YouTube
   evidence, and the uninterrupted beta soak against the same release and
   aggregate receipt. Accept only the source-bound protected evidence. A failed
   cutover retains its pending marker and separate production postflight;
   resolve that state before another attempt.

The older predeletion producer and Python deletion cutover workflow are
historical evidence paths. Their run IDs are not inputs to this post-deletion
release. The new readiness gate still fails closed if the live beta has an
unproven passport job, incompatible artifact, or active physical Flow.
