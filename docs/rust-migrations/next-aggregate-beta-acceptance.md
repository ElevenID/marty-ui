# Next aggregate beta: acceptance checklist

The final aggregate beta operator requires two external issuer input files.
`IssuerChainFile` contains exactly `organization_id`, `csca_issuer_did`,
`csca_certificate_id`, and `dsc_issuer_did`. Its organization and DSC DID must
match the private application file. `IssuerCeremonyFile` uses the existing
`probe_passport_beta_chain.py` request shape: `organization_id`, a `csca`
object with the CSCA DID, certificate ID, ICAO format, country, organization,
common name and validity days, and a `dsc` object with both DIDs, the same
CSCA certificate ID, ICAO format, country, organization, common name,
validity days and stable idempotency key. These fields must match the selection.

Provide distinct `CscaSessionFile` and `DscSessionFile` cookies with
`signing-key:create` plus, respectively, `passport-certificate:issue-csca`
and `passport-certificate:issue`. With the signed new Gateway and Signing Keys
staged and public ingress closed, the operator seals a durable request intent,
creates the two managed issuer profiles through the normal Gateway route,
then performs the governed CSCA and DSC ceremonies through those same Gateway
routes and sessions. Certificate IDs and the DSC idempotency key make exact
retries safe. The subsequent read-only gate checks the selected valid CSCA
record and active DSC certificate, strict X.509 chain, fresh signatures from
both profiles, and nonexportable Transit keys in preserved beta OpenBao.
Keep the ceremony intent, ceremony receipt and KMS proof with the aggregate
receipt. Public ingress remains closed until the Rust owner checks pass.

Source-readiness audit: Signing Keys #913 and the passport aggregate #919 are
on protected main. The reviewed aggregate correction and deployment writer fence
must also be on protected main before a release claim. The
[1.1.218 coordinate](passport-predeletion-release-1.1.218.md) was tombstoned
after qualification failed. The [1.1.219 coordinate](passport-predeletion-release-1.1.219.md)
also stopped before promotion when its pinned public-stack harness selected a
retired Python DIDComm owner. The [1.1.220 release](passport-predeletion-release-1.1.220.md)
passed release qualification, but its protected disposable producer failed and
did not create acceptance evidence. The [1.1.221 coordinate](passport-predeletion-release-1.1.221.md)
selects the reviewed teardown correction for another Rust qualification run.
Historical beta 1.1.217 evidence cannot qualify the new source.
The final beta release must come from the source after Python passport deletion.

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
2. Review the 1.1.221 eligibility change with the corrected public-stack harness
   pin and disposable teardown guard on protected main. Then use
   `.github/workflows/prepare-stack-tag.yml` and `cd.yml` to claim and publish
   the immutable **pre-deletion qualification** release. Retain the source,
   claim/transaction and run identities. Verify annotated tag/source, complete
   checksums, signed manifest/provenance, release assets and every OCI digest
   listed in the signed aggregate manifest, including credentials issuance,
   UI, services and migrations. This release is for protected disposable
   runtime proof; do not deploy it to beta or reuse earlier acceptance evidence.
3. Pass the source-bound protected disposable Rust passport acceptance with
   six owned service images, all nine routes, tenant isolation, the managed
   KMS CSCA/DSC chain and SOD signing, a two-job Marty simulator batch,
   signed callbacks, and Rust job restart/resume. The separate base Compose,
   selfhost Compose, and Kubernetes live consumer fixture is optional later
   work in #944. Separately install and attest a durable passport-scoped
   write fence on real beta, then inventory the shared Python issuance service,
   attest the live cutover drain, and preserve or resolve every job and artifact.
   The service also owns unrelated routes and must remain available; its
   passport write paths must be blocked. Verify the exact head of the
   [Credentials deletion PR](https://github.com/ElevenID/marty-credentials/pull/305),
   whose gate now calls for the scoped fence, and run its protected final
   cutover producer. Attest the
   later beta drain watermark against that head, pass its post-cutover CI,
   and resolve review findings before merging the deletion. Live receipts are
   absent today, so this gate is still pending.
4. Select a fresh unused coordinate for the **post-deletion** source, refresh
   all component pins, and repeat the protected claim and release sequence.
   Verify that the final signed images contain the reviewed Rust owner and no
   superseded Python passport route.
5. After the protected aggregate operator has merged and the final signed
   post-deletion release is available, perform the one beta cutover with
   `scripts/run-passport-beta-aggregate-deploy.ps1` from a clean released
   worktree. Supply the signed stack manifest and the attested fence,
   maintenance, and native migration receipts. Supply an absolute
   `-ApplicationFile` as an absolute output path outside protected source. The
   operator creates and verifies the pilot organization's Credential Template,
   Application Template, and physical destination through staged Gateway while
   the passport write fence remains `fully_fenced`, then durably writes the
   selected IDs and managed issuer DID to that file. The
   operator also needs `-IssuerChainFile` and `-IssuerCeremonyFile` with the
   selected managed CSCA/DSC identities and exact certificate request, plus
   distinct `-CscaSessionFile` and `-DscSessionFile` cookies with the grants
   described above. The selected DIDs must be local path-scoped
   `did:web:beta.elevenidllc.com:orgs:...` identities. The operator checks
   the staged Signing Keys `PUBLIC_DOMAIN` before sealing the ceremony intent.
   The operator creates the DSC issuer profile before the Credential Template,
   then completes the CSCA/DSC certificate ceremony through normal Gateway
   authorization while the public edge remains closed.
   Supply `-FlowFile` as an absolute output path outside protected source. After
   the Rust owner transition, the operator creates and activates the physical
   Flow through staged Gateway and durably writes its ID. It also needs an
   absolute `-SessionFile` containing a governed beta operator Cookie value
   with Credential Template, Application Template, and destination create/view/
   activate grants, `flow-definition:create`, `flow-definition:activate`,
   `flow-definition:view`, `credential-template:view`,
   `flow-instance:start`, and `flow-instance:view` permissions. Keep
   all private inputs and generated outputs outside protected source. Start
   signed Gateway on its verified loopback listener while the public edge is
   stopped. Durable reference intents prevent replaying an uncertain creation
   or activation POST; unresolved writes keep ingress closed. Validate the live
   Flow definition, references and issuer after the transition.
   After the transition, create a synthetic DRAFT job through signed Rust
   issuance and a physical Flow through private Gateway, then match both
   responses to durable Flow and encrypted job rows. Durable attempt and
   dispatch markers prevent an uncertain response from repeating a POST. If
   the Flow creation response is lost, keep ingress closed until its Gateway
   write-route trace is independently resolved; a later GET cannot stand in
   for that trace.
   Keep the transition, private write, Flow, and aggregate receipts outside protected
   source. Verify the exact Compose render, signed images,
   preserved beta state, KMS custody, and production isolation before accepting
   the runtime. The operator also checks the public production root before
   beta mutation and in the final runtime receipt. If the cutover fails, read
   the separate `.production-postflight.json` receipt. After a verified
   pre-mutation capture, the operator first tries to restart only the exact
   previously running production containers if any stopped, then checks their
   health and public route. A restart is recorded as a continuity breach even
   when availability returns. The receipt also compares the production
   generation against the fenced maintenance receipts; resolve any failed
   postflight before resuming the beta cutover. Reserve the bounded cutover
   window exclusively on the shared host: do not run production maintenance,
   deployment, or manual container stops between the pre-mutation capture and
   postflight. If production maintenance is needed, finish it before starting
   a new cutover attempt. These loopback
   calls are pre-ingress ownership gates, not
   end-to-end acceptance. After the public edge opens, run the selected
   physical Flow and nine-route passport lifecycle through
   `https://beta.elevenidllc.com`, including the demo recording, and bind
   those public responses to the same release and aggregate receipt. The
   aggregate receipt remains `acceptance_pending` until those checks pass.
   The older `deploy-local-beta-release.ps1 -OfficialStackRelease`
   still invokes Python migrations and is not the Rust-only cutover operator.
   Native passport remains off until the protected passport PR chain and this
   KMS-only selector have merged, the exact beta image digest is available,
   and the runtime gates below pass. The former five-file passport overlay has
   been replaced in the Rust candidate by managed issuer signing, Transit
   artifact encryption, Transit callback MAC, an existing internal service
   credential handoff, and a beta-only non-physical bureau simulator. **Do not
   provision the old passport key files or select an older profile.** Render
   checks and `-PlanOnly` are not runtime acceptance.
   Resolve an active, organization-scoped `ICAO_EMRTD` X.509 document-signer
   identity created through the existing issuer UI; bind it to the passport
   job and use its managed Signing Keys/KMS reference and published certificate
   for opaque CMS/SOD signing. Create a separate managed `ICAO_EMRTD` CSCA
   issuer profile and obtain its public certificate through the reviewed
   beta-only CSCA ceremony. Gateway requires `passport-certificate:issue-csca`
   and a credential distinct from the DSC issuance credential; Signing Keys
   signs the CSR and self-signed CA certificate through the active KMS profile,
   verifies both signatures, and enrolls the public trust anchor with a
   profile-revision fence. The older public CSCA import remains available.
   With no external CA for this beta, use the issuer console's **Issue CSCA**
   action on the active ES256 CSCA profile, record its certificate ID, then use
   **Issue DSC** on the separate active ES256 document-signer profile with that
   CSCA DID and certificate ID. Retain the displayed DSC request reference with
   the exact request details so a lost response can be retried idempotently.
   Verify the active CSCA-to-DSC chain before accepting a passport job. This
   review branch is not yet merged or deployed. A read-only beta check on
   2026-09-26 found no CSCA lifecycle record for the pilot organization; its
   six existing issuer profiles include no `ICAO_EMRTD` document signer. This
   remains a cutover gate: create separate managed CSCA and DSC keys, issue
   the beta CSCA certificate through the governed operator route, issue the
   DSC from that active CSCA, and verify the trust-anchor projection before
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
   The shared Rust image builds both beta-only binaries and its closed entrypoint
   dispatches `passport-callback-signer` and `passport-beta-bureau` explicitly.
   The exact-head protected image and release-contract jobs must pass before
   claiming an aggregate release.

   The [Signing Keys public-route parity audit](signing-keys-public-parity-2026-09-26.md)
   found 24 Gateway-declared method/path pairs without Rust public handlers on
   its protected-main baseline. The current stacked review head has local Rust
   handlers for all 24, but they are not yet merged or beta-accepted. The
   managed-key creation route has an authenticated real-HTTP Gateway-to-Rust
   test. The stacked Gateway route matrix now checks session and tenant rejection
   for 22 further method/path pairs, plus successful service certificate, KMS
   public-key verification, JWKS/DID publication, and config resolution through
   an authenticated GCP adapter fixture. AWS/GCP provider envelopes are normalized
   by the shared public-JWK sanitizer before resolver algorithm matching; AWS
   key usage and signing algorithms, GCP key-version algorithm, and Azure Key
   Vault key operations reject provider-declared non-signing keys. A public JWK
   with `key_ops: ["verify"]` remains eligible when its provider does not declare
   signing restrictions. OpenBao's public-JWK
   response does not expose its Transit `supports_signing` flag; confirm that
   capability during live beta acceptance. The
   direct-service public JWKS/DID contract still uses the provider key reference
   as `kid` and a locator-derived DID fragment. Preserve this published identity
   until previously issued credentials expire; move future custody identifiers
   behind issuer profiles with a separately reviewed compatibility migration.
   The fixture supplies a bearer token and does not establish workload-identity
   token acquisition. The next stacked Gateway fixture exercises issuer-profile
   create and resolve through a stateful mock Transit server, then confirms the
   internal issuer-DID sign route sends the derived profile key and EdDSA payload
   to Transit without returning the KMS locator to callers. Its fixed mock
   signature proves routing and custody selection, not cryptographic validity.
   A further opt-in Gateway test now creates separate CSCA and DSC issuer
   profiles with a disposable OpenBao Transit instance, requests both PKCS#10
   CSRs, and compares each parsed CSR public key with the resolved issuer key.
   It exercises KMS signing and Rust signature verification through Gateway.
   A further guarded Gateway/OpenBao/Redis acceptance now invokes the governed
   CSCA ceremony and DSC issuance routes, verifies their certificate chain,
   and checks replay, changed-input conflict, operator separation, and public
   custody redaction. This is disposable test evidence, not live beta enrollment.
   The same marked CI step now runs the Rust issuance managed-profile chain
   test through a real disposable OpenBao signer and verifies its SOD signature,
   data-group hash, tenant isolation, revocation, and stale-key rejection.
   A further opt-in Gateway test rotates a dedicated registered Transit service, checking
   tenant denial, the managed-service rotation boundary, one KMS rotation,
   and persisted version history. This is not issuer-profile key rotation:
   shared managed services are rejected by the service route, and a future
   CSCA/DSC profile rotation needs its own reviewed contract and API. A
   separate Gateway test now generates a dedicated service CSR with disposable
   OpenBao, verifies its subject and KMS public key binding, and checks tenant
   denial and custody redaction. Rerun the route audit on protected main after
   the stack lands, and complete beta
   acceptance before describing the aggregate release as feature-complete.

   A read-only Redis inventory on 2026-09-26 found zero beta and production
   managed `cred-issuer-*` bindings or active profiles for `holder_binding`,
   `presentation_signing`, or `oid4vp_request_signing`. The dedicated managed
   prefixes can therefore retain purpose isolation without a current legacy
   generic-prefix migration. Recheck both environments immediately before
   cutover; if that inventory changes, preserve exact tenant-bound live keys
   before retiring Python.

   Certificate-enrollment follow-up: the protected baseline's service CSR UI
   action lacked a matching public service route. This review branch restores
   `/v1/signing-keys/services/{service_id}/certificate-csr` for dedicated
   services and redirects the managed-service button to issuer identities;
   do not use the shared-service CSR action for the pilot chain.
   The managed OpenBao signing
   service can be shared by several issuer profiles, while each CSCA/DSC has
   its own KMS key reference. The Rust CSR operation must select the active
   issuer identity tuple, resolve its KMS custody server-side, sign the PKCS#10
   request in KMS, and verify the returned CSR against the current KMS public
   key. It must not accept a caller-supplied key reference or attach a chain
   to the shared service. This review branch contains a distinct
   issuer-scoped Rust PKCS#10 CSR route and UI action that verifies the
   signature against the current KMS public key. Before beta acceptance,
   exercise it against beta KMS, complete the managed beta CSCA ceremony and
   DSC chain enrollment, and verify the separate tenant-scoped operator
   permission and trust-anchor projection; no private key or raw signing
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
   At cutover, deployment verifies the passport-scoped write fence and stops
   old application writers during the Rust owner switch. It requires zero
   in-flight legacy bureau jobs before switching to KMS callback
   verification. The deployment preflight rejects an existing bureau without
   the isolated signer: the current restore script cannot recover such a
   pre-isolation passport snapshot. The inventoried beta has no bureau, so
   the first passport cutover remains conditional; recheck that
   condition before deployment and keep the restore constraint visible.
6. Require the beta origin to equal `https://beta.elevenidllc.com`.
   Retain fixed beta Compose projects/network and labeled-volume ownership checks.
   Capture and compare production's exact before/after identity and state;
   beta isolation checks do not independently prove production unchanged.
   Do not deploy, restore, reset or probe mutating endpoints on production.
7. Preserve the original three deployment evidence files and package them with
   the released `beta-evidence-bundle` utility. Complete private recorder
   `release-qualification.yml`, then public `.github/workflows/e2e-tests.yml`
   with exact run/SHA/receipt hashes. Retain full browser, demo and credential
   lifecycle results, including fresh custom-themed Keycloak/KMS switching
   recordings. Portfolio qualification alone is not all-demo acceptance.
8. Complete `.github/workflows/wallet-conformance.yml` using protected evidence
   URL/hash, verified attachments and exact release/lifecycle lineage. Preserve
   genuine Spruce issuance/login recordings, signed-request capture and the
   seven native-wallet handoffs required by the catalog. Keep the inactive
   Walt.id blocker visible; do not replace device evidence with mocks.
9. Start a new uninterrupted release/source-bound soak. Existing
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
