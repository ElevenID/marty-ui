# Passport beta acceptance evidence

`contracts/passport-beta-native-acceptance.json` is the release and D-12
recording gate. The earlier `passport-beta-batch-acceptance.json` and its
synthetic direct-simulator probe remain a simulator compatibility diagnostic.
They cannot establish that the selected Flow job entered the native batch, so
their result cannot qualify recording or Python retirement. The protected
runner now joins the selected Flow job to the native batch, but the remaining
release probes and live beta run have not passed.

`scripts/collect_passport_beta_acceptance.py` records a bounded prerequisite
report from an already deployed **official aggregate beta** release. Run it on
the beta host with the deployment's artifact directory:

For the forward Rust aggregate, the directory contains the exact
`aggregate-deployment.json` written by the protected operator, its adjacent
`aggregate-deployment.json.plan.json`, and the signed `stack-manifest.json`
with `SHA256SUMS`. The operator also preserves adjacent files ending in
`.fence-receipt.json`, `.maintenance-intent.json`,
`.maintenance-receipt.json`, and `.native-receipt.json`. Keep the original
bytes. The protected acceptance runner requires this aggregate generation.
The collector verifies the native receipt chain and live migration marker,
then verifies the plan
and receipt digests, release and issuance attestations, and each live beta
container, image, start time, Compose hash, and network against the deployment
receipt. The production baseline is reported only as an API-key HMAC
commitment; the raw snapshot digest remains in the protected receipt.

```powershell
$env:PASSPORT_ACCEPTANCE_API_KEY = '<organization-scoped key from governed beta secrets>'
py -3.12 scripts/collect_passport_beta_acceptance.py --artifact-dir C:\path\to\beta-artifacts --output C:\path\to\private-evidence\passport-beta-prerequisite.json --verify-attestation
Remove-Item Env:PASSPORT_ACCEPTANCE_API_KEY
```

The collector checks the exact source and `marty.stack/v1` manifest identity,
each required running beta Compose container and digest-pinned image, and the
public Gateway's authenticated capability response and unauthenticated denial.
It does not write Docker environment values, the API key, or HTTP bodies to the
report. Keep the report in a private evidence directory. A local worktree
snapshot, missing passport service, drifted image, unready capability, or
unexpectedly open endpoint makes collection fail.

After the protected release is deployed and managed issuer profiles plus the
CSCA/DSC chain are enrolled, add `--application-file` with a private test
application JSON. This opt-in mode requires `--verify-attestation` and a ready
authenticated KMS issuer capability before it mutates beta. It creates one
application through Gateway, generates data groups and SOD, submits to the
bureau, polls production status, records an operator quality decision, and
activates the result. The report records exact route outcomes and hashes of
the input and job identifiers; it never writes applicant fields. This covers
seven application route identities. Capability checks add an eighth. Flow
ownership and the signed provider webhook remain separate probes. A passing
quality decision is not evidence of physical booklet quality. A failed run
writes a minimal `blocked` report and exits nonzero.

The protected manual `Passport Beta Prerequisite Evidence` workflow runs on
the beta WSL2 runner with the `beta-lifecycle` environment. Its input points
to the official deployment artifact directory on that runner. The optional
application exercise reads the beta organization's key and synthetic test
application from environment secrets. The workflow uploads only the sanitized
report, never the application file. It rechecks release and container identity
after the mutating probe so a concurrent beta change cannot be hidden.

The emitted schema is `marty.passport-beta-acceptance/v1` and its status is
always `blocked`. `--verify-attestation` checks the release checksum and
GitHub attestations for the manifest and all three UI OCI images; the result
sets `release.signed_manifest_verified`. Verification constrains the signer to
the official `cd.yml` workflow on protected main at the exact deployed source
commit and rejects self-hosted signer provenance. It requires authenticated `gh`
access to the release repository. The following probe keys
remain unverified until protected acceptance runs execute and publish exact
artifact lineage: `managed_csca_dsc_chain`, `sod_signature`,
`simulator_material_receipt`,
`nine_route_gateway_flow`, `packaged_image`, `physical_bureau_submission`,
`physical_bureau_batch`, `signed_bureau_callback`, `legacy_drain`,
`production_isolation`, and `recorded_demo`. The two `physical_bureau_*` names
are retained for the frozen simulator route-compatibility receipt; they do not
assert physical production. `physical_claim_boundary` records
`physical_claim=not_claimed` and `booklet_verified=false` only for the isolated
Marty simulator. `physical_booklet_verified` remains false and is not a
prerequisite for the Rust-only beta software acceptance. A future
physical-booklet claim requires independent evidence. Protected base Compose,
self-host, and Kubernetes acceptance, Rust restart/resume, and the cutover drain
precede Python passport deletion; this beta report follows that deletion.

## Protected beta acceptance run

The manual `passport-beta-acceptance.yml` workflow uses the same protected
`beta-lifecycle` environment and local beta runner. It requires the official
released deployment artifact directory, beta API key, and synthetic test
application. The runner authenticates the stack manifest and all three UI OCI
images, checks six live beta services, and confirms KMS managed issuer mode.
The selected Flow run first authenticates the native internal service token
and distinct reconciliation operator token through a read-only native
preflight. It then takes a read-only snapshot of both production Compose projects, queries
beta PostgreSQL for in-flight jobs, legacy or malformed artifact rows, and
active physical-document Flows using the deployment preflight's narrow
expired verification orphan exemption,
executes the seven application route identities, and repeats the beta and
production checks. The selected Flow batch uses the inspected native container's
private operator route with its deployed `GRPC_SERVICE_TOKEN` as `x-api-key`,
the distinct `PASSPORT_ACCEPTANCE_RECONCILIATION_OPERATOR_TOKEN`, and the
organization header. The private application file is removed before artifact
upload.

The runner also reads the three live beta containers' native routing and
internal-auth selectors without publishing their environment. It requires
Gateway, Flow, and issuance-native to select the native owner and Flow to
target `http://issuance-native:8005`. A Gateway request to
`/v1/flows/capabilities` must expose the nine physical-document steps. A
second Gateway request sends `{}` to the bureau webhook without a signature.
The live Gateway selector determines whether the signed deployment's native
owner must return its exact missing-header 422 response or the separately
selected provider ingress must return its exact invalid-signature 401 response.
This checks an ingress guard, not a valid signed callback. The governed Flow
probe must separately execute all nine steps for one native job and bind its
managed SOD, first accepted simulator material, private signed callback receipt,
and terminal `ACTIVE` state to the same organization, issuer DID, application,
source job, and bureau job. It requires the Flow issuer-DID fix in PR #929 in
the deployed aggregate image. The `nine_route_gateway_flow` probe stays false
until the selected Flow job is one of the two batch jobs and its Gateway route trace is verified. Only
fixed route names, counts, statuses, selector booleans, and sanitized receipt
evidence enter the report.

The beta simulator now stores a 32-byte digest of the exact callback body and
KMS signature only after native issuance accepts the signed callback and the
status transition commits. Its authenticated private job poll returns the
lowercase hex digest as `callback_receipt_sha256`; preexisting jobs can return
`null`. The simulator never stores or returns the callback body or signature.
The aggregate beta profile sends this callback through the private Gateway
route to the native owner. The protected host probe checks the live simulator
container's exact Gateway callback selection before using the receipt as
route evidence. A route selection alone does not verify a delivered callback.
The current batch diagnostic creates two separate native jobs, posts synthetic
SOD and DSC material directly to the simulator, then binds through two native
single submissions. This verifies simulator compatibility but cannot set the
release `physical_bureau_batch` probe to verified. For release acceptance, the
runner must pause the selected Flow after `sign_sod`, prepare one companion
native job, and call the private native two-job batch route with identifiers
only. Native code supplies both signed artifacts, dispatches the selected
Flow job first, and binds each original bureau UUID under durable intent and
first-accepted receipt checks. The frozen batch wire omits `document_type`;
receipt-backed idempotent native calls may fill it after the exact pair is
accepted. The selected Flow then resumes and observes its already bound job
without creating another bureau job. Both jobs must reach `SHIPPED` with their
own simulator markers and signed callback receipts before quality and
activation. An ambiguous or partial send holds its intent and blocks
acceptance until exact private reconciliation. The runner never tears down
the durable `elevenid-beta` project.

The release report must use keyed HMAC commitments over the exact native
batch transport request and first-dispatch response bytes, captured inside
the protected trust boundary. The synthetic diagnostic's wire commitments
cannot substitute. API-key HMAC source and bureau commitments correlate the
selected Flow, batch, material receipt, callback, route trace, and D-12
recorder. Keys, raw IDs, document material, callback body, and signature stay
out of published evidence. `physical_bureau_batch` and its signed callback
evidence become verified only for this same selected job, with
`physical_claim=not_claimed` and no booklet claim.

The private native batch route requires a base64-encoded 32-byte
`x-passport-batch-wire-key` header from the protected acceptance process
before mutation. After a strict first HTTP 202, it attempts to KMS-encrypt
the exact request and response bodies as tenant-bound private evidence and
store their keyed commitments before document-type completion or native binding. A
recovery using the same run key decrypts the retained bodies and recomputes
both HMACs before reporting `wire_evidence_status=verified`; it never
promotes replay bytes into first-dispatch proof. If retention fails or the
first attempt is ambiguous, immutable receipt-backed binding may complete
after its lease, but the route reports `wire_evidence_status=unavailable`
without commitments. That run cannot qualify acceptance or recording and
requires a fresh reviewed acceptance run. The key stays in a mode-0600
pending-state file under the beta runner's private `~/.local/state/marty/`
directory, outside the checkout and uploaded artifacts. The file is created
before companion mutation, updated before dispatch, and cleared only after
selected Flow completion and proof validation. If a run fails or is
interrupted, a new run is blocked until an operator privately reconciles the
retained batch UUID, key, Flow/job identities, and native intent. Never delete
an unresolved pending file to make the probe pass. The report contains only
sanitized commitments. The native wire gate still needs a protected live beta run.
After a verified selected Flow run, the runner writes a separate mode-0600
private D-12 identity handoff for that run and attempt. It never uploads the
file or its path; the public report contains only API-key HMAC commitments
for the selected organization, Flow definition and instance, application,
source job, and bureau job. The handoff is not a preliminary qualification
and cannot replace the remaining callback denial, nine-route, or beta gates.

The full run requires the managed beta CSCA and DSC ceremonies before it
creates a passport job. The protected `beta-lifecycle` environment supplies
`PASSPORT_ACCEPTANCE_CERTIFICATE_PLAN_JSON` and separate governed operator
session cookies in `PASSPORT_ACCEPTANCE_CSCA_OPERATOR_COOKIE` and
`PASSPORT_ACCEPTANCE_DSC_OPERATOR_COOKIE`. The plan is a JSON object with
`organization_id`, a `csca` request for the public self-signed ceremony, and
a `dsc` request bound to its `issuer_did` and `certificate_id`. Both requests
use `ICAO_EMRTD` and the official Gateway routes; issuer profile purposes
distinguish CSCA from DSC even if the DID is the same. The runner checks the
returned public certificates against the selected CSCA with OpenSSL strict
chain and self-signature verification. The plan and both session cookies are
validated before any beta mutation, and the plan's tenant and DSC issuer must
match the private test application. The probe follows the issuer console's
cookie-based Gateway request and organization query; it does not supply an API
key or asserted user identity. Evidence contains certificate and DID hashes, never
session cookies or certificate bodies. Missing or partial ceremony input fails
before any application or certificate mutation.
The ceremony now runs before the direct, batch, or Flow passport jobs. Its
public chain check alone does not prove that their signed SODs used the exact
selected DSC. The protected runner reports the chain verified only after it
reconciles the selected job's immutable simulator material receipt with that DSC.

After native submission, the protected runner reads the private beta simulator
row for the same tenant, source job, and bureau job. It compares the first
accepted decoded SOD and parsed DSC hashes with the native SOD and the
preselected governed DSC, and checks the exact DSC PEM wire hash. The first
receipt is immutable across replay. Legacy rows or malformed synthetic
material cannot satisfy this probe. The uploaded report contains only match
results and API-key HMAC job commitments, not raw material or receipt digests.

The protected full run also requires one `PASSPORT_ACCEPTANCE_FLOW_PLAN_JSON`
and `PASSPORT_ACCEPTANCE_FLOW_OPERATOR_COOKIE`. The Flow plan binds the signed
release's `source_commit` and `stack_manifest_sha256`, `organization_id`,
`issuer_did`, one active `flow_definition_id`, its three governed
template/profile `references` (`application_template_id`,
`credential_template_id`, and `delivery_destination_profile_id`), and
synthetic `physical_document` input. The
runner rejects issuer or profile overrides in that input before the ceremony.
After the direct Gateway job, the native acceptance target executes a
distinct selected nine-step Flow job using the selected DSC. It pauses after
`sign_sod`, joins that same job to the two-job native batch, then completes
the Flow against its original bureau UUID. That one Flow job must match its
first-accepted simulator material receipt, private signed callback receipt,
route trace, and final native status. The runner now joins the selected Flow
job to a companion in the native two-job batch, checks the first dispatch's
private wire proof and both immutable material receipts, and then completes
the Flow. The synthetic batch remains a separate diagnostic.
The uploaded report omits raw Flow, application, source-job, bureau-job,
applicant, MRZ, and operator-session values. A selected SOD/material match
alone does not establish `nine_route_gateway_flow` or recording qualification.
The public `physical_bureau_submission` probe remains unverified until the
D-12 recorder can correlate selected identities through protected commitments
without publishing raw identifiers.

The production snapshot proves continuity **during this acceptance run**. It
does not replace the deployment wrapper's before/after production comparison.
The report requires the isolated simulator mode and sets `legacy_drain` and the additional
`production_continuity_during_probe` probe when those live checks pass, while
`production_isolation` remains false. The workflow fails while the report is
`blocked`, but uploads the sanitized report from an attempted probe. The
acceptance report remains `blocked` until the live run verifies SOD signature,
the selected Flow job in the two-job batch, full nine-route Gateway/Flow proof,
same-job signed simulator callback, simulator batch compatibility,
deployment-wide production isolation, and recorded demo evidence have
executable receipts. Supported consumer acceptance and Rust restart/resume
must pass before Python passport deletion and this beta run. D-12 recording
and publication remain blocked while these gates are open.
No live beta deployment or protected successful acceptance run is claimed by
this guide. A simulator acceptance must set `physical_claim=not_claimed`.

The protected run uploads a GitHub artifact named
`passport-beta-acceptance-<run-id>` containing the same name plus `.json`.
A post-deletion beta acceptance receipt uses
`evidence_artifact: passport-beta-acceptance-<run-id>.json` and the exact file
SHA-256, together with that successful run ID and its protected source SHA.
It cannot be accepted while the report is `blocked`.
