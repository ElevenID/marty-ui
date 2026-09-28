# Passport beta acceptance evidence

`scripts/collect_passport_beta_acceptance.py` records a bounded prerequisite
report from an already deployed **official aggregate beta** release. Run it on
the beta host with the deployment's artifact directory:

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
`physical_bureau_batch`, `signed_bureau_callback`, `legacy_drain`, `rollback`,
`production_isolation`, and `recorded_demo`. The two `physical_bureau_*` names
are retained for the frozen simulator route-compatibility receipt; they do not
assert physical production. `physical_claim_boundary` records
`physical_claim=not_claimed` and `booklet_verified=false` only for the isolated
Marty simulator. A future physical-booklet claim requires independent evidence;
the simulator makes no such claim. Separate supported base Compose, self-host,
and Kubernetes acceptance remains mandatory before Python retirement.

## Protected beta acceptance run

The manual `passport-beta-acceptance.yml` workflow uses the same protected
`beta-lifecycle` environment and local beta runner. It requires the official
released deployment artifact directory, beta API key, and synthetic test
application. The runner authenticates the stack manifest and all three UI OCI
images, checks six live beta services, and confirms KMS managed issuer mode.
It then takes a read-only snapshot of both production Compose projects, queries
beta PostgreSQL for in-flight jobs, legacy or malformed artifact rows, and
active physical-document Flows using the deployment preflight's narrow
expired verification orphan exemption,
executes the seven application route identities, and repeats the beta and
production checks. Mutating requests target only beta Gateway and the
inspected beta simulator's private batch route. The private application file
is removed before artifact upload.

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
The protected runner also creates two distinct native passport jobs through Gateway,
generates their data groups and managed SODs, then submits those exact job identities
to the inspected beta simulator's private batch route. It binds each returned bureau
job ID through native single-job submission before accepting callbacks. It checks
the one-to-one mapping, polls both jobs to `SHIPPED` with simulator tracking markers,
requires two distinct callback receipt digests, and finishes each native job through
quality and activation. The batch uses an explicit document type for simulator
idempotency with native submission; the frozen Rust batch adapter's historical wire
shape is tested separately. If a native binding fails after batch submission, the
fresh simulator and native jobs may remain in the beta runtime. The run fails
closed, and the nonterminal-job drain blocks cutover until the synthetic jobs
are quarantined and remediated under the existing beta rollback procedure.
The probe never tears down the durable `elevenid-beta` project. It publishes per-run keyed HMAC
commitments for the exact batch request and response. Source and bureau job ID
commitments use the acceptance API key and the frozen material-receipt preimages,
so they can be compared across probes. The keys, raw IDs, document material,
callback body, and signature stay out of evidence.
The report marks `physical_bureau_batch` and its signed callback evidence
verified only after these checks, with `physical_claim=not_claimed` and no
booklet claim. Each returned batch job must map to its own submitted native
job and private signed receipt; two independent callback receipts cannot
substitute for the governed Flow job's same-job callback proof.

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
After the direct Gateway job, it executes a distinct nine-step Flow job using
the selected DSC. That one Flow job must match its first accepted simulator
material receipt, private signed callback receipt, and final native status.
The uploaded report omits raw Flow, application, source-job, bureau-job,
applicant, MRZ, and operator-session values. A selected SOD/material match
alone does not establish `nine_route_gateway_flow` or recording qualification.

The production snapshot proves continuity **during this acceptance run**. It
does not replace the deployment wrapper's before/after production comparison.
The report requires the isolated simulator mode and sets `legacy_drain` and the additional
`production_continuity_during_probe` probe when those live checks pass, while
`production_isolation` remains false. The workflow fails while the report is
`blocked`, but uploads the sanitized report from an attempted probe. The
acceptance report remains `blocked` until the live run verifies SOD signature,
the selected Flow job in the two-job batch, full nine-route Gateway/Flow proof,
same-job signed simulator callback, simulator batch compatibility, rollback,
deployment-wide production isolation, supported
consumer acceptance, and recorded demo evidence have executable receipts.
D-12 recording and publication remain blocked while these gates are open.
No live beta deployment or protected successful acceptance run is claimed by
this guide. The current report cannot qualify Python retirement on its own.

The protected run uploads a GitHub artifact named
`passport-beta-acceptance-<run-id>` containing the same name plus `.json`.
A future retirement receipt uses
`evidence_artifact: passport-beta-acceptance-<run-id>.json` and the exact file
SHA-256, together with that successful run ID and its protected source SHA.
This receipt must not be marked qualified while the report is `blocked`.
