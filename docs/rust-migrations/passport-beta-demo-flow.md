# Passport beta demo flow

D-12 records Marty's passport software flow on the **same aggregate beta
deployment** used for Rust acceptance. It uses managed CSCA and DSC issuer
profiles, the Marty bureau simulator, and a signed native callback. The
recording and its report must say `physical_claim=not_claimed` and
`booklet_verified=false`. A physical booklet or external provider is outside
this evidence claim.

The recording cannot depend on the final accepted passport report: that report
itself requires `recorded_demo`. A protected main workflow named
`passport-beta-preliminary.yml` must first publish
`passport-beta-preliminary-<run_id>.json` with schema
`marty.passport-beta-preliminary/v1` and status `qualified_for_recording`.
It must attest the official signed stack, exact beta deployment manifests,
distinct managed issuer profiles, same-job SOD, nine Rust routes and completed
Flow steps, two-job simulator batch and selected job commitment, signed native
callback, physical claim boundary, the private first-accepted simulator
SOD/DSC receipt for that same job, and separate unsigned and
foreign-organization callback denials. It must include separately captured,
privacy-scanned uncut unsigned and foreign callback videos with hashes in the
preliminary report, plus two matching privacy-scan JSON artifacts whose digests
and passing results the recorder verifies. The workflow must keep raw passport data, tokens, private
keys, and the HMAC commitment key out of its artifact.
The unsigned native webhook must return the frozen missing-signature-header
HTTP 422 response; a signed foreign-organization callback for the same bureau
job must return the native job-not-found HTTP 404 without changing that job.
Both negative requests must bind to the positive synthetic job and selected
bureau-job commitment; the foreign event must carry a distinct organization.
`scripts/probe_passport_beta_negative_callbacks.py` performs these two live
denials after checking the signed aggregate deployment and private selected-job
handoff. It signs the foreign callback through the isolated beta signer and
emits only keyed identity and state commitments. Its JSON result is diagnostic
until the separate uncut videos and privacy scans are captured and verified;
it cannot qualify the preliminary recording gate on its own.
The protected recording job may invoke the probe once with `--case unsigned`
and once with `--case foreign`, creating one single-case result per uncut clip.
Each invocation rechecks the selected job, signed deployment, native route, and
production continuity. The preliminary producer must verify that the two
single-case results agree on the selected source and bureau commitments and
unchanged job-state commitment before it joins them with their exact videos
and privacy scans. A single-case result is never a two-denial receipt.
`tests/scripts/record-beta-passport-negative-callbacks.js` records each live
case within one continuous browser clip. The protected Python probe sends its
prepared request through a one-use loopback bridge; the browser makes the
actual same-origin beta webhook request and displays only its returned HTTP
status and fixed denial projection. Python then verifies the selected job is
unchanged. The script invokes the pinned demo recorder's
frame/OCR/QR privacy scanner, and emits `negative-callback-media.json` only if
both cases have the same signed release, aggregate beta deployment, selected
job, and unchanged-state commitment. It requires the private handoff and a new
mode-0700 output directory outside the checkout and deployment artifacts. The
scanner checkout must match `PASSPORT_DEMO_RECORDER_COMMIT`, which the protected
workflow derives from the governed deployment's source, local deployment, and
deployed demo manifests. The recorder revision is an explicit release input;
it is not a component of the signed stack manifest. The `beta-lifecycle`
environment needs `PASSPORT_DEMO_SOURCE_READ_TOKEN`, a fine-grained token with
Contents read access to the private `ElevenID/marty-demo-recorder` repository.
The existing `DEMO_RECORDER_DISPATCH_TOKEN` lacks that permission. The workflow
installs the pinned recorder's locked dependencies and verifies `ffmpeg` and
`tesseract` before consuming the selected live Flow. These media files remain
diagnostic until the protected preliminary producer verifies them and qualifies
the recording receipt.
The private handoff must remain outside the deployment artifact directory and
source checkout. The probe writes a new result file outside that directory,
rejects the local beta proxy mode, and uses direct beta HTTPS for its job and
callback requests.

The D-12 recorder's `externalQualification` runs
`tests/scripts/audit-beta-physical-passport-flow.js`. Supply
`PASSPORT_BETA_ARTIFACT_DIR`, `PASSPORT_BETA_PRELIMINARY_RUN_ID`, and
`PASSPORT_BETA_PRELIMINARY_SHA256` plus a governed beta operator login. Supply
the protected aggregate deployment receipt as `aggregate-deployment.json`,
its exact `aggregate-deployment.json.plan.json`, the signed
`stack-manifest.json`, and `SHA256SUMS` in that artifact directory. The
preliminary producer must compare each live beta container and image ID with
the receipt, and bind the public report to the receipt, plan, and signed stack
hashes. The recorder does not use old local/source deployment manifests.
Supply
`PASSPORT_BETA_PRIVATE_PLAN_FILE` outside the checkout and artifact directory
and `PASSPORT_BETA_API_KEY` from protected secrets. The plan has schema
`marty.passport-beta-demo-private/v1`, the exact selected organization, Flow
definition and instance, application, source job and canonical bureau UUID,
plus the deployed source and stack digests. It is a mode-0600 local file on
the Linux recorder and is never uploaded. The beta acceptance runner writes
the plan only after the selected Flow and native batch receipts verify, under
`~/.local/state/marty/passport-beta-demo-selected-<run-id>-<attempt>.json` on
the protected beta runner. It refuses to overwrite an existing plan or start a
new batch while unresolved native state exists. The operator transfers the
file to the recorder through the governed private handoff and retains it until
recording is reconciled. The recorder checks every plan
identity against the preliminary API-key HMAC commitments before navigating
to beta. CSCA and DSC profile commitments use one `issuer-profile` HMAC
label so an identical profile cannot masquerade as two, and both negative
callback runs carry the same selected source and bureau commitments. Public
unchanged-state evidence is an API-key HMAC over a private state digest; the
unkeyed digest stays protected. The
script downloads the exact protected workflow artifact, verifies its digest
and deployed source, checks the same simulator job in the live Flow Instances
API and UI, and records only after login. The recorded page stays hidden until
the protected identifiers in its visible text are masked; downstream privacy
scans still gate publication. It emits a sanitized `report.json`
`physical-passport-issuance-evidence.webm`, and the two uncut negative videos;
the recorder then applies its
privacy, caption, transcript, review, and YouTube publication gates.

The final beta acceptance producer must verify the recorder's protected run,
review files, media/privacy hashes, ElevenID LLC channel and playlist, and
live YouTube publication result. It must bind those to the same source commit,
stack manifest, aggregate deployment receipt and plan hashes, beta origin, and
`physical_claim=not_claimed` before setting `recorded_demo.verified=true`.
Python passport retirement requires protected Rust parity, the final live
drain, and the reviewed deletion gate before the aggregate beta deployment.
The recording and final receipt then qualify the single Rust-only beta soak.

The preliminary workflow, full signed callback and Rust restart producer, D-12
publication inputs, and final demo receipt producer are still outstanding.
No beta recording or YouTube upload has occurred under this plan.
The disposable model rehearses the stack and does not replace this live beta
recording or its protected preliminary receipt.
