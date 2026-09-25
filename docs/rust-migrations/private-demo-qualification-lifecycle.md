# Private demo qualification before public beta acceptance

The beta lifecycle now requires a **completed** private recorder qualification.
It no longer starts a fire-and-forget qualification that can fail unnoticed while
browser acceptance proceeds. Intake remains available in the private recorder's
`release-qualification.yml` workflow (workflow dispatch and repository dispatch).
The ordering is deliberate: original verified deployment receipt → private intake
and qualification → public lifecycle → fresh recordings, device evidence and soak.
No production deployment is part of these steps.

## Private intake

Use the original three evidence files retained by the successful official beta
deployment wrapper. Do not rebuild expected component maps from live beta or edit
the receipt's source kind, readiness flags, source revisions or image digests.
The released UI revision must contain `beta-evidence-bundle`; release 1.1.216
predates that utility and cannot use this input path.

After checking signatures/provenance, exact release/source bindings and the
deployment audit, run the released Rust utility to pack the original evidence:

```bash
cargo run --locked --manifest-path rust/Cargo.toml \
  -p marty-release-evidence --bin beta-evidence-bundle -- \
  pack "$DEPLOYMENT_EVIDENCE_DIRECTORY" "$NEW_PRIVATE_TRANSPORT_FILE"
```

The transport contains operational metadata. Keep it private; do not print it,
commit it, include it in a public workflow event, or publish it as an artifact.
Use an authenticated account allowed to dispatch the private recorder workflow:

```bash
gh workflow run release-qualification.yml \
  --repo ElevenID/marty-demo-recorder --ref main \
  -f beta_origin="$BETA_ORIGIN" -f release_version="$RELEASE_VERSION" \
  -f marty_ui_release_sha="$MARTY_UI_RELEASE_SHA" \
  -f beta_source_id="$BETA_SOURCE_ID" \
  -f review_record_id="$DEMO_REVIEW_RECORD_ID" \
  -F deployment_evidence=@"$NEW_PRIVATE_TRANSPORT_FILE"
```

Record the exact resulting run ID and verify its head SHA is the reviewed
recorder main revision. Do not choose an unrelated run merely because it is the
latest one. Then wait on that specific handle:

```bash
gh run watch "$DEMO_QUALIFICATION_RUN_ID" \
  --repo ElevenID/marty-demo-recorder --exit-status
```

Stop if qualification fails. The private workflow must have checked the complete
portfolio against actual beta using the unpacked original evidence. It publishes
only `release-qualification.json` in
`demo-release-qualification-$RELEASE_VERSION`, never the original bundle.

The recorder repository currently cannot enforce branch protection under its
GitHub plan. Maintainers must finish reviews and wait for terminal green checks
before explicitly merging; do not rely on `--auto`. The public consumer requires
the exact reviewed recorder SHA and does not treat `main` alone as sufficient.

## Public lifecycle

Set `DEMO_DEPLOYMENT_MANIFEST_SHA256` from the **original deployer receipt**, not
from the downloaded qualification report. Supply the existing seven lifecycle
inputs plus these four required inputs:

- `demo_qualification_run_id`: the completed successful private run above.
- `demo_recorder_sha`: its exact reviewed 40-character recorder revision.
- `demo_review_record_id`: the positive numeric GitHub PR comment ID supplied to
  the recorder intake for its immutable maintainer-review checkpoint.
- `demo_deployment_manifest_sha256`: the original receipt's lowercase SHA-256.

The existing repository-scoped `DEMO_RECORDER_DISPATCH_TOKEN` secret reads the private run,
artifact, server-side PR issue comment, and collaborator permission. Configure a
fine-grained token restricted to `ElevenID/marty-demo-recorder` with repository
permissions **Actions: Read-only**, **Pull requests: Read-only**, and
**Metadata: Read-only**. GitHub accepts `Issues: Read-only` as an alternative for
the issue-comment endpoint, but this environment standardizes on Pull requests
read. Metadata read covers the collaborator-permission endpoint. No write or
administration permission is needed. The secret name is retained for
configuration compatibility; never copy its value into logs or command
arguments. Environment approval and existing release provenance, live-source
checks, browser/CSP tests and credential journeys remain mandatory.

`marty-release-evidence` shares the authenticated run parser with stack-release
validation. The new `validate-demo-qualification` binary verifies:

- Exact repository and head repository, run ID, workflow name/path, successful
  terminal state, allowed dispatch event, main ref and reviewed recorder SHA.
- Qualified report, release version, MIP 0.5.0, separate UI revision and
  coordinated source ID, original deployment receipt hash, and official stack
  hash independently computed from the signed published stack manifest.
- `lifecycleQualified: true`, `qualificationMode: official-private`, and the
  byte-exact canonical beta origin supplied independently by the lifecycle as
  `BETA_ORIGIN`; local and historical recorder modes cannot qualify this gate.
- A valid deployed-demo hash, positive scenario count and the recorder's explicit
  `freshRecordingRequired: true` contract. Full scenario semantics are enforced
  by the exact reviewed recorder, not inferred from the count by this consumer.
- Complete public maintainer-review provenance, including the exact repository,
  comment record/body hashes, PR and reviewed head/tree, author, association,
  independently queried `admin` or `maintain` permission, and immutable server
  timestamps. The reviewed recorder head must equal both the requested recorder
  revision and the successful run.
- Independently downloaded GitHub comment and collaborator-permission records.
  The validator requires the exact recorder PR issue URL and numeric record ID,
  reconstructs the fixed-order canonical server-record JSON and hashes the exact
  UTF-8 comment body, validates the structured feature/security/test approval
  with zero findings, and rejects duplicate JSON members at any depth.

Raw private run metadata and downloaded reports remain under `RUNNER_TEMP`.
The Rust validator emits only allowlisted, validated release and review provenance
to public lifecycle evidence (`demo-qualification.json`); arbitrary extra report
fields are not copied.
The lifecycle context also records the private run ID, recorder revision and
deployment receipt hash. Missing/expired artifacts, access failures, unsuccessful
runs and binding mismatches stop the gate before browser tests.

## Evidence limits

Qualification is a release/portfolio binding prerequisite, **not completed fresh
recordings, successful credential journeys, external wallet/device evidence, or
a completed acceptance soak**. Tests use clearly labeled synthetic run/report
fixtures; these are never deployment acceptance evidence. A hosted qualification
and lifecycle on the newly released aggregate are still required after landing
this change. Published beta216 and its retained evidence must not be relabeled.
