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
inputs plus these three required inputs:

- `demo_qualification_run_id`: the completed successful private run above.
- `demo_recorder_sha`: its exact reviewed 40-character recorder revision.
- `demo_deployment_manifest_sha256`: the original receipt's lowercase SHA-256.

The existing `DEMO_RECORDER_DISPATCH_TOKEN` secret now reads the private run and
artifact in the consumer step; it needs private repository Actions read access.
Its name is retained for configuration compatibility. Do not copy its value into
logs or command arguments. Environment approval and existing release provenance,
live-source checks, browser/CSP tests and credential journeys remain mandatory.

`marty-release-evidence` shares the authenticated run parser with stack-release
validation. The new `validate-demo-qualification` binary verifies:

- Exact repository and head repository, run ID, workflow name/path, successful
  terminal state, allowed dispatch event, main ref and reviewed recorder SHA.
- Qualified report, release version, MIP 0.5.0, separate UI revision and
  coordinated source ID, original deployment receipt hash, and official stack
  hash independently computed from the signed published stack manifest.
- A valid deployed-demo hash, positive scenario count and the recorder's explicit
  `freshRecordingRequired: true` contract. Full scenario semantics are enforced
  by the exact reviewed recorder, not inferred from the count by this consumer.

Raw private run metadata and downloaded reports remain under `RUNNER_TEMP`.
The Rust validator emits only allowlisted, validated fields to public lifecycle
evidence (`demo-qualification.json`); arbitrary extra report fields are not copied.
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
