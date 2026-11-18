# Published and native Canvas worker startup

Status: eight actual-process startup/idle-heartbeat cases match locally on the
published PostgreSQL migrations. The candidate remains unrouted; these empty
queues do not qualify authoritative provider work or every deployment consumer.

## Independent reference

The compact inputs in
[`canvas-worker-startup-scenarios.json`](../../contracts/canvas-worker-startup-scenarios.json)
cover disabled rollout with missing, empty, organization-only, DID-only and
complete identity, plus enabled rollout with missing, invalid-DID and complete
identity. Both deployed PostgreSQL URL forms are exercised. All cases use valid
synthetic secret inputs and the actual default Python processor loader; none
changes application code, database queries, clocks or lifecycle policy.

`scripts/run_canvas_worker_startup_oracle.py` runs eight real
`python -m issuance.canvas_worker` children inside the pinned published image.
The existing `PublishedDatabase` owner supplies the official migration schema,
minimal synthetic organization dependency, provenance checks, read-only mounts
and exact-ID cleanup. No deployment URL or credential is accepted.

The image is
`ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`,
CPython 3.12.13. The frozen artifact retains worker and Canvas-router source
SHA-256 values. Two independent complete raw captures have SHA-256
`4b6818b8f1e521fa74705e130b0721eb8a7fa9f61d78fa371935907c50a918cd`.
Their observations were frozen before the native initialization change.

Every published process reaches an idle heartbeat, stays alive, reports a
configured standalone processor with zero leased jobs, and leaves the job table
empty. Missing or invalid LTI identity does not prevent that empty-queue cycle.
The probe interrupts each owned child only after observing its heartbeat; logs
are discarded, and all child handles are reaped in normal and failure paths.

The raw Python `subprocess` return value is -2 after SIGINT, retained unchanged
in `exit_code_after_interrupt`. Its shell/Docker representation is 130; the
existing native contract returns 130 after cancellation cleanup. This transport
representation is normalized explicitly in the native comparison, not by
rewriting the independently captured reference or treating termination as success.

## Native correction and regression

The first actual native replay failed at `disabled_missing_identity`: the
process exited before its idle heartbeat. The binary previously required both
identity fields at construction, even though deployment defaults leave them
empty with rollout disabled.

The correction passes the configured values, or their existing empty defaults,
to the canonical `IssuerDidCanvasLtiToolJwtSigner`. That owner already trims and
validates identity before resolution or signing. The redundant eager-required
helper is deleted; no second signer, configuration policy or provider is added.
Secret loading, URL policy, scheduling, leases and rollout rules are unchanged.

The expanded signer test verifies missing, whitespace, partial and invalid-DID
configuration, plus absent signing authorization, against both signing and JWKS
operations. Each must fail before any identity-resolution or signature request.
Previously covered method/key checks remain intact.

The new required published-schema gate regenerates the entire frozen Python
artifact, then launches the actual Cargo-built Rust worker for each input. It
compares the full selected heartbeat metadata, role, continued liveness and
empty job count on the same published schema. It reuses the existing owned-child
and signal helper; original idle/blocked SIGINT/SIGTERM cases are retained.

The initial Windows run after the runtime correction exposed a harness issue:
the cleared child environment also omitted `SystemRoot`, preventing a database
heartbeat. Preserving only that standard Windows OS path made all eight cases
pass. Application environment and credentials remain cleared. Timeout diagnostics
report only case name and persisted phase, never child logs or connection data.

Windows proves actual startup and database heartbeat and then reaps the child.
It does **not** prove POSIX signaling. The configured Linux CI gate additionally
delivers SIGINT and requires the previously established exit representation.
Hosted exact-head checks remain mandatory before protected landing.

All 37 configured image/schema tests pass locally in 322.87 seconds, with none
ignored or filtered. The 325 library, 5 worker-binary, 22 issuance-behavior and
53 affected Python tests pass, as do strict all-target Clippy, formatting and
CI Bash syntax. The exact owned published-schema fixture inventory is empty.

## Remaining scope

This closes the recorded LTI-identity startup mismatch, not arbitrary bootstrap
configuration, missing secret-source policy, nonempty REST/AGS/NRPS/OAuth work,
whole readiness/activation, active-provider cancellation, or image entrypoint
selection. Continue with the composed worker/provider/published-schema gate in
the [cutover inventory](canvas-worker-cutover-readiness.md). Keep every normative
legacy gap and deployment consumer; do not infer Python deletion or beta
acceptance from an empty-queue startup pass. Production remains unchanged.
