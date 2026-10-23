# Official conformance before stack publication

Product CD prepares and attests the exact five-role manifest from its durable
digest transaction before version-tag promotion. It calls the shared official
suite at immutable integration main source `7b0a46e57ac254067c5069654498327f3ff366d6`,
including the product's KMS-only setup. All seven lanes must succeed.

The no-write release claim checks that the literal harness pin is an ancestor
of integration `main`, and matches the caller's `harness_revision`. Pin the
accepted merge commit after integration, rather than a squash-merged PR head
whose branch can be deleted. Candidate run 39873517844 could not resolve the
old PR-head reusable workflow; restoring its original branch allowed run
39874228600 to start. That ref remains preserved for reproducibility of the older source.
The accepted merge commit has the identical Git tree to the reviewed PR head.

Native conformance startup uses the shared release validator in Rust-only mode
both before and after manifest attestation. It requires the five current KMS
image roles and rejects retired Python issuance components. Candidate run
39874228600 built and passed its five image/runtime gates, but all seven official
lanes stopped before assertions because this startup check still selected the
legacy manifest policy. The corrected preflight passes against that actual
candidate, including real GitHub manifest attestation and its committed native
capability floor. This read-only check is not an official protocol pass; the
failed lane summaries remain failed and a fresh candidate execution is required.

Candidate run 39886188606 completed KMS-only bootstrap and all five image/runtime
gates, but its seven official lanes failed native startup before protocol
assertions. The run step did not supply GitHub authentication for manifest
attestation. The same immutable manifest passes the native release preflight
with authenticated `gh attestation verify`; this is not a protocol qualification.

The shared harness supplies its read-only job token only to trusted native
startup and strips all GitHub authentication aliases before invoking upstream
suite processes. The common subprocess environment helper enforces this boundary
for both the lane runner and the stack adapter. Native preflight failures report
the failing stage and exit code without exposing command output or credentials.
A fresh exact-source candidate must pass all seven official suites; the failed
run and its summaries remain unchanged.

Candidate run 39902897491 passed authenticated native preflight and KMS-only
bootstrap, but all seven lanes stopped before assertions because the Envoy
issuance bridge retained a source build without a released image binding.
The GHCR overlay now selects the same immutable services artifact for that
bridge, preserving its keyless entrypoint and scoped KMS configuration.
Released startup rejects any remaining source build in the rendered graph,
and the isolated executable probe checks both issuance and bridge linkage.
These startup checks do not establish a protocol pass.

Local execution then exposed a second startup defect: Compose restarted
`openbao-init` after the disposable KMS bootstrap had completed. The production
initializer correctly refused the already-initialized Raft state. Native resume
now verifies the exact project, service, image and successful completion of both
bootstrap jobs, plus the running healthy OpenBao container. It explicitly starts
the selected runtime graph with `--no-deps`, preserving migration and health
ordering while leaving those verified bootstrap services untouched. Missing,
foreign, failed or unhealthy custody prevents startup. Fresh runs still execute
the original strict ceremony; its fresh-state guard is unchanged.

The reusable suite verifies product `cd.yml` provenance, exact protected-main
source, independent manifest digest and all five KMS image roles. It does not
require a public release or modify the ordinary reviewed release pin. Its
sanitized summaries explicitly identify an unpublished candidate.

The Rust `validate-official-suite` verifier requires seven distinct successful
lane summaries from the current release run and attempt, bound to the same
source, manifest and harness. Missing, mismatched, failed, entirely skipped,
pre-activation and empty official evidence fail closed. The digest of the
allowlisted receipt becomes required `official_interoperability` transaction
evidence. The current-run public summaries are retained alongside that receipt.

Publication copies the exact tested manifest bytes and checks their independent
producer digest. It does not regenerate a potentially different manifest.
There is no conditional bypass or continue-on-error path through qualification.
Old five-gate transactions cannot qualify or resume under this new policy;
they remain historical evidence and must not be rewritten as passing it.

Source checks and synthetic unit controls do not establish an official pass.
The adapter and product gate must complete protected integration and a real
candidate execution before claiming release qualification. Keep beta runtime,
disposable conformance stacks, demo acceptance and editorial review distinct.
