# Official conformance before stack publication

Product CD prepares and attests the exact five-role manifest from its durable
digest transaction before version-tag promotion. It calls the shared official
suite at immutable integration source `4b86dced7bacb54df225d46080bd080f3af344d8`,
including the product's KMS-only setup. All seven lanes must succeed.

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
