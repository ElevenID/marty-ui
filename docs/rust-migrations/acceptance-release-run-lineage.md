# Acceptance release-run lineage

For the subsequent private-recorder prerequisite, see
[Private demo qualification before public beta acceptance](private-demo-qualification-lifecycle.md).
It reuses the run-identity parser below without changing the supported current
or historical stack-release triggers.

## Discovered compatibility gap

The lifecycle and wallet acceptance workflows still checked for a tag-branch
Stack release run. Lifecycle also required a `push` event. The digest-first
producer now dispatches `.github/workflows/cd.yml` on protected `main` and
publishes its immutable tag only after qualification. Those stale acceptance
checks reject the actual successful `v1.1.215` release run `33937499784`, whose
GitHub API record is `workflow_dispatch`, `main`, source
`1866528ab859ea7007ca34671ad80a62131fd79d`. This was found by comparing the
workflow predicates with the actual run record, not by dispatching a doomed
acceptance run or weakening browser assertions.

## Shared Rust correction

Both acceptance lanes now call `marty-release-evidence`'s
`validate-stack-release-run` binary using the authenticated repository-scoped
GitHub Actions API response. The pure validator has no network, deployment,
credential or signing implementation. It verifies the exact numeric run ID,
repository and head repository, successful completed status, workflow name and
path, source SHA, and one of two explicitly supported trigger/ref pairs:

- Current digest-first flow: `workflow_dispatch` on `main`.
- Historical evidence: `push` on the exact requested `v<version>` tag.

Lifecycle also passes its independently supplied release SHA. Wallet derives
the validated release SHA, keeps the distinct lifecycle tooling revision, and
checks the signed manifest's version/source and downstream evidence lineage
through the existing promotion validator. Neither lane treats a successful run
alone as proof of publication: all existing release-download, checksum,
attestation, manifest, browser/device and source-binding gates remain.

The new crate uses only already-locked serde/serde_json dependencies. Cargo.lock
adds its local package entry; there are no external dependency upgrades or
crypto-pin changes. Rust owns the shared validation; workflow shell only fetches
the API response and passes trusted expectations. Wallet runs this validation
from current checked-out tooling before selecting its separately bound evidence
tooling revision. This does not select untrusted code from the API response.

## Evidence and remaining work

The allowlisted actual215 run fixture and synthetic historical case pass. Tests
reject missing fields, wrong run IDs/repos/workflow paths/refs/events/sources,
unfinished/failed/cancelled runs, malformed JSON, invalid expectations and
oversized responses. CLI tests cover both workflow invocation shapes and ensure
failures produce no source or input-data echo. Actual fresh GitHub API output
for33937499784 passes both invocation forms and returns only its exact source.

Three Rust unit tests and two CLI integration tests pass, as do all-target
crate Clippy,70 existing/updated release/environment/documentation/wallet
promotion contracts and the Rust ownership checker. Workspace CI automatically
builds/tests/lints this new member. Maintainer review, protected merge gates and
actual release-bound lifecycle/device acceptance remain required. This patch
does not deploy, promote to production, produce device evidence, complete a
recording or prove the governed acceptance soak. Published215 remains immutable.
