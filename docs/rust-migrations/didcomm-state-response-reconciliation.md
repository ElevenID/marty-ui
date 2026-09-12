# Preserved dirty direct-state work: semantic reconciliation

This is a test/reference reconciliation, not another production migration or a
deployment. The old dirty worktree was **not missing production behavior**:
`9b4a8b67a8e73c8a355a4ca2118b64e534379413` already integrated the equivalent
implementation before this clean reconciliation base `3253f8a76`.

## Feature and test mapping

| Preserved old work | Existing integrated owner | Reconciliation |
| --- | --- | --- |
| `UnsupportedTransactionState(status)` | `InvalidTransactionState(status)` in `initiation_didcomm.rs` | Same state payload and eligibility phase; no duplicate enum or production patch. |
| Issued 409; Signing/Failed/Expired/Revoked 400 | `initiation_didcomm_http.rs` exact status/detail mapping | Existing whole-response direct HTTP corpus retained. |
| Five initial rejection cases and eligible continuation | `ineligible_states_match_captured_python_without_downstream_effects`, `eligible_states_continue_through_delivery_after_state_parity` | Existing tests retained unchanged. |
| Busy/unknown/binding fences, transported projection recovery and delivered replay before eligibility | `durable_delivery_dispatch_precedes_ineligible_transaction_state`, plus generic delivery/claim tests | Strengthen the existing five-state test with exact pending delivery/transported and claim snapshots after busy, unknown and wrong-holder fences; wrong holder after delivered replay remains rejected without downstream work. |
| `didcomm-state-python-reference.json` | `didcomm-direct-state-python-reference.json` | Same five status/body observations. Existing corpus additionally records one lookup per case. No parallel artifact. |

The old and integrated case arrays were compared after only renaming the old
`case` label to `state` and accounting for the existing explicit `lookup_calls: 1`.
All five observations match. Durable dispatch still precedes initial eligibility;
these response observations must never override known delivery, projection-only
recovery, concurrent/unknown outcomes, or holder binding.

## Reproducible reference

The existing capture command remains available; `--check` is additive:

```powershell
python scripts/capture_didcomm_direct_state_reference.py <credentials-checkout> --check
python -m pytest tests/test_didcomm_direct_state_reference.py
```

The checkout supplies pinned Git objects, not imported current application code.
The existing corpus source is `87eae30788924921a42848425d315e2f33f7ae41`; the old
dirty artifact identifies `9bd2747f040f203188529758ec38f0a5dce5ac5f`. Both revisions
were independently checked to contain these identical relevant blobs:

| Source | Git blob |
| --- | --- |
| `services/issuance/infrastructure/api/routes.py` | `6b3a7fa0e169862e815bcb6bca64b0b21a5adf6a` |
| `tests/unit/test_didcomm_boundary.py` | `f373c4d1762f916b616e4b83a38101112ec78e85` |
| `services/issuance/domain/entities.py` | `1b5e2eba90c1ec13c1a38135f4da92813f1d1073` |

Capture verifies all three blobs, executes the unchanged route body and trusted
organization helpers/request DTOs, the original `_request` fixture, and real
entity models. Only route registration decorators are removed for direct
invocation. It uses a controlled same-tenant repository and fail-if-called
delivery trap, then the actual FastAPI exception renderer. Synthetic configuration
replaces the capture environment and outbound socket operations are blocked
after local event-loop creation. No live service configuration or keys are read.

Python 3.12.10 / FastAPI 0.135.3 / Starlette 1.0.0 / Pydantic 2.13.0 reproduced
all five status/body observations, one lookup and zero deliveries each. This is
direct route-body/exception-renderer evidence, **not** deployed HTTP middleware,
PostgreSQL, cryptography, transport, or KMS acceptance. The corpus bytes and
metadata remain unchanged; its historical capture description predates this
safer AST extraction. LF-normalized SHA-256:
`19d6a6ea5a8adfdd9e07fb61a91a417427c5474193d92474dc585a78ee7ea891`.

Root-discovered guards do not import capture-time FastAPI dependencies. They
freeze artifact identity, reject observation/source drift, test the existing CLI
and additive check mode, and reject disconnected, ignored or cfg-disabled named
Rust gates. Existing mandatory workspace CI still executes the registered Rust
tests; these source guards are supplemental, not substitutes for execution.

Qualification on this reconciliation base: 36 filtered `initiation_didcomm`
library tests and all six `didcomm_delivery_behavior` HTTP tests passed with
Rust 1.95.0, locked/offline dependencies. Strict issuance `--lib --tests` Clippy,
issuance package formatting, Ruff, all 33 Python guards and the five-case
capture `--check` passed. No PostgreSQL/container gate was claimed or required
for this test-only strengthening. The initial whole-workspace formatting command
hit Windows argument-length limits before any test ran; the scoped issuance
format command succeeded and corrected one changed assertion's wrapping.

## Recoverability before cleanup

The old dirty tree remains untouched:
`_codex-worktrees/marty-ui-didcomm-state-response-parity-v1`, base
`c2cc53e15a5fc344f4ad2565e3e46444a39fc485`.
An exact recoverable patch of its three tracked changes plus untracked artifact
is retained locally at
`_codex-tmp/didcomm-state-response-old-dirty-20260913.patch` (workspace-relative).
SHA-256: `c55a642c97491dbe38c7c3e8bbb73082723fda86d37e36033a1e24a7efe268df`.
`git apply --reverse --check` passed against the still-dirty old tree. This patch
is local recovery evidence, not a release artifact. No branch, worktree, source
file, or artifact is deleted by this change. Cleanup requires the maintainer's
independent mapping/patch review and approval after the retained gates pass.
