# Packaged worker startup and configuration sources

Status: all 24 cases passed locally and in hosted image job `101527827400`
at `505dcf50660e3ca74004d1765bb642c47fc234e7` (CI `34048520936`).
The hosted startup markers are recorded at 2026-09-06 17:39:03 UTC.
That head also passed all 65 configured runtime tests in 1165.59 seconds
(job101527827413) and Rust CodeQL34048520957.
This extends the [image preflight](canvas-worker-image-entrypoint.md)
and [frozen startup reference](canvas-worker-startup.md), not whole-worker
acceptance or permission to switch deployed consumers.

Every one of the eight independently frozen startup cases runs under each of
three configuration modes (24 native container starts):

| Mode | Worker selector | Master key | Database URL |
| --- | --- | --- | --- |
| Direct | `canvas-sync-worker` | Direct environment value | Direct value, using the reference case's scheme |
| Files/template | `canvas_sync_worker` | CRLF secret file; API/HMAC keys also use files | Template expanded after reading the CRLF database-password file |
| Selected environment | `canvas-sync-worker` | Operator-selected variable through `INTEGRATION_SECRET_MASTER_KEY_ENV` | Direct value, using the reference case's scheme |

Both `postgresql` and `postgresql+asyncpg` forms retain their original case
assignments. Missing/empty/partial/invalid LTI identity and enabled/disabled
integration settings retain the original frozen inputs. The expected heartbeat,
liveness and empty-queue observations are the existing independently captured
startup corpus; no expectations were recaptured or weakened for packaging.
Configuration modes exercise the normative key-source/consumer requirements,
not newly claimed published-image captures for those combinations.

The fixture creates a network-none tmpfs PostgreSQL instance with no published
ports. The existing official migration probe runs from its immutable issuance
image in that database container's network namespace. It verifies worker-source
hash and migration revisions before any native process starts. There is no new
migration owner, handwritten replacement schema or deployment database input.

Each native worker shares only that isolated namespace and receives fixed
synthetic inputs and read-only secret files. Its unique worker ID must produce
the exact reference idle heartbeat. It must still be alive before SIGINT, then
exit with the established native 130/reference -2 mapping and zero queued jobs.
No heartbeat, job, lease or timestamp is edited. The full observation is compared
strictly, including rejection of unexpected fields; all synthetic secret values
must remain absent from startup logs.

Both image gates share one exact-ID container owner. Context unwinding removes
worker, migration probe and database, including when an inner cleanup fails.
Bounded readiness, command and process waits remain explicit. Unit tests cover
24-case configuration coverage, strict comparison failures, observation errors,
deadline exhaustion and nested cleanup. They are not runtime parity evidence.

The known pre-worker local issuance image was used as a negative control. The
official migrations and provenance assertions passed, but that image could not
produce the required worker heartbeat and the harness rejected it at its bounded
deadline. All labelled fixture containers were gone afterward. This validates
the failure path, not any positive native-image startup claim.

Provider/signing/OAuth effects, all deployment
consumer definitions, migration ordering, headless health semantics and beta
acceptance remain separate requirements in the
[cutover inventory](canvas-worker-cutover-readiness.md). Production and persistent
self-host remain unchanged.

Local validation: all 867 executed repository Python contracts pass in 36.35
seconds, with the existing opt-in verifier containerd/Buildx case skipped.
Ruff formatting/lint and diff checks pass. The configuration/comparison/cleanup
tests and negative image control do not replace positive runtime qualification.

The subsequent actual local Linux image run passed all eight preflight cases and
all 24 packaged startup cases from clean source `2e282db33`. The test-only image
`marty-canvas-worker-startup:local-2e282db` has image ID
`sha256:e58b71863e9a9592eb32f2695f363c93d4126412dc9907b839babf977d41cb3d`.
It was built from the pinned CI issuance Dockerfile; release compilation passed.
All exact heartbeat/liveness/empty-queue/SIGINT and synthetic-secret-log checks
passed, and no labelled fixture containers remained after completion. No
deployment image was replaced or published. Hosted image execution subsequently
passed at `505dcf506` as recorded above; full runtime regression and the remaining
cutover gates must also pass before switching consumers.
