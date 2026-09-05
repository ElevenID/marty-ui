# Actual Canvas worker process-signal gate

The published Python 3.12.13 issuance image
`ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`
was run as `python -m issuance.canvas_worker` in a network-isolated container.
Only synthetic secret values and an unavailable loopback database were supplied.
After observing initialized worker startup, SIGINT was delivered to that owned
container. Its observed exit code was **130**, not generic failure code 1.
The frozen process fixture records image, Python version, worker hash and scope.
This is actual published-process evidence, not successful database-cycle proof.

The first setup attempt exited before initialization because the synthetic
TOKEN_HMAC_KEY was missing. That failed setup is not signal evidence. Supplying
the required synthetic configuration allowed the actual worker to start; only
that initialized run supplied the frozen result. No beta credentials, database
or production container was used.

## Correction and executable verification

The Rust entry point now returns `ExitCode::from(130)` for cancellation only
after successful cleanup. Graceful completion remains zero. Work or cleanup
failure remains a non-success exit; successful work cannot hide cleanup failure.
The new cancellation regression failed against the previous mapping, then
passed with the distinct nonzero exit code. Original operation failures are
still preserved and all previous binary tests remain enabled.

Unix signal streams are registered synchronously before the owned worker can
start. This closes the startup ordering race found in review: database readiness
must not precede signal-handler registration. The handlers remain inline-owned.
SIGINT requests cancellation; SIGTERM retains the native graceful-drain policy,
which is not a claim of matching Python's default SIGTERM handling.

The existing mandatory Canvas worker PostgreSQL executable now launches the
actual Cargo-built worker binary with a cleared environment and synthetic
configuration. Four fixture cases deliver SIGINT or SIGTERM while the worker is
idle or waiting on a real PostgreSQL table lock:

- SIGINT must exit130 even while the test retains the blocking SQL lock.
- SIGTERM must remain alive while its cycle is blocked; releasing the lock lets
  it finish the cycle and exit0.

Readiness is observed through the real idle heartbeat or PostgreSQL lock-wait
state under a unique application name, not a fixed startup sleep. Signals target
only an unreaped owned child PID. RAII kills and reaps the child if an assertion
fails; there is no process-name or process-group targeting. Child output is not
retained and inherited credentials are not supplied.

CI checks the actual worker executable exists alongside the ten existing SQL
contract executables. The contract runs on the same Linux runner/build tree;
it does not replace the process with a unit-test harness. Windows compiles the
portable harness but explicitly does not execute POSIX signal cases. Only the
mandatory Linux PostgreSQL run can establish those process assertions; a local
Windows pass does not establish them.

## Remaining boundaries

These empty-queue process tests complement the existing held-connection disposal
and controlled active-job tests. Exit after process termination alone is not
proof that asynchronous cleanup ran; the held-connection test independently
proves the completion-before-disposal ordering is forbidden.

Real provider I/O, active authoritative-processor process signals, published
migration schema, SIGKILL/host failure and full-worker parity are not established
here. No deployment consumer, Python implementation, crypto pin or release
coordinate changes. All remaining worker cutover and aggregate beta acceptance
requirements remain mandatory before immediate gated Python deletion.
