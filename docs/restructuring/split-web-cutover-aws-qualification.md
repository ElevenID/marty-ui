# Focused Docker qualification after website removal

`scripts/qualify_split_web_cutover_aws.py` qualifies one exact integrated Marty
commit on the existing disposable Linux amd64 host. It supplements the completed
package/profile/export/consumer checks and the separate pre-removal split-web
qualification. It does not create AWS resources, publish a registry image,
produce a signed receipt, select production traffic, or exercise authentication.

The four stages are deliberately limited:

1. Build the actual `docker/ui.Dockerfile` `application` target.
2. Build its actual `selfhost` target with the full customer profile and
   `nginx.spa.conf`.
3. Start the built images on an isolated Docker network. Check application and
   console entries, entry assets, release/source/audience markers, runtime
   configuration, absent marketing static files, application API error forwarding,
   and the customer console-only startup boundary and query-preserving alias.
4. Run all four tests in `ui/scripts/test_nginx_application_routes.py` against its
   pinned Nginx image, including production/static/dev/OKE routing and all eight
   customer/console section combinations. The original assertions are unchanged;
   the transport adds this run's ownership labels and container resource bounds.

The two builds use the same target and dependency argument choices as the UI
branches of `scripts/build-push-registry.sh`. The broad registry script is not
invoked: it also handles services, operator admission and registry behavior.
Dependencies come from the selected commit's `release/stack-lock.json`; their
release URLs and SHA-256 digests remain explicit build arguments. Bun 1.4.4 and
Nginx 1.29.1 bases must match the reviewed immutable Docker digests.

## Required host and source state

Use the existing non-root user, rootless Docker socket at
`/run/user/UID/docker.sock`, systemd user service, cgroup v2, and enabled linger.
Docker Buildx, Git and Python 3.10 or newer must already exist. This gate does not
need a host Node/Bun installation or Chrome. It requires at least 3 GiB available
memory and 8 GiB free space; wait for the earlier qualification before starting
if the host does not meet those bounds. There is no pruning or host provisioning.

Keep the runner checkout, product checkout and evidence directory separate.
Select a complete lowercase 40-character commit, not a branch or tag. The runner
requires that exact clean HEAD and verifies every tracked file's Git blob bytes
and mode, even when an index flag could hide a worktree change. Git replacement
objects are disabled. It copies only those verified files into its own build
context, excluding ignored host settings, credentials and installed dependencies.
It verifies the source and copied inputs again after the checks.

The evidence root must be new and have an existing parent. Its `temporary`
subdirectory must fit within 60 UTF-8 bytes, preserving the established short
temporary-path rule. Never reuse an earlier attempt's evidence directory.

## Invocation

The operator supplies the exact reviewed source and existing host paths:

```bash
CUTOVER_RUNNER=/home/marty/development/cutover-runner/scripts/qualify_split_web_cutover_aws.py
CUTOVER_SOURCE=/home/marty/development/cutover-source
CUTOVER_COMMIT=REPLACE_WITH_THE_EXACT_REVIEWED_40_CHARACTER_COMMIT
CUTOVER_EVIDENCE=/home/marty/cutover/e
CUTOVER_SOCKET=/run/user/$(id -u)/docker.sock

python3 "$CUTOVER_RUNNER" plan \
  --marty-root "$CUTOVER_SOURCE" --source-commit "$CUTOVER_COMMIT" \
  --evidence-root "$CUTOVER_EVIDENCE" --docker-socket "$CUTOVER_SOCKET"

python3 "$CUTOVER_RUNNER" preflight \
  --marty-root "$CUTOVER_SOURCE" --source-commit "$CUTOVER_COMMIT" \
  --evidence-root "$CUTOVER_EVIDENCE" --docker-socket "$CUTOVER_SOCKET"

python3 "$CUTOVER_RUNNER" run \
  --marty-root "$CUTOVER_SOURCE" --source-commit "$CUTOVER_COMMIT" \
  --evidence-root "$CUTOVER_EVIDENCE" --docker-socket "$CUTOVER_SOCKET" \
  --deadline-utc 2026-11-21T08:50:00Z
```

The deadline above is the reviewed window for this disposable-host session;
retain its existing automatic stop. A later session needs its own authorized
deadline. The runner admits a deadline 5 minutes to 3 hours ahead, bounds each
stage in its own systemd user unit, and reserves cleanup time. It stops after the
first failed stage. It does not rerun the earlier 31-stage suite.

## Evidence and cleanup

`qualification.json` records source/tree identity, runner/helper hashes, exact
Docker recipe and artifact inputs, initial container IDs, per-stage log hashes,
owned resource cleanup, and retained local output image IDs. `image-smoke.json`
contains actual HTTP/image observations; `plan.json` and `source-inventory.json`
retain the command and source boundaries.

All diagnostic containers and networks carry a random per-run ownership label.
Cleanup enumerates only that label, verifies ownership before removal, and
refuses to remove a container present before this run. Timeout cleanup stops
only the stage's own systemd unit. Existing container IDs must still exist at
the end; unrelated concurrent containers are reported without modification.
The two completed local output images are retained by immutable ID for review.
Fixture images are removed. No daemon-wide stop, image/system prune, shared
network teardown, registry login, push, signing or deployment is performed.

A failed or interrupted build remains failed evidence even if owned resources
were removed successfully. Preserve its report and logs; do not treat the local
images or unsigned diagnostics as a production release or a completed switchover.
