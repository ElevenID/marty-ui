# Customer-managed systemd lifecycle

The retained Linux operator exports installation-scoped **user** systemd units
for a fresh rootless Compose installation. The customer owns Docker, user
lingering, host storage, networking, and service enablement. Every operation
uses the installation lock and binds the retained release, operator, Docker
engine, Compose project, authenticated files, and current credential generation.

The v2 lifecycle connects cold recovery and recurring maintenance. Local tests
of these mechanisms are distinct from an actual host reboot, daemon restart,
backup restore, or public browser qualification. Its reports continue to say
`installation_ready: false`; enabling a timer is not release qualification.
Existing v1 unit exports are not adopted or upgraded by this fresh-install release.

Cold recovery validates the complete authenticated Compose model while starting
only the explicit retained infrastructure dependency group. The ingress binding,
application containers, and completed setup identities remain visible to policy
and ownership checks; initialization cannot be replayed by this partial start.
An interrupted start is reconciled against the exact model digest in its original
intent before another lifecycle operation can proceed.

An older retained operator can refuse this infrastructure-only start before any
start intent is written because its reduced model omits the bound ingress. Preserve
that installation and its evidence. The lifecycle configuration binds the original
signed operator and inventory; replacing that binary is not a supported upgrade.
Qualify this correction using a fresh installation from a signed release containing
it. An unchanged generation or a refusal before a start intent is not a renewal
or restart pass.

Maintenance capabilities depend on the retained owners and selected generation.
The recurring generation owner supports public ACME generations and
installer-managed private-CA generations; imported foundation credentials remain
customer-managed. The capability map identifies that owner for both supported
sources without asserting installed renewal success. Lifecycle install and status
copy the selected generation owner's `automatic_renewal_supported` observation, or report
`null` if that evidence is unavailable. Export and action reports do not infer
all-mode renewal support. OpenBao listener TLS recovery has its separate retained
local-control authority and does not establish application-credential recovery.

## Export and install

Run the retained operator as the existing non-root installation owner:

```sh
/absolute/installation/marty-deploy lifecycle export \
  --install-dir /absolute/installation --docker-bin /usr/bin/docker
/absolute/installation/marty-deploy lifecycle install \
  --install-dir /absolute/installation --docker-bin /usr/bin/docker
```

`export` returns unit text without writing it. `install` saves an immutable
configuration, five units, and initial paused intent under `evidence`. An
interrupted export can complete only byte-identical files. Conflicting units,
foreign records, broken intent chains, or changed paths are refused.

| Unit | Responsibility |
| --- | --- |
| `lifecycle-marty-UUID.service` | Reconcile the installation at user-manager startup and stop owned runtime at shutdown. |
| `lifecycle-marty-UUID-check.service` | Read-only deployment and OpenBao certificate inspection. |
| `lifecycle-marty-UUID-check.timer` | Run checks every five minutes with persistent catch-up and up to 30 seconds of jitter. |
| `lifecycle-marty-UUID-maintenance.service` | One bounded recovery and credential-maintenance invocation. |
| `lifecycle-marty-UUID-maintenance.timer` | Run maintenance every five minutes with persistent catch-up and up to 30 seconds of jitter. |

The generated check and maintenance commands include `--scheduled`. Only those
two actions accept it. They wait up to 30 seconds, measured by a monotonic
clock, for the same exclusive installation lock. A still-busy lock returns an
explicit `result.outcome: deferred` with no journal observation, Docker call,
intent change, validation success, or readiness claim. A later timer activation
can try again; the deferred invocation does not retry an operation that has
already begun. Other lock errors, unsafe paths or permissions, and corrupt
journals remain failures. Ordinary commands without `--scheduled` retain
immediate lock refusal, including status and manual lifecycle controls.

The check service's 180-second start limit reserves 150 seconds for its work
and 30 seconds for lock acquisition. Maintenance reserves its existing
1800-second work budget plus the same 30-second wait, for a total of 1830
seconds. These limits do not change the installation's durable intent or any
external trial deadline. Existing installed units remain pinned to their
original operator and recorded bytes; they are not rewritten by this change.

Export, install, and configured status return an exact
`next_actions.manual_recovery_command`.
Manual recovery does not require lingering or persistent user-service enablement;
it still requires the retained Docker engine to be accessible and running to be
intended. Export, install, and status observe the user-manager prerequisites
before returning unattended enablement instructions.

`unattended_eligible` applies only to the observed user-systemd prerequisites:

| Value | Meaning | Returned next action |
| --- | --- | --- |
| `true` | Lingering is enabled and the installation owner's rootless Docker user unit is loaded, persistently enabled, and active. | Review the exact `next_actions.commands` arrays and run them as that owner when running is intended. |
| `false` | At least one prerequisite is observed missing, or the observation belongs to root or another user. | Follow `prerequisite_remediation` and rerun lifecycle status. Unattended enablement commands are withheld. |
| `null` | No prerequisite is known false, but at least one observation is unavailable. | Use the returned read-only verification commands in the installation owner's host session, resolve the unavailable observation, and rerun lifecycle status. Unattended enablement commands are withheld. |

The customer or host administrator must enable lingering, install or repair the
rootless Docker user unit, and enable and start that unit as needed. The operator
does not perform those changes. `true` does not establish that Marty's units are
enabled, that a reboot has been tested, or that the installation is qualified.
`systemd_enablement_observed` remains `false`.

Once all prerequisites are observed as true, the returned commands have this
form. Substitute the actual UUID and paths; quote shell paths as necessary:

```sh
/absolute/installation/marty-deploy lifecycle resume \
  --install-dir /absolute/installation --docker-bin /usr/bin/docker
systemctl --user link \
  /absolute/installation/evidence/lifecycle-marty-UUID.service \
  /absolute/installation/evidence/lifecycle-marty-UUID-check.service \
  /absolute/installation/evidence/lifecycle-marty-UUID-check.timer \
  /absolute/installation/evidence/lifecycle-marty-UUID-maintenance.service \
  /absolute/installation/evidence/lifecycle-marty-UUID-maintenance.timer
systemctl --user daemon-reload
systemctl --user enable --now lifecycle-marty-UUID.service \
  lifecycle-marty-UUID-check.timer lifecycle-marty-UUID-maintenance.timer
```

Unit commands use literal argv without a shell, credential values, or an
`EnvironmentFile`. Spaces, percent signs, and dollar signs in installation
paths are supported. Quotes, apostrophes, and backslashes in the executable
path are refused because systemd rejects them. This is not a relocation API.

Status performs bounded, read-only observations of the current user's lingering
and `docker.service` load, enablement, and active state. An unavailable
observation is `null`, distinct from observed `false`. Runtime-only unit
enablement does not satisfy reboot enablement. The observer does not enable
services, change lingering, install packages, or operate another user's manager.
Installation-unit enablement itself is not inferred from Docker's status.

The customer must keep the installation, rootless Docker state, and linked units
on storage available before user-manager startup. Follow Docker's
[rootless user-service guidance](https://docs.docker.com/engine/security/rootless/tips/).
The optional privileged HTTP-01 socket bridge is a separate customer-admin
operation described in [HTTP-01 host routing](installer-http01-host-bridge.md).

## Durable stop, pause, resume, and security seal

```sh
/absolute/installation/marty-deploy stop --install-dir /absolute/installation
/absolute/installation/marty-deploy lifecycle pause --install-dir /absolute/installation
/absolute/installation/marty-deploy lifecycle resume --install-dir /absolute/installation
/absolute/installation/marty-deploy lifecycle security-seal --install-dir /absolute/installation
/absolute/installation/marty-deploy lifecycle status --install-dir /absolute/installation
```

| Recorded intent | Scheduled behavior | How to resume |
| --- | --- | --- |
| Initially paused | No runtime operation; exporting units does not stop an already-running stack. | `lifecycle resume` |
| Running | Boot and maintenance reconcile; check observes. | Already enabled by intent. |
| Manually paused or stopped | No startup or renewal. A pending stop is reconciled to stopped. | `lifecycle resume`, or the retained ordinary `start` command. |
| Security sealed | No startup or renewal. Reconcile all owned runtime to stopped. | Explicit `lifecycle resume` only. |
| Uninstalled | No automatic recreation of removed resources. | A separate supported installation or restore operation is required. |

Intent is persisted before Docker mutation under the same lock. A failed stop
or security seal leaves the request durable but does not claim that the process
stopped. Boot and maintenance can converge that pending stop. The read-only
check never changes runtime. An ordinary stop, pause, or uninstall cannot
silently downgrade security-sealed intent to a pause that ordinary start clears.

Security sealing stops the entire owned runtime, including the OpenBao process,
so its in-memory unsealed state is discarded. It preserves the existing static
seal key, recovery key, persistent store, and signing keys. This operation does
not call the OpenBao seal API and does not claim protection from an administrator
who can read the host's protected seal material or bypass these controls.

Ordinary system shutdown stops runtime **without** changing running intent.
Stopping the boot unit directly is therefore transient. Use the supported stop
or pause command for maintenance that must survive reboot. After uninstall,
disable the exact installation boot service and both timers. Ordinary uninstall
preserves host data, credentials, recovery material, images, and named volumes.

## Cold recovery and recurring maintenance

While running is intended, `boot`, `maintain`, and explicit resume perform the
following serialized work:

1. Let the generation owner reconcile a retained incomplete replacement before
   ordinary current-session inspection. Only that recorded transaction can
   admit an intermediate mixture of old and replacement container IDs.
2. Observe retained native container identities and apply the bounded
   infrastructure health policy if a process is alive but persistently unhealthy.
3. Start only the retained OpenBao, readiness watcher, and HTTP-01 responder.
   OpenBao readiness uses its local Unix control socket, so an expired HTTPS
   leaf does not prevent this step.
4. Reconcile OpenBao's TCP certificate through the fixed local recovery helper,
   reload the exact owned OpenBao process, and verify HTTPS against the retained
   issuer and selected leaf. No TLS verification bypass is used.
5. Finish an already-authorized initial-root retirement if its helper response
   was lost. Maintenance does not authorize a new retirement. An unfinished
   retirement and a new generation activation cannot advance concurrently.
6. Authenticate the selected generation's current usability. A public generation
   can start before provider maintenance when its certificate is valid now and
   its credentials remain strictly within the conservative 1,800-second age
   window established by their retained observation. This check uses no new
   certificate-admission margin and does not treat pending ACME work as an
   application replacement. Missing, conflicting, or invalid evidence is an
   error, rather than a stale-generation classification.
7. If that selection is usable, apply bounded application health repair, start
   the exact retained runtime, and validate it before provider work. Otherwise,
   the credential-generation owner must run first, followed by application
   health repair, retained startup, and validation.
8. Run the single credential-generation owner when it has not already run. It
   uses retained scoped machine identity, stages immutable replacements,
   reconciles recorded activation, and selects only a verified successor.
   Public certificate orders belong to the due ACME cycle; a token-only refresh
   carries the existing valid chain. When the runtime started first, validate
   the selected runtime again after successful maintenance. The generation
   owner starts any successor itself; lifecycle does not repeat application
   health repair or startup in this pass.

A provider outage therefore cannot prevent an already-usable selected public
runtime from restarting. A provider or integrity error still fails the
maintenance invocation and remains visible; early startup does not turn that
failure into a success report. Expired certificates and credentials outside the
conservative age window remain on the maintenance-first path. Private or imported
generations do not gain this public-generation shortcut.

Successful reports include `current_generation_startup` and
`application_started_before_generation_maintenance`, so the reported startup
operation can be distinguished from a later successor activation. These fields
do not establish deployment readiness or host reboot qualification.

The first failed stage is reported. A missing seal key, changed input, unavailable
scoped authority, full disk, or uncertain activation does not authorize new
initialization, key recreation, or adopting another store. TLS and workload
recovery use scoped authority. The separate retirement helper may use the
original root only to confirm and revoke that exact credential under its saved
authorization. See [OpenBao local recovery](installer-openbao-local-recovery.md)
and [public generations](installer-public-ingress-generation.md).

The lifecycle configuration remains anchored to the initial admitted application
session. Later selected sessions must prove their authenticated generation
lineage back to that anchor. Certificate renewal does not rewrite the unit
configuration or discard maintenance intent.

## Qualify a stopped private-CA installation

Use the retained installation owner and operator for this probe. Keep a public
record of the installation ID, Docker engine ID, selected generation sequence,
and application fixtures before stopping the host. `lifecycle status` reports
the selected generation and whether credential refresh is due. `trust-info`,
while the selection is valid, reports the public certificate expiry and
`recorded_token_expires_at`; retain those timestamps without exporting secret
files.

The current managed private-CA producer issues eight-hour leaves and tokens.
The generation owner considers credentials due for refresh after thirty
minutes, so stale-generation renewal can be tested before expiry. The public
CLI has no short-TTL or force-renew option. A stale-generation test and a real
offline-expiry test must be recorded separately. For expiry qualification, keep
the installation paused or the host offline until the recorded validity window
has actually passed; do not change the clock, edit generation evidence, or
replace credentials by hand.

Set the actual retained path and use the Docker executable recorded during
installation:

```sh
marty_install_dir='/absolute/retained/installation'
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  lifecycle status --install-dir "$marty_install_dir" --docker-bin /usr/bin/docker
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  lifecycle pause --install-dir "$marty_install_dir" --docker-bin /usr/bin/docker
```

After a successful pause, the customer can stop and start the disposable host
using its normal platform controls. Pause persists across that restart; the
stack must remain paused until explicit resume. Once the same user's rootless
Docker is available, run the exact `next_actions.manual_recovery_command`
reported by lifecycle status under `setpriv --no-new-privs`, or its equivalent:

```sh
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  lifecycle resume --install-dir "$marty_install_dir" --docker-bin /usr/bin/docker
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  lifecycle status --install-dir "$marty_install_dir" --docker-bin /usr/bin/docker
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  validate --install-dir "$marty_install_dir" --docker-bin /usr/bin/docker
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  trust-info --install-dir "$marty_install_dir"
```

Inspect the resume result's generation and OpenBao recovery outcomes, compare
the selected generation and public validity timestamps, and verify the same
application fixtures remain usable. `lifecycle maintain` exercises the same
recovery while running is already intended; it does not clear a deliberate
pause. Preserve the first failing stage and retained evidence if recovery
blocks. Replaying the bootstrap, an initial provisioning job, or a Kubernetes
credential-recovery script is not a continuation of this native installation.

This probe establishes manual recovery for the observed interruption and
credential age. It does not establish automatic no-login reboot recovery;
that requires enabling the returned user units and a separate unpaused reboot
test. Neither observation grants production readiness.

## Sustained unhealthy processes

Docker's restart policies handle exited processes. The operator's separate
health owner can restart one **already-running, unhealthy, owned** runtime
service per pass. It does not rerun setup jobs or use a blanket restart loop.

A service must have remained unhealthy across observations for at least ten
minutes. Required upstream dependencies must be healthy or successfully
completed according to the native Compose model. After a repair attempt there
is a thirty-minute cooldown and a maximum of two attempts per service in a
rolling 24-hour window. An interrupted or unconfirmed restart consumes the same
budget as a confirmed attempt. Changes in container identity reset sustained
unhealthy observation, while the service's recent repair budget is retained.

Infrastructure and application are separate passes in a maintenance invocation,
so at most one service in each pass can be repaired. The fixed Compose operation
is a bounded `restart --no-deps`; every retained resource identity must remain
unchanged. Post-restart native health is observed, not inferred from a successful
client exit. A failing dependency blocks repair of its dependents.

`health-checkpoint.json` is an atomically replaced bounded checkpoint with an
exact recoverable pending successor. Thousands of timer observations do not
produce thousands of observation files. Actual repair operations retain their
immutable native intents and results. Missing or conflicting checkpoint state
fails closed rather than silently resetting the repair budget. The customer
owns diagnostic retention and monitoring of failed checks and timers.

## systemd behavior and remaining qualification

The boot unit is ordered after the customer's rootless Docker user service.
Checks and maintenance are ordered after boot and hold the same installation
lock as manual commands. The worker is a bounded oneshot without
`RemainAfterExit` or its own restart loop. Docker owns container process
restarts; systemd owns scheduling and host startup.

The boot service allows a small bounded number of startup attempts. Re-entry
reconciles durable operation state and does not replay initialization or an
unknown public order. The native stop/start owner can reobserve an uncertain
idempotent command; destructive removal is not automatically replayed.

The supported-host qualification must still exercise an actual no-login reboot,
a Docker daemon restart, killed application and database processes, persistent
fixtures, offline credential expiry, and pause/security-seal across reboot.
The official OpenBao binary tests establish component behavior; they do not
stand in for these assembled-host observations.

Primary references:

- [Docker restart policy guidance](https://docs.docker.com/engine/containers/start-containers-automatically/)
- [Compose startup and dependency readiness](https://docs.docker.com/compose/how-tos/startup-order/)
- [systemd 255 command-line quoting](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html#Command%20lines)
- [systemd 255 persistent timers](https://www.freedesktop.org/software/systemd/man/255/systemd.timer.html#Persistent=)
