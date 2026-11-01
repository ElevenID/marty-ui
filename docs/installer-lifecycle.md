# Customer-managed systemd lifecycle

The retained Linux operator can export installation-scoped **user** systemd
units for an existing rootless Compose installation. It uses the installation's
recorded Docker engine, project, authenticated Compose inputs, and retained
operator. It does not provision a host, enable a user manager, install Docker,
replay setup jobs, or adopt another installation.

This is the initial lifecycle implementation. The units start and stop existing
runtime containers and run read-only deployment checks. Automated certificate
renewal and recovery after credential expiry remain separate work. The command
reports `installation_ready: false`; creating or enabling these units is not
evidence of successful reboot recovery.

## Export and install

Run the retained operator as the installation's existing non-root owner. The
installation must already have its authenticated Compose maintenance session
and the original retained operator must still match the recorded release
inventory.

```sh
/absolute/installation/marty-deploy lifecycle export \
  --install-dir /absolute/installation \
  --docker-bin /usr/bin/docker

/absolute/installation/marty-deploy lifecycle install \
  --install-dir /absolute/installation \
  --docker-bin /usr/bin/docker
```

`export` returns the rendered units without writing files. `install` saves a
private immutable configuration, the three generated units, and the first
durable intent record inside `installation/evidence`. Their names include the
installation UUID:

| Unit | Operation |
| --- | --- |
| `lifecycle-marty-UUID.service` | Start existing runtime containers at user-manager startup; stop them during shutdown. |
| `lifecycle-marty-UUID-check.service` | Run the existing read-only deployment validator when running is intended. |
| `lifecycle-marty-UUID-check.timer` | Schedule the check every five minutes, with a short randomized delay and persistent catch-up. |

The initial intent is **paused**. Installing the units does not stop containers
that are already running. It leaves the decision to resume automatic startup
explicit, and does not infer that a previously stopped installation should run.

The JSON output includes exact `next_actions.commands` argument arrays for the
retained `start` command, linking all three units, reloading the user manager,
and enabling the boot service and check timer. Review those commands and run
them as that same installation owner when running is intended. They have this
shape; substitute the actual UUID and paths returned by the operator:

```sh
/absolute/installation/marty-deploy start \
  --install-dir /absolute/installation --docker-bin /usr/bin/docker

systemctl --user link \
  /absolute/installation/evidence/lifecycle-marty-UUID.service \
  /absolute/installation/evidence/lifecycle-marty-UUID-check.service \
  /absolute/installation/evidence/lifecycle-marty-UUID-check.timer

systemctl --user daemon-reload
systemctl --user enable --now \
  lifecycle-marty-UUID.service lifecycle-marty-UUID-check.timer
```

Quote paths containing spaces or shell metacharacters when entering commands
manually. The unit files themselves use literal, correctly escaped argv without
a shell. They contain no credential values or environment-file imports.
Spaces, percent signs and dollar signs in installation paths are supported.
Installation paths containing quotes, apostrophes or backslashes are refused
because systemd rejects those characters in the executable name even after
correct escaping. This command does not relocate an existing installation.

The customer must provide a working rootless `docker.service` in the same user
manager and arrange user lingering for unattended boot. The installer does not
run `sudo`, change lingering, call `systemctl`, or alter another user's units.
The installation and linked unit files must be on storage available when the
user manager starts. Docker's [rootless installation instructions](https://docs.docker.com/engine/security/rootless/)
describe the daemon and user-manager prerequisites.

## Persistent maintenance intent

Use the retained operator's existing controls for maintenance:

```sh
/absolute/installation/marty-deploy stop \
  --install-dir /absolute/installation --docker-bin /usr/bin/docker

/absolute/installation/marty-deploy start \
  --install-dir /absolute/installation --docker-bin /usr/bin/docker

/absolute/installation/marty-deploy lifecycle status \
  --install-dir /absolute/installation --docker-bin /usr/bin/docker
```

After lifecycle installation, manual `start` appends running intent before
invoking Compose. Manual `stop` and `uninstall` append paused intent before
invoking Compose. All these writes and the native operation use the same
exclusive installation lock. A failed stop retains the pause request and the
native operation's failure evidence; it does not claim that containers stopped.

While paused, `lifecycle boot`, `lifecycle check`, and `lifecycle shutdown`
return a no-op without contacting Docker. The timer cannot undo the pause.
Ordinary user-manager shutdown calls `lifecycle shutdown`, which stops the
existing project while preserving running intent for the next boot.

Stopping the systemd service directly is a transient control: its shutdown
command preserves running intent. Use the retained `stop` command for a
maintenance pause that survives a later boot. After native uninstall, the
customer can disable the generated boot service and timer with
`systemctl --user disable --now` using their exact unit names. Unit files,
credentials, data and diagnostic evidence are retained.

The native maintenance executor preserves its existing ownership checks and
refuses mutation after an uncertain start, stop or down operation. The systemd
service allows a small bounded number of failed startup attempts, useful for
preflight failures such as an unavailable daemon. This never grants permission
to repeat an uncertain Compose operation. Inspect the recorded native evidence
and resolve the cause; there is no force, purge, setup replay, or repair loop.

## Scheduling and inspection

The boot unit is ordered after the rootless Docker user service, so normal
shutdown reverses that ordering. It does not share Docker's service lifecycle
through `PartOf=` or `Requires=`. Compose restart policies remain responsible
for ordinary container process failures; these units do not introduce a second
container scheduler.

The check service is also ordered after the installation's boot service. A
persistent timer catching up at boot therefore cannot acquire the installation
lock before startup completes and exhaust the boot service's bounded retries.
The same ordering makes checks stop before the boot service's shutdown command.

The timer runs `lifecycle check`, which calls the existing bounded read-only
validator and saves its private diagnostic report. It can report missing or
unhealthy services and failed public checks. It cannot rotate credentials,
renew certificates, restart workloads, repair sealed OpenBao, or recover expired
control-plane authentication. Status explicitly reports automatic renewal as
not implemented and expired-credential recovery as not qualified. The customer
owns diagnostic retention and monitoring of timer failures.

`lifecycle status` describes recorded lifecycle intent and native maintenance
history. It does not claim to have queried systemd enablement or observed current
container health. Use the generated unit names with `systemctl --user status`
and run the existing deployment validator for those separate observations.

Every scheduled command revalidates the release, retained operator, installation
path, Docker binding, Compose configuration, and exact generated unit contents.
Intent records form an append-only sequence tied to the configuration digest.
Missing, changed, foreign, non-contiguous, or linked records are refused. An
interrupted `lifecycle install` may complete only matching immutable artifacts;
it never replaces conflicting files. Changing paths, release identity, engine,
or generated unit policy is not an upgrade or migration path in this release.

The Compose digest is the authenticated saved maintenance session, including
any completed foundation registration extension. Existing credential-generation
commands do not activate their output. Future activation that changes the
saved model or its bound inputs needs an authenticated generation handoff in the
maintenance inspector before it can coexist with these units. Such changes
currently fail closed; this lifecycle implementation does not silently rebind
its immutable configuration or discard running/paused history.

The unit templates use standard [systemd command-line quoting](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html#Command%20lines)
and [persistent timers](https://www.freedesktop.org/software/systemd/man/255/systemd.timer.html#Persistent=).
The remaining host qualification must exercise actual user-manager boot,
intentional pause across reboot, daemon and process crashes, and credential
expiry. Unit rendering and intent-policy tests establish the local contract;
they do not replace those deployment observations.
