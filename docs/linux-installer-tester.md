# Linux installer tester quickstart

Use this path to try an **exact signed nightly candidate** on a disposable Linux
amd64 machine with test identities and data. It needs no source checkout,
organization credentials, or acceptance controller. Candidate testing does not
grant release admission, installer Ready status, full functional/recovery
qualification, or production readiness.

## 1. Prepare the Linux host

Use the 8 GiB test target and leave at least 20 GiB free on **Docker's data
filesystem**, in addition to space for the host OS. These are test resources,
not a supported production capacity. The [resource profiles](installer-bootstrap.md#controller-observations-and-resource-profiles)
describe the separate qualification floors.

Complete host preparation in your ordinary login session before running Marty:

1. Have the host administrator install the trusted OS tools: `setpriv`
   (usually supplied by util-linux), Bash, curl, tar, and standard Linux core
   utilities. Use a permanent, regular non-root account for Docker and Marty.
2. Follow Docker's [Engine installation](https://docs.docker.com/engine/install/)
   and [rootless setup](https://docs.docker.com/engine/security/rootless/)
   instructions for your distribution. Rootless setup requires `newuidmap` and
   `newgidmap` and at least 65,536 subordinate IDs for your user in each of
   `/etc/subuid` and `/etc/subgid`. Run the rootless setup helper as that user
   after the administrator has prepared those prerequisites.
3. Install the [Compose plugin](https://docs.docker.com/compose/install/linux/)
   using Docker's instructions. The signed operator separately checks the
   selected plugin before using it in an isolated Docker configuration. The
   standard `$HOME/.docker/cli-plugins/docker-compose` location is supported;
   arbitrary plugin paths supplied through `DOCKER_CONFIG` are not.
4. Start the rootless Docker **user** service using the
   [official user-service instructions](https://docs.docker.com/engine/security/rootless/tips/).
   Marty requires the same user's `/run/user/<uid>/docker.sock`, cgroup v2, the
   systemd cgroup driver, and memory-limit support. A rootful daemon, membership
   in the `docker` group, or `userns-remap` does not satisfy this requirement.

Do this setup before using `setpriv --no-new-privs`: rootless daemon setup uses
the subordinate-ID helpers. Run the Marty commands below without `sudo`, as the
same account that owns the already-running daemon. The installer does not
install packages, start Docker, alter subordinate IDs, or configure host trust.

For optional unattended operation, the administrator also needs to arrange
[user lingering](https://www.freedesktop.org/software/systemd/man/latest/loginctl.html)
and persistent Docker user-service enablement. Check the native lifecycle
observations in step 6 before expecting services to start without a login.

## 2. Download the chosen bootstrap and check the host

Choose one exact published nightly from the
[releases page](https://github.com/ElevenID/marty-ui/releases), and read its
release notes (generated from `SELFHOST-PREVIEW-README.md`). Replace the tag below
with that release's tag. Keep the
bootstrap and candidate tag together; older nightlies may predate these
commands. If that release's bootstrap does not recognize `--check-host`, use its
own installation guide or a newer published nightly containing this interface.

In your regular user's shell:

```sh
marty_tag='vX.Y.Z-nightly.YYYYMMDD.RUN_ID'
umask 077
marty_bootstrap_dir="$(mktemp -d)" &&
  curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    "https://github.com/ElevenID/marty-ui/releases/download/$marty_tag/install.sh" \
    -o "$marty_bootstrap_dir/install.sh"
```

Proceed only if the download succeeded. You can inspect the downloaded script
before executing it. This initial bootstrap is obtained over HTTPS; it
authenticates the signed inventory and deployment operator before executing
that operator. The operator verifies remaining payloads before provisioning.
See the complete [bootstrap trust boundary](installer-bootstrap.md).

Select only your own rootless socket in this shell. Check your trusted installed
Compose plugin, then run the bootstrap host check:

```sh
unset DOCKER_CONTEXT
export DOCKER_HOST="unix:///run/user/$(id -u)/docker.sock"
/usr/bin/setpriv --no-new-privs -- docker compose version &&
  /usr/bin/setpriv --no-new-privs -- sh "$marty_bootstrap_dir/install.sh" --check-host
```

The bootstrap check runs without downloading verification tools or
release payloads and without creating an installation. It does not establish
Compose compatibility, sufficient resources, successful startup, or readiness.
It creates and removes a private temporary Docker configuration.
The separate Compose version check uses your normal trusted host configuration;
the signed operator still performs its own plugin admission. Resolve either
command's failure before proceeding; keep the same rootless account and socket.

## 3. Run the exact candidate

```sh
/usr/bin/setpriv --no-new-privs -- sh "$marty_bootstrap_dir/install.sh" \
  --candidate-test "$marty_tag"
```

Review the host-impact confirmation. Omit `--yes` for this first test. The
default uses managed OpenBao and private localhost HTTPS; no foundation file is
needed. Keep the printed absolute installation path. Candidate provisioning can
pull images, create owned containers and volumes, and retain private state and
credentials. Failures preserve that state for diagnosis.

To choose direct DNS hosting or an external proxy, prepare the private
`--hosting-file ABSOLUTE_PATH` before this invocation using the
[hosting guide](installer-hosting.md). Public ACME needs direct DNS hosting,
correct DNS/routing, public HTTP-01 reachability, and explicit agreement to the
chosen CA terms; follow [ACME hosting](installer-acme-host.md). Local/private-CA
hosting does not need public DNS or an ACME account.

`--channel nightly`, `--channel stable`, and `--version TAG` require separate
signed admission and remain held. Do not substitute them for candidate testing.
A missing asset or failed signature/provenance check is a stop: preserve the
error and verify the selected release, rather than fetching an operator from a
different tag or disabling verification.

## 4. Inspect the result and finish pending ACME

Set the actual path printed by the installer. Keep using its retained operator
as the same non-root owner; the bootstrap is not an update or repair command.

```sh
marty_install_dir='/absolute/path/printed/by/the/installer'
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  status --install-dir "$marty_install_dir"
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  doctor --install-dir "$marty_install_dir"
```

**Exit zero alone does not mean the application has started.** With ACME, an
invocation can return a normal pending outcome with `application_started: false`.
For that installation, inspect the saved order:

```sh
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  acme status --install-dir "$marty_install_dir"
```

For an ordinary pending order, wait until all applicable retained deadlines
(`next_poll_at`, `next_attempt_at`, and `initial_terminal_retry_at`, when present)
permit continuation. They are Unix timestamps in seconds. Then use the returned
literal `continuation` command, or this equivalent with the exact Docker path
used for installation (shown as `/usr/bin/docker`):

```sh
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  acme continue --install-dir "$marty_install_dir" --docker-bin /usr/bin/docker
```

Inspect its outcome again. An unknown order outcome or explicit reconciliation
hold needs review; repeatedly invoking continuation is not reconciliation.
Preserve the installation and its timing records. Do not rerun the bootstrap,
change saved hosting inputs, recreate credentials, or loop through CA deadlines.
Staging ACME produces test evidence and does not activate a production install.
The [ACME continuation contract](installer-acme-host.md#continuing-a-normal-pending-order)
describes terminal replacement and refusal cases.

## 5. Verify HTTPS and the running application

After actual application startup:

```sh
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  trust-info --install-dir "$marty_install_dir"
/usr/bin/setpriv --no-new-privs -- "$marty_install_dir/marty-deploy" \
  validate --install-dir "$marty_install_dir"
```

Use the exact `origin` from `trust-info` as the browser URL. Local/private-CA
mode requires you to obtain `ca_certificate_pem` and its `ca_der_sha256`
fingerprint through the authenticated operator/SSH route, compare the exported
CA's fingerprint, and explicitly trust that test CA in the intended browser or
OS trust store. The installer does not add trust. A certificate-warning bypass
does not verify HTTPS. For a remote host in local mode, use the documented SSH
tunnel; opening its public IP cannot reach a loopback-only listener. Follow
[browser access and trust](installer-hosting.md#inspect-the-installation-and-open-the-browser)
for these steps and the distinct external-proxy frontend certificate.

For the default managed installation with local authentication, the bootstrap
account's username is **`operator@localhost`**. Its randomly generated password
is retained in **`$marty_install_dir/operator-password`**, an owner-only file
inside the private installation directory. Open it privately as the installation
owner and enter its single-line value in the browser. Keep it out of shell
arguments, recordings, shared terminals, feedback, and logs. Use this Marty
account rather than the separate Keycloak service-administration credentials.
An imported foundation using external authentication has no local operator
password; use the identity-provider account arranged for that foundation.

Record validation's individual required checks and verify the actual page in a
fresh browser session, including a separate sign-in attempt if testing login.
Local HTTP validation does not execute JavaScript, prove public access, or
authenticate that account. A candidate can pass its bounded checks while
`installation_ready` remains false and the optional credential journey is
`SKIP`. Report only the flows you actually exercised; do not infer full
qualification from startup or an opened login page. If sign-in fails, report the
redacted error and retained stage; preserve the generated credential instead of
changing bound files or rerunning provisioning.

## 6. Optional lifecycle and reboot testing

After successful candidate validation, the installer writes the installation's
user units and paused intent and prints the lifecycle next actions. The units
are not enabled automatically. Follow the [native lifecycle guide](installer-lifecycle.md),
run the retained operator under no-new-privileges, and inspect `lifecycle status`.
Only when `unattended_eligible` is observed `true`
should you review and execute its exact `next_actions.commands` as the same
owner. Those actions resume intended operation, link the exact units, and enable
the user services/timers. A false or unavailable prerequisite needs resolution
first. Do not invent unit names or treat exported files as enabled services.

Before arranging a reboot, verify the actual unit enablement and keep a way to
reconnect. Afterward, observe lifecycle status, doctor, validation, and browser
access again. Record early refusal reasons and later automatic retries; eventual
recovery does not establish which initial predicate failed. Preserve evidence
before attempting manual repair. A reboot pass is scoped to that test, not
production or full recovery qualification.

## 7. Share useful feedback and stop deliberately

Send your inviter or [issue #1350](https://github.com/ElevenID/marty-ui/issues/1350)
the exact nightly tag, OS/architecture, RAM and Docker-filesystem free space,
Docker/Compose versions, first failing stage, exit status, redacted error or
refusal reason, and the validation checks/browser flows you observed. Include
whether ACME was pending and whether any restart/recovery was automatic or
manual. Preserve reported evidence filenames locally. Do not attach the whole
installation, raw logs, private keys, tokens, passwords, or credential data.

For a native Compose failure, keep the displayed `operation=`, `failure_class=`,
`client_exit_code=`, `observation_validated=`, and `diagnostic=` fields. The
diagnostic path is relative to the printed installation directory and names the
retained operation result, for example
`evidence/compose-setup-openbao-bootstrap-result.json`. Preserve that receipt
locally; share the displayed fields instead of attaching the complete Compose
receipt, which can contain private command and configuration metadata.
`observation_validated=true` means the resource observations were accepted; it
does not mean setup succeeded. An unknown client exit code or an unestablished
postcondition requires investigation. Do not rerun the bootstrap, an initial
setup job, or a Compose command to retry failed provisioning. The retained
`start` and lifecycle commands recover an already established runtime; they do
not resume incomplete initial setup.

For a native health refusal, retain the reported `reason=` and `diagnostic=`
reference when present. The installation's
`evidence/health-refusal-0001.json` through `health-refusal-0032.json` are bounded
metadata receipts with an invocation UUID inside each record. Retention preserves
the earliest records without overwriting them; a full or unavailable store is
reported explicitly. Use the reported receipt to distinguish a refusal from
later automatic recovery. Unavailable evidence does not mean the health check
passed.

Use the retained operator's `stop --install-dir` for a durable manual stop, or
`uninstall plan --install-dir` to review cleanup before acting; see
[deployment operations](installer-bootstrap.md#deployment-operations) and
[lifecycle controls](installer-lifecycle.md#durable-stop-pause-resume-and-security-seal).
Ordinary uninstall retains recoverable data, credentials, images, and the Redis
volume. Reset the disposable machine only after collecting the feedback you
intend to keep.
