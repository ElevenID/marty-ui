# Windows Docker Desktop recovery

Use the existing Compose recovery wrapper from a trusted tooling checkout. Keep
the deployment directory separate from that checkout. Retain the **complete,
ordered** base/overlay list, environment file, projects and selected Docker
context from the reviewed installed deployment. Recovery is not an upgrade or a
substitute for signed release/composition verification. Do not derive a new
deployment solely from one container's Compose labels: a project may contain
containers created with different historical invocations.

Save a nonsecret operator-owned JSON file outside public source:

```json
{
  "schema": "marty.windows-recovery/v1",
  "parameters": {
    "StackDirectory": "C:/Marty/deployment",
    "ExpectedDockerContext": "desktop-linux",
    "ProductionProject": "marty-production",
    "ProductionEnvFile": "C:/Marty/private/production.env",
    "ProductionComposeFile": [
      "C:/Marty/deployment/docker-compose.yml",
      "C:/Marty/private/production-ui-overlay.yml"
    ],
    "OpenbaoProject": "marty-openbao",
    "OpenbaoComposeFile": "C:/Marty/deployment/docker-compose.selfhost.openbao.yml",
    "OpenbaoEnvFile": "C:/Marty/private/production.env"
  }
}
```

These are examples, not host settings. Paths must be existing absolute paths.
The retained file contains paths and project/context identifiers, never token,
unseal-key or environment contents. Restrict writes to the recovery operator.
Do not edit deployment inputs during recovery. For an independent website,
omit `ProductionComposeFile`: authenticated `.marty-website/state.json` owns the
exact invocation and retained website overlay. Configure the existing
`MARTY_WEBSITE_PYTHON`, `MARTY_WEBSITE_GH` and `MARTY_WEBSITE_COSIGN` tools under
the same operator account. Add `RegistryConfig` to `parameters` with the absolute
path to that account's private Docker `config.json`, and configure `DOCKER_CONFIG`
to its parent for the actual pulls. Direct invocations use `-RegistryConfig`.
The saved configuration retains the path only; never put credential contents in
it. See [independent website recovery](independent-website-release.md).

```powershell
$Tooling = 'C:/Marty/tooling'
$Configuration = 'C:/Marty/private/windows-recovery.json'
& "$Tooling/scripts/recover-marty-after-reboot.ps1" -RecoveryConfigurationFile $Configuration -CheckOnly
```

`-CheckOnly` checks the selected Linux engine/context, file availability, active
website transaction/lock guards and Compose configuration without starting or
recreating containers. It writes the ordinary recovery transcript; it suppresses
rendered configuration and native configuration diagnostics. It does not verify
signatures, mount contents, state consistency, registry admission, website
availability or restart/reboot behavior. An absent or incompatible retained input
is a refusal, not permission to fall back to a smaller file list.

After backup/rollback preparation and the applicable restart authorization,
omit `-CheckOnly` to recover. Combined recovery always runs idempotent
`up -d --no-build --wait` for the full active model, including ingress and
dependencies; no forced recreation is requested. Compose can recreate a service
whose model changed, so use only the reviewed retained inputs. OpenBao and its
persistent unseal helper must both become ready before product recovery. The
wrapper never runs the opt-in bootstrap profile. Clear `COMPOSE_PROFILES`.
Existing Raft state and keys must already belong to the selected deployment.

Beta is independent and is excluded by default. `RecoverBeta: true` explicitly
enables the legacy beta invocation in this wrapper; use its dedicated recovery
owner when beta has newer retained overlays. Production recovery is not authority
to reconcile another team's beta runtime.

For an authorized startup installation:

```powershell
& "$Tooling/scripts/install-marty-boot-recovery.ps1" -RecoveryConfigurationFile $Configuration
```

The installer first runs the exact saved configuration preflight. It registers
the historical `Marty-Recovery-At-Boot` task name for compatibility, but now runs
**at operator logon**, delayed two minutes, under the current interactive user
with limited privileges. It does not change/start Windows services or use SYSTEM.
Configure Docker Desktop to start for that user. The task retains the selected
context and refuses a different selection; it never switches contexts. Ordinary
PowerShell execution policy must permit the trusted local scripts. Installing a
task is not a test of application restart, Docker Desktop restart, user logon or
full-host reboot. Qualify each separately and do not claim unattended pre-logon
availability. Inspect existing task ownership/authorization before replacement.

Rehearse with a separate Compose project, loopback ports and test-only bind
storage. Record the ordered invocation, image identities, mount markers and
container identities before/after recovery. Application login, registration,
consoles, KMS-backed operations and credential flows need separate runtime tests.
Marketing/pricing page availability does not qualify billing or real payments.

## Retained managed OpenBao candidate

For a candidate already adopted by the
[Windows generation owner](windows-renewal-activation.md), use the managed
schema instead of the legacy Compose configuration above:

```json
{
  "schema": "marty.windows-managed-recovery/v1",
  "selection_file": "C:/Marty/private/renewal/config.private.json"
}
```

`selection_file` is the existing generation-owner configuration used for
adoption, not a replacement Compose model or a new deployment. Store both files
in private, operator-owned directories. Supply the trusted Python interpreter
explicitly; the JSON cannot select an executable. For example:

```powershell
& "$Tooling/scripts/recover-marty-after-reboot.ps1" `
  -RecoveryConfigurationFile 'C:/Marty/private/managed-recovery.json' `
  -ManagedPython 'C:/Python312/python.exe' -CheckOnly
```

Managed `-CheckOnly` holds the selected generation and validates configuration,
storage, the retained Linux engine and existing-ID dependency plan. It does not
authenticate, mint a token, start containers or prove current credential lifetime
or application readiness. Its output explicitly reports those limits. This mode
does not use the legacy transcript or Compose `up` path.

After applicable restart authorization, omit `-CheckOnly` to recover existing
IDs through the selected owner. Once Bao and its unseal helper are ready, the
verified native operator authenticates the existing renewal AppRole. A fresh
private session directory and token file are reserved before login; the token is
saved and flushed before its scoped authority is checked. Only the session path
and nonsecret result metadata return to Windows. Existing enrollment, generations,
roles and policies remain unchanged. A fresh session does not renew leaf
credentials: native minimum-lifetime, certificate and custody checks still gate
application startup. Failure retains the recovery marker and attempt evidence;
never retry by removing those records.

`-WaitForEngine` optionally waits up to five minutes for the retained Docker pipe.
Only read-only `info` calls repeat while it is unavailable. They use the existing
owned Windows job and continuously bounded pipe drains. An abnormal CLI timeout,
surviving descendant or cleanup failure refuses rather than retrying; cleanup has
the owned runner's separate bounded deadline. A responding engine
with a different ID, operating system or data root refuses immediately. The wait
starts no engine, switches no context and writes no recovery intent. All selected
inputs remain held, and normal admission still runs after the wait.

For an authorized candidate logon-task installation, reuse the existing installer
with a separate explicit task name:

```powershell
& "$Tooling/scripts/install-marty-boot-recovery.ps1" `
  -RecoveryConfigurationFile 'C:/Marty/private/managed-recovery.json' `
  -ManagedPython 'C:/Python312/python.exe' -TaskName 'Marty-Candidate-Recovery'
```

The installer runs the exact managed check-only preflight before registration.
It refuses the historical task name and any existing matching name, including in
other task folders. Registration uses the native
[Task Scheduler `TASK_CREATE` flag](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-registertaskdefinition),
so a name collision after preflight also refuses instead of updating a task.
The action retains the explicit interpreter, absolute Windows system PowerShell
path and `-WaitForEngine`. The existing interactive,
limited-privilege operator-logon trigger and two-minute delay apply. Inspect the
registered action and task ownership after installation. Existing legacy invocations
retain their historical behavior. Installing this task does not test logon, engine
or host reboot, and does not provide pre-logon availability.

Normal recovery does not renew or repair expired generations or resume an
uncertain earlier attempt. Explicit online renewal uses the same entrypoint:

```powershell
& "$Tooling/scripts/recover-marty-after-reboot.ps1" `
  -RecoveryConfigurationFile 'C:/Marty/private/managed-recovery.json' `
  -ManagedPython 'C:/Python312/python.exe' -WaitForEngine `
  -RenewCredentials -LogicalTlsProject $EnrolledLogicalTlsProject
```

The namespace must be the existing enrollment, not a new project name. The CLI
holds the unchanged managed manifest, finishes any engine-wait lease, then calls
the existing `renew_once` owner under its own fresh lease. It emits metadata only
after all held-input exits. Adding `-CheckOnly` verifies configuration without
minting or activation; its result explicitly reports `renewal_executed=false`.
It does not qualify the namespace against the issuer or prove runtime readiness.

A separately named online renewal task can reuse the installer:

```powershell
& "$Tooling/scripts/install-marty-boot-recovery.ps1" `
  -RecoveryConfigurationFile 'C:/Marty/private/managed-recovery.json' `
  -ManagedPython 'C:/Python312/python.exe' -TaskName 'Marty-Candidate-Renewal' `
  -RenewCredentials -LogicalTlsProject $EnrolledLogicalTlsProject `
  -RenewalIntervalMinutes $QualifiedIntervalMinutes
```

The interval must be explicitly qualified between 15 and 240 minutes. Select it
from the actual minimum issued token/certificate lifetimes, admission floor,
worst-case operation duration and allowed outages; the installer does not infer
these or qualify unattended availability. Each tick performs a full renewal and
recreates credential-consuming application roles, so qualify its availability
impact too. Keep tooling at a reviewed, stable installed checkpoint rather than
an active development checkout before installing a real task.
The current append-only selection journal is bounded at 256 operations. Renewal
refuses before minting when full; it never truncates or resets history. Its
remaining capacity and a supported history-preserving continuation are additional
unattended qualification requirements. Do not treat an indefinite trigger as
proof of indefinite renewal capacity.

The renewal task uses an interactive, limited operator logon trigger with a
two-minute delay and repetition, no immediate failure retries, a one-hour task
limit and IgnoreNew concurrency. The duration is omitted for
[indefinite repetition](https://learn.microsoft.com/en-us/windows/win32/taskschd/repetitionpattern-duration).
It requires the signed-in operator session; it is not a SYSTEM boot service.
Create-only registration and the same project guards prevent replacement or
uncertain-operation replay. The installer preflight is check-only and never
mints. Actual task registration, invocation, repetition/logon timing, separately
authorized engine/host reboot, and supported expired-generation recovery still
require host qualification. An unregistered COM definition test proves XML
serialization only. No task is installed by the test suite.

After separate registration, check the exact managed task without elevation:

```powershell
& "$Tooling/scripts/verify-marty-boot-recovery.ps1" `
  -RecoveryConfigurationFile 'C:/Marty/private/managed-recovery.json' `
  -ManagedPython 'C:/Python312/python.exe' -TaskName 'Marty-Candidate-Renewal' `
  -RenewCredentials -LogicalTlsProject $EnrolledLogicalTlsProject `
  -RenewalIntervalMinutes $QualifiedIntervalMinutes -CheckOnly
```

The verifier requires the current operator's separate root-folder task and the
exact installed action, interpreter, configuration, working directory, trigger
and settings. It refuses active or mismatched tasks. Its read-only runtime
preflight uses the existing owned-process job and bounded drains, with an
independent `-PreflightTimeoutSeconds` budget (default 300; range 1–600).
Check-only makes no task start request. The historical no-argument legacy
verifier invocation retains its original administrator requirement and task.

Omit `-CheckOnly` only for a qualified task execution request. The verifier never
stops, changes, deletes or retries a task. It requires a newer `LastRunTime`,
Ready state and result zero within a monotonic `-TimeoutSeconds` acceptance
budget (default 3600; range 1–3600). Task API calls can return after that budget;
late observations cannot qualify, and a timeout does not stop the task.
`task_start_requested` and `fresh_task_completion_observed` are separate receipt
fields. A concurrent trigger with IgnoreNew prevents unique attribution to the
manual request, so `requested_run_attribution_verified` remains false.
An optional absolute `-StatusFile` must name a new file in an existing directory;
the verifier never overwrites a prior receipt. A successful observation does not
qualify periodic/logon triggers, host reboot, expired-generation recovery or
production admission. Those receipt flags remain false.
