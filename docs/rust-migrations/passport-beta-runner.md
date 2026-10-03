# Passport beta one-job runner

The protected passport workflows use `self-hosted, linux, x64,
passport-beta-wsl2`. Canvas jobs retain `canvas-oss-wsl2`. These labels
must stay separate because GitHub can dispatch either job as soon as a
matching runner appears. Both runner modes hold the same Windows host mutex,
so they cannot register concurrently on the shared Docker Desktop host.

Use the reviewed `main` checkout on the intended beta host. Before
registration, confirm the Ubuntu 24.04 WSL2 distribution and runner
directory exist, Docker Desktop exposes a Unix socket inside that WSL
distribution, the beta network and tunnels are running, and production
containers are healthy. The registration wrapper checks these conditions
and refuses any leftover passport disposable resource. Docker Desktop WSL
integration is enabled on the current host, and the host preflight passed
after production recovered from the Docker Desktop restart.

The wrapper records the IDs, start times, restart counts, running states,
health states, and historical exit codes of all 29 production containers
before registering. It requires
the same inventory before and after the job. The job repeats that comparison
before evidence collection. All 24 production runtime containers must be
present and healthy. The five historical stopped containers are checked by
name and exit code; the issuance migration had already exited with code 1
before this runner setup, and retired billing had exited with code 255.
Neither is restarted as part of passport runner admission.

From PowerShell, start the foreground one-job runner:

```powershell
.\scripts\register-canvas-oss-runner.ps1 -Purpose Passport
```

The wrapper first rejects an incomplete repository runner inventory, any
already-registered runner that advertises both protected purpose labels, or
another runner with the requested purpose label. It then registers an ephemeral
GitHub runner with the dedicated label,
verifies that its server-side labels contain exactly the standard runner labels
and the dedicated purpose label, and exports the verified runner name to
its one job. Every protected passport job checks the host again before
its evidence step. The wrapper repeats the host check after the job and
removes a rejected new registration before starting the job. It leaves a
quarantine marker if post-job host cleanup is unverified. Keep the PowerShell
process alive until the job exits and GitHub removes the runner.

A [protected producer run](https://github.com/ElevenID/marty-ui/actions/runs/37139093870)
on 2026-10-03 was routed to a Canvas-named runner;
the in-job passport identity check rejected it before reading plan or release
artifacts. The wrapper now detects stale or dual-purpose registrations before
starting `run.sh`, but cannot unregister an independently running runner or
prevent a queued job from reaching it before the wrapper starts. Investigate
and remove the stale registration/labels on the host rather than weakening the
job preflight or treating that run as passport qualification evidence.

This runner only produces protected evidence. It does not authorize a
release claim, beta deployment, or changes to production.
