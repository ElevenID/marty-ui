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
and refuses any leftover passport disposable resource. On the current host,
the WSL Docker socket is absent. Do not register a passport runner until the
host preflight passes.

From PowerShell, start the foreground one-job runner:

```powershell
.\scripts\register-canvas-oss-runner.ps1 -Purpose Passport
```

The wrapper registers an ephemeral GitHub runner with the dedicated label,
verifies the server-side labels, and exports the verified runner name to
its one job. Every protected passport job checks the host again before
its evidence step. The wrapper repeats the host check after the job and
leaves a quarantine marker if cleanup is unverified. Keep the PowerShell
process alive until the job exits and GitHub removes the runner.

This runner only produces protected evidence. It does not authorize a
release claim, beta deployment, or changes to production.
