# Migrate an existing beta connector from token arguments

An older tunnel profile placed the tunnel token in the container command. Normal
beta deployment rejects that representation even when the protected token file
matches: it must not leave credentials in process arguments. Migrate that
stateless connector once before the application rollout. Reuse the active token;
this does not require another account API key or token rotation.

Use the existing deployment's exact beta Compose argument array (project,
environment files, image bindings and configuration files) as
`$betaComposeArguments`. Keep its durable runtime configuration and image
bindings. Do not substitute defaults, use the self-host production project, print
`compose config`, or put the token in a command. `$protectedBetaConnectorEnvFile`
is the existing private file containing only `TUNNEL_TOKEN=<active token>`.
`$privateMigrationDirectory` must be an owned private directory outside OneDrive.

The helper's preparation mode accepts only the former repository's exact
`tunnel --no-autoupdate run --token <matching token>` command, checks the running
beta project/service and private input, and writes a token-free override. It
does not start or replace a container. Other argv shapes, stale tokens and
foreign containers remain rejected. Ordinary deployment never enables this mode.

Run from the reviewed UI checkout, preserving the existing Compose inputs:

```powershell
. .\scripts\beta-deployment-lock.ps1
$lock = Enter-BetaDeploymentLock
try {
    $override = Join-Path $privateMigrationDirectory 'connector-env-only.yml'
    $log = Join-Path $privateMigrationDirectory 'connector-migration.log'
    python .\scripts\beta_tunnel_configuration.py `
      --credential-env-file $protectedBetaConnectorEnvFile `
      --prepare-legacy-migration --override-output $override
    if ($LASTEXITCODE -ne 0) { throw 'Legacy connector preparation failed' }

    # Recreate only the stateless connector; do not restart dependencies.
    & docker compose @betaComposeArguments -f $override up `
      --detach --no-deps --force-recreate cloudflared *> $log
    if ($LASTEXITCODE -ne 0) { throw 'Connector replacement failed; inspect the private log' }

    # Strict binding must now pass without the migration flag.
    python .\scripts\beta_tunnel_configuration.py `
      --credential-env-file $protectedBetaConnectorEnvFile
    if ($LASTEXITCODE -ne 0) { throw 'New connector failed strict environment-only binding' }
}
finally { Exit-BetaDeploymentLock -Lock $lock }
```

Verify the existing public beta release and UI endpoints before the application
rollout. Retain the override with deployment configuration so later Compose
operations keep the protected `env_file` binding. If replacement or public
connectivity fails, diagnose that connector before proceeding; do not relax the
normal gate or replay application migrations. An environment-only connector
needs no migration and continues through the normal strict deployment path.
