$ErrorActionPreference = 'Stop'

$env:Path = "C:\Program Files\Docker\Docker\resources\bin;$env:Path"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$SelfhostEnv = Join-Path $RepoRoot '.env.selfhost.production.local'
$SelfhostCompose = Join-Path $RepoRoot 'docker-compose.selfhost.prod.yml'
$OpenbaoCompose = Join-Path $RepoRoot 'docker-compose.selfhost.openbao.yml'
$ProductionComposeArgs = @('--env-file', $SelfhostEnv, '-f', $SelfhostCompose)
$OpenbaoComposeArgs = @('--env-file', $SelfhostEnv, '-f', $OpenbaoCompose)
$OpenbaoContainer = 'marty-selfhost-openbao-openbao-1'
$OpenbaoUnsealContainer = 'marty-selfhost-openbao-openbao-unseal-1'
$WebsiteStatePath = Join-Path $RepoRoot '.marty-website/state.json'
$HasIndependentWebsite = Test-Path -LiteralPath $WebsiteStatePath -PathType Leaf
$BetaEnv = Join-Path $RepoRoot '.env.tunnel.beta.local'
$BetaCompose = @(
    (Join-Path $RepoRoot 'docker-compose.base.yml'),
    (Join-Path $RepoRoot 'docker-compose.profile.dev.yml'),
    (Join-Path $RepoRoot 'docker-compose.profile.tunnel.yml')
)
$LogRoot = Join-Path (Split-Path -Parent $RepoRoot) 'marty-selfhost-prod'
$LogPath = Join-Path $LogRoot 'marty-recovery.log'

New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
Start-Transcript -Path $LogPath -Append | Out-Null

function Invoke-Step([string]$Name, [scriptblock]$Action) {
    Write-Host "[$(Get-Date -Format s)] $Name"
    & $Action
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
}

function Test-ContainerReady([string]$Name) {
    $status = docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' $Name 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    $parts = ($status -split '\|', 2)
    return $parts[0] -eq 'running' -and ($parts[1] -eq 'none' -or $parts[1] -eq 'healthy')
}

try {
    $deadline = (Get-Date).AddMinutes(5)
    do {
        try { docker info *> $null; $dockerReady = ($LASTEXITCODE -eq 0) } catch { $dockerReady = $false }
        if (-not $dockerReady) { Start-Sleep -Seconds 5 }
    } while (-not $dockerReady -and (Get-Date) -lt $deadline)
    if (-not $dockerReady) { throw 'Docker Desktop did not become ready within five minutes.' }

    Push-Location $RepoRoot
    try {
        if (Test-Path -LiteralPath (Join-Path $RepoRoot '.marty-website/transaction.json')) {
            throw 'An interrupted website transaction requires deploy_website.py --recover before reboot recovery.'
        }
        if (Test-Path -LiteralPath (Join-Path $RepoRoot '.marty-website/deploy.lock')) {
            throw 'A website deployment lock exists; wait for its owner or confirm stale-lock recovery before proceeding.'
        }
        if ($HasIndependentWebsite) {
            # Public TLS/tunnel ingress for the signed host shape is supervised
            # independently of product/OpenBao readiness. This wrapper restores
            # local website/edge service, then probes that separate public owner.
            # Paths are operator-provisioned, checksum-reviewed binaries. The
            # trusted Python owner validates state, original receipts, rendered
            # configuration, image pins and actual running image IDs before use.
            foreach ($tool in @('MARTY_WEBSITE_PYTHON', 'MARTY_WEBSITE_GH', 'MARTY_WEBSITE_COSIGN')) {
                if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($tool))) {
                    throw "Independent website recovery requires $tool; see docs/independent-website-release.md"
                }
            }
            $WebsiteState = Get-Content -LiteralPath $WebsiteStatePath -Raw | ConvertFrom-Json
            $WebsiteHost = $WebsiteState.host
            $WebsiteArguments = @(
                '--start-current', '--stack-dir', $RepoRoot,
                '--project', [string]$WebsiteHost.project,
                '--env-file', [string]$WebsiteHost.env_file,
                '--openbao-compose-file', [string]$WebsiteHost.openbao_compose_file,
                '--openbao-env-file', [string]$WebsiteHost.openbao_env_file,
                '--openbao-project', [string]$WebsiteHost.openbao_project,
                '--public-origin', [string]$WebsiteHost.public_origin,
                '--gh', $env:MARTY_WEBSITE_GH, '--cosign', $env:MARTY_WEBSITE_COSIGN
            )
            $ProductionComposeArgs = @('--project-directory', $RepoRoot, '--project-name', [string]$WebsiteHost.project,
                                       '--env-file', [string]$WebsiteHost.env_file)
            foreach ($composeFile in $WebsiteHost.compose_files) {
                $WebsiteArguments += @('--compose-file', [string]$composeFile)
                $ProductionComposeArgs += @('-f', [string]$composeFile)
            }
            if ($WebsiteHost.ca_file) { $WebsiteArguments += @('--ca-file', [string]$WebsiteHost.ca_file) }
            Invoke-Step 'Restore authenticated website and edge before product readiness' {
                & $env:MARTY_WEBSITE_PYTHON (Join-Path $PSScriptRoot 'deploy_website.py') @WebsiteArguments
            }
            $ProductionComposeArgs += @('-f', (Join-Path $RepoRoot '.marty-website/compose.website.json'))
            $OpenbaoComposeArgs = @('--project-directory', $RepoRoot, '--project-name', [string]$WebsiteHost.openbao_project,
                                    '--env-file', [string]$WebsiteHost.openbao_env_file, '-f', [string]$WebsiteHost.openbao_compose_file)
            $OpenbaoContainer = "$($WebsiteHost.openbao_project)-openbao-1"
            $OpenbaoUnsealContainer = "$($WebsiteHost.openbao_project)-openbao-unseal-1"
        }
        if (-not (Test-ContainerReady $OpenbaoContainer) -or
            -not (Test-ContainerReady $OpenbaoUnsealContainer)) {
            Invoke-Step 'Start standalone OpenBao' {
                docker compose @OpenbaoComposeArgs up -d --no-build openbao openbao-unseal
            }
        }
        $baoDeadline = (Get-Date).AddMinutes(2)
        while (-not (Test-ContainerReady $OpenbaoContainer) -and
               (Get-Date) -lt $baoDeadline) {
            Start-Sleep -Seconds 5
        }
        if (-not (Test-ContainerReady $OpenbaoContainer)) {
            throw 'OpenBao did not become healthy after the unseal service started.'
        }
        $productionServices = @('marty-selfhost-prod-edge-1', 'marty-selfhost-prod-gateway-1', 'marty-selfhost-prod-cloudflared-1', 'marty-selfhost-prod-ui-1', 'marty-selfhost-prod-applicant-1', 'marty-selfhost-prod-issuance-1')
        if ($HasIndependentWebsite) {
            Invoke-Step 'Recover product while retaining the selected website overlay' {
                # The website lock was released after --start-current. Select
                # only default-active product roles with --no-deps; an unlocked
                # recovery must never reconcile edge/website slots from a stale
                # Compose model during a concurrent website promotion.
                & $env:MARTY_WEBSITE_PYTHON (Join-Path $PSScriptRoot 'recover_product_services.py') -- @ProductionComposeArgs
            }
        } elseif (@($productionServices | Where-Object { -not (Test-ContainerReady $_) }).Count -gt 0) {
            Invoke-Step 'Recover self-host production stack' {
                docker compose @ProductionComposeArgs up -d --no-build --force-recreate --wait
            }
        }
        $betaServices = @('marty-gateway', 'marty-ui-prod', 'cloudflared-tunnel', 'tunnel-nginx-proxy')
        if (@($betaServices | Where-Object { -not (Test-ContainerReady $_) }).Count -gt 0) {
            Invoke-Step 'Recover beta application stack' {
                docker compose --env-file $BetaEnv -f $BetaCompose[0] -f $BetaCompose[1] -f $BetaCompose[2] up -d --no-build --force-recreate --wait
            }
            Invoke-Step 'Recover beta tunnel' {
                docker compose --env-file $BetaEnv -f $BetaCompose[0] -f $BetaCompose[1] -f $BetaCompose[2] up -d --no-build --force-recreate --wait docs nginx-proxy cloudflared
            }
        }
        Invoke-Step 'Validate production containers' {
            docker compose @ProductionComposeArgs ps --status running
        }
        Invoke-Step 'Validate beta containers' {
            docker compose --env-file $BetaEnv -f $BetaCompose[0] -f $BetaCompose[1] -f $BetaCompose[2] ps --status running
        }
        if ($HasIndependentWebsite) {
            $WebsiteArguments[0] = '--check-current'
            Invoke-Step 'Check retained website through separately supervised public ingress' {
                & $env:MARTY_WEBSITE_PYTHON (Join-Path $PSScriptRoot 'deploy_website.py') @WebsiteArguments
            }
        }
    } finally {
        Pop-Location
    }
    Write-Host "[$(Get-Date -Format s)] Marty recovery completed successfully."
    exit 0
} catch {
    Write-Error $_
    exit 1
} finally {
    Stop-Transcript | Out-Null
}
