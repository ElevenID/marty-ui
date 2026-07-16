$ErrorActionPreference = 'Stop'

$env:Path = "C:\Program Files\Docker\Docker\resources\bin;$env:Path"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$SelfhostEnv = Join-Path $RepoRoot '.env.selfhost.production.local'
$SelfhostCompose = Join-Path $RepoRoot 'docker-compose.selfhost.prod.yml'
$OpenbaoCompose = Join-Path $RepoRoot 'docker-compose.selfhost.openbao.yml'
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
        if (-not (Test-ContainerReady 'marty-selfhost-openbao-openbao-1')) {
            Invoke-Step 'Start standalone OpenBao' {
                docker compose --env-file $SelfhostEnv -f $OpenbaoCompose up -d --no-build
            }
            Invoke-Step 'Unseal/bootstrap OpenBao' {
                docker compose --env-file $SelfhostEnv -f $OpenbaoCompose run --rm openbao-bootstrap
            }
        }
        $productionServices = @('marty-selfhost-prod-edge-1', 'marty-selfhost-prod-gateway-1', 'marty-selfhost-prod-cloudflared-1', 'marty-selfhost-prod-ui-1', 'marty-selfhost-prod-applicant-1', 'marty-selfhost-prod-issuance-1')
        if (@($productionServices | Where-Object { -not (Test-ContainerReady $_) }).Count -gt 0) {
            Invoke-Step 'Recover self-host production stack' {
                docker compose --env-file $SelfhostEnv -f $SelfhostCompose up -d --no-build --force-recreate --wait
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
            docker compose --env-file $SelfhostEnv -f $SelfhostCompose ps --status running
        }
        Invoke-Step 'Validate beta containers' {
            docker compose --env-file $BetaEnv -f $BetaCompose[0] -f $BetaCompose[1] -f $BetaCompose[2] ps --status running
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
