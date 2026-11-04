[CmdletBinding()]
param(
    [string]$RecoveryConfigurationFile,
    [string]$ExpectedDockerContext,
    [string]$StackDirectory,
    [string[]]$ProductionComposeFile = @(),
    [string]$ProductionEnvFile,
    [string]$ProductionProject = 'marty-selfhost-prod',
    [string]$OpenbaoComposeFile,
    [string]$OpenbaoEnvFile,
    [string]$OpenbaoProject = 'marty-selfhost-openbao',
    [switch]$RecoverBeta,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

# A scheduled invocation retains only nonsecret paths/project/context settings.
# Direct parameters remain useful for an isolated rehearsal.
if ($RecoveryConfigurationFile) {
    if (@($PSBoundParameters.Keys | Where-Object { $_ -notin @('RecoveryConfigurationFile', 'CheckOnly') }).Count) {
        throw 'Use retained recovery configuration or direct settings, not both.'
    }
    try {
        if (-not [IO.Path]::IsPathRooted($RecoveryConfigurationFile)) { throw 'absolute path required' }
        $configuration = Get-Content -LiteralPath $RecoveryConfigurationFile -Raw | ConvertFrom-Json
        if (($configuration.PSObject.Properties.Name | Sort-Object) -join ',' -ne 'parameters,schema' -or
            $configuration.schema -ne 'marty.windows-recovery/v1' -or
            $configuration.parameters -isnot [PSCustomObject]) { throw 'invalid schema' }
        $strings = @('StackDirectory', 'ProductionEnvFile', 'ProductionProject', 'OpenbaoComposeFile',
                     'OpenbaoEnvFile', 'OpenbaoProject', 'ExpectedDockerContext')
        foreach ($property in $configuration.parameters.PSObject.Properties) {
            $name = $property.Name
            $value = $property.Value
            if ($name -in $strings) {
                if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) { throw 'invalid string' }
            } elseif ($name -eq 'ProductionComposeFile') {
                if ($value -isnot [array] -or $value.Count -eq 0 -or
                    @($value | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count) {
                    throw 'invalid Compose files'
                }
            } elseif ($name -eq 'RecoverBeta') {
                if ($value -isnot [bool]) { throw 'invalid beta selection' }
            } else { throw 'unknown parameter' }
            Set-Variable -Name $name -Value $value
        }
        if (-not $configuration.parameters.StackDirectory -or -not $configuration.parameters.ExpectedDockerContext) {
            throw 'stack and context required'
        }
    } catch { throw 'Invalid retained recovery configuration; use the documented nonsecret schema.' }
}

$env:Path = "C:\Program Files\Docker\Docker\resources\bin;$env:Path"

if (-not $StackDirectory) { $StackDirectory = Split-Path -Parent $PSScriptRoot }
$RepoRoot = (Resolve-Path -LiteralPath $StackDirectory).Path
if (-not $ProductionEnvFile) { $ProductionEnvFile = Join-Path $RepoRoot '.env.selfhost.production.local' }
if (-not $OpenbaoEnvFile) { $OpenbaoEnvFile = $ProductionEnvFile }
if (-not $OpenbaoComposeFile) { $OpenbaoComposeFile = Join-Path $RepoRoot 'docker-compose.selfhost.openbao.yml' }
$ProductionComposeArgs = @('--project-directory', $RepoRoot, '--project-name', $ProductionProject,
                           '--env-file', $ProductionEnvFile)
foreach ($composeFile in $ProductionComposeFile) { $ProductionComposeArgs += @('-f', $composeFile) }
$OpenbaoComposeArgs = @('--project-directory', $RepoRoot, '--project-name', $OpenbaoProject,
                        '--env-file', $OpenbaoEnvFile, '-f', $OpenbaoComposeFile)
$OpenbaoContainer = "$OpenbaoProject-openbao-1"
$OpenbaoUnsealContainer = "$OpenbaoProject-openbao-unseal-1"
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

function Invoke-DockerRead([string[]]$Arguments) {
    # PowerShell 5.1 transcripts retain native stderr even when redirected.
    # Capture it through Process pipes so no native error record is created.
    function Quote-Argument([string]$Value) {
        $escaped = [regex]::Replace($Value, '(\\*)("|$)', {
            param($match)
            $suffix = if ($match.Groups[2].Value -eq '"') { '\"' } else { '' }
            return ('\' * (2 * $match.Groups[1].Value.Length)) + $suffix
        })
        return '"' + $escaped + '"'
    }
    $process = New-Object System.Diagnostics.Process
    try {
        $process.StartInfo.FileName = (Get-Command docker.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
        $process.StartInfo.Arguments = ($Arguments | ForEach-Object { Quote-Argument $_ }) -join ' '
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        if (-not $process.Start()) { throw 'start failed' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) {
            $process.Kill()
            throw 'timeout'
        }
        $output = $stdout.GetAwaiter().GetResult()
        $discarded = $stderr.GetAwaiter().GetResult()
        if ($output.Length -gt 1048576) { throw 'oversized output' }
        return [pscustomobject]@{ Code = $process.ExitCode; Output = $output.TrimEnd([char[]]"`r`n") }
    } catch { throw 'Docker read operation failed; native diagnostics were withheld.' }
    finally { $process.Dispose() }
}

function Assert-ComposeInputs([string[]]$Arguments, [string[]]$RequiredServices = @()) {
    # Never print rendered configuration: it can contain interpolated secrets.
    for ($i = 0; $i -lt $Arguments.Count; $i += 2) {
        if ($Arguments[$i] -in @('-f', '--env-file', '--project-directory')) {
            $path = $Arguments[$i + 1]
            if (-not [IO.Path]::IsPathRooted($path) -or -not (Test-Path -LiteralPath $path)) {
                throw 'Recovery requires existing absolute Compose, environment and project paths.'
            }
        }
    }
    $result = Invoke-DockerRead (@('compose') + $Arguments + @('config', '--quiet'))
    if ($result.Code -ne 0) { throw 'Recovery Compose preflight failed; no services were changed.' }
    if ($RequiredServices.Count) {
        $result = Invoke-DockerRead (@('compose') + $Arguments + @('config', '--services'))
        $services = @($result.Output -split '\r?\n')
        if ($result.Code -ne 0 -or 'openbao-bootstrap' -in $services -or
            @($RequiredServices | Where-Object { $_ -notin $services }).Count) {
            throw 'OpenBao recovery requires the persistent unseal service and an inactive bootstrap profile; no services were changed.'
        }
    }
}

function Test-ContainerReady([string]$Name) {
    $result = Invoke-DockerRead @('inspect', '-f', '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}', $Name)
    if ($result.Code -ne 0) { return $false }
    $parts = ($result.Output -split '\|', 2)
    return $parts[0] -eq 'running' -and ($parts[1] -eq 'none' -or $parts[1] -eq 'healthy')
}

try {
    $deadline = (Get-Date).AddMinutes(5)
    do {
        try { $info = Invoke-DockerRead @('info'); $dockerReady = ($info.Code -eq 0) } catch { $dockerReady = $false }
        if (-not $dockerReady) { Start-Sleep -Seconds 5 }
    } while (-not $dockerReady -and (Get-Date) -lt $deadline)
    if (-not $dockerReady) { throw 'Docker Desktop did not become ready within five minutes.' }

    if ($ExpectedDockerContext) {
        $context = Invoke-DockerRead @('context', 'show')
        if ($context.Code -ne 0 -or $context.Output -ne $ExpectedDockerContext) {
            throw 'Selected Docker context differs from retained recovery settings; no context was switched.'
        }
    }
    $engine = Invoke-DockerRead @('info', '--format', '{{.OSType}}')
    if ($engine.Code -ne 0 -or $engine.Output -ne 'linux') { throw 'Recovery requires the selected Linux Docker engine.' }
    if ($env:COMPOSE_PROFILES) { throw 'Clear COMPOSE_PROFILES; recovery must not activate initialization profiles.' }

    Push-Location $RepoRoot
    try {
        if (Test-Path -LiteralPath (Join-Path $RepoRoot '.marty-website/transaction.json')) {
            throw 'An interrupted website transaction requires deploy_website.py --recover before reboot recovery.'
        }
        if (Test-Path -LiteralPath (Join-Path $RepoRoot '.marty-website/deploy.lock')) {
            throw 'A website deployment lock exists; wait for its owner or confirm stale-lock recovery before proceeding.'
        }
        if (-not $HasIndependentWebsite -and $ProductionComposeFile.Count -eq 0) {
            throw 'Combined recovery requires the complete ordered -ProductionComposeFile list, including retained overlays.'
        }
        if ($HasIndependentWebsite -and $ProductionComposeFile.Count -gt 0) {
            throw 'Split recovery uses authenticated retained website state; do not override its Compose files.'
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
            $ProductionComposeArgs += @('-f', (Join-Path $RepoRoot '.marty-website/compose.website.json'))
            $OpenbaoComposeArgs = @('--project-directory', $RepoRoot, '--project-name', [string]$WebsiteHost.openbao_project,
                                    '--env-file', [string]$WebsiteHost.openbao_env_file, '-f', [string]$WebsiteHost.openbao_compose_file)
            $OpenbaoContainer = "$($WebsiteHost.openbao_project)-openbao-1"
            $OpenbaoUnsealContainer = "$($WebsiteHost.openbao_project)-openbao-unseal-1"
        }
        Assert-ComposeInputs $ProductionComposeArgs
        Assert-ComposeInputs $OpenbaoComposeArgs @('openbao', 'openbao-unseal')
        if ($RecoverBeta) {
            Assert-ComposeInputs @('--env-file', $BetaEnv, '-f', $BetaCompose[0], '-f', $BetaCompose[1], '-f', $BetaCompose[2])
        }
        if ($CheckOnly) {
            Write-Host 'Recovery configuration preflight passed. No services changed; runtime/reboot qualification is not implied.'
            exit 0
        }
        if ($HasIndependentWebsite) {
            Invoke-Step 'Restore authenticated website and edge before product readiness' {
                & $env:MARTY_WEBSITE_PYTHON (Join-Path $PSScriptRoot 'deploy_website.py') @WebsiteArguments
            }
        }
        if (-not (Test-ContainerReady $OpenbaoContainer) -or
            -not (Test-ContainerReady $OpenbaoUnsealContainer)) {
            Invoke-Step 'Start standalone OpenBao' {
                docker compose @OpenbaoComposeArgs up -d --no-build openbao openbao-unseal
            }
        }
        $baoDeadline = (Get-Date).AddMinutes(2)
        while ((-not (Test-ContainerReady $OpenbaoContainer) -or
                -not (Test-ContainerReady $OpenbaoUnsealContainer)) -and
               (Get-Date) -lt $baoDeadline) {
            Start-Sleep -Seconds 5
        }
        if (-not (Test-ContainerReady $OpenbaoContainer) -or
            -not (Test-ContainerReady $OpenbaoUnsealContainer)) {
            throw 'OpenBao and its persistent unseal helper did not become ready.'
        }
        if ($HasIndependentWebsite) {
            Invoke-Step 'Recover product while retaining the selected website overlay' {
                # The website lock was released after --start-current. Select
                # only default-active product roles with --no-deps; an unlocked
                # recovery must never reconcile edge/website slots from a stale
                # Compose model during a concurrent website promotion.
                & $env:MARTY_WEBSITE_PYTHON (Join-Path $PSScriptRoot 'recover_product_services.py') -- @ProductionComposeArgs
            }
        } else {
            Invoke-Step 'Recover self-host production stack' {
                docker compose @ProductionComposeArgs up -d --no-build --wait
            }
        }
        $betaServices = @('marty-gateway', 'marty-ui-prod', 'cloudflared-tunnel', 'tunnel-nginx-proxy')
        if ($RecoverBeta -and @($betaServices | Where-Object { -not (Test-ContainerReady $_) }).Count -gt 0) {
            Invoke-Step 'Recover beta application stack' {
                docker compose --env-file $BetaEnv -f $BetaCompose[0] -f $BetaCompose[1] -f $BetaCompose[2] up -d --no-build --wait
            }
            Invoke-Step 'Recover beta tunnel' {
                docker compose --env-file $BetaEnv -f $BetaCompose[0] -f $BetaCompose[1] -f $BetaCompose[2] up -d --no-build --wait docs nginx-proxy cloudflared
            }
        }
        Invoke-Step 'Validate production containers' {
            docker compose @ProductionComposeArgs ps --status running
        }
        if ($RecoverBeta) {
            Invoke-Step 'Validate beta containers' {
                docker compose --env-file $BetaEnv -f $BetaCompose[0] -f $BetaCompose[1] -f $BetaCompose[2] ps --status running
            }
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
