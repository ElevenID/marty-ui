# Run with Windows PowerShell. Load only the exact stop function AST; never
# execute the operator's top-level beta mutation path in this rehearsal.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$operator = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'scripts/start-passport-beta-db-maintenance.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $operator, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Beta operator has a PowerShell parse error' }
$functions = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Stop-BetaGeneration'
}, $true))
if ($functions.Count -ne 1) { throw 'Exact beta stop function is absent' }
. ([scriptblock]::Create($functions[0].Extent.Text))

$cloud = 'a' * 64
$gateway = 'b' * 64
$flow = 'c' * 64
$auth = 'd' * 64
$postgres = 'e' * 64
$script:running = @{
    $cloud = $true; $gateway = $true; $flow = $false
    $auth = $true; $postgres = $true
}
$script:stops = [Collections.Generic.List[string]]::new()
$script:identityChecks = 0

function Assert-DockerIdentity {
    param($Plan)
    if ($Plan.schema -cne 'marty.passport-beta-db-maintenance-plan/v1') {
        throw 'Unexpected plan in disposable stop rehearsal'
    }
    $script:identityChecks += 1
}

function docker {
    if ($args.Count -lt 2) { throw 'Unexpected Docker command' }
    $id = [string]$args[-1]
    if (-not $script:running.ContainsKey($id)) {
        throw 'Mock Docker was called for an unplanned container'
    }
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'inspect') {
        if ($script:running[$id]) { return 'true' }
        return 'false'
    }
    if ($args[0] -eq 'stop') {
        $script:stops.Add($id)
        $script:running[$id] = $false
        return $id
    }
    throw 'Unexpected Docker command in stop rehearsal'
}

$plan = [pscustomobject]@{
    schema = 'marty.passport-beta-db-maintenance-plan/v1'
    beta_generation = @(
        [pscustomobject]@{ service = 'flow'; container_id = $flow },
        [pscustomobject]@{ service = 'postgres'; container_id = $postgres },
        [pscustomobject]@{ service = 'gateway'; container_id = $gateway },
        [pscustomobject]@{ service = 'auth'; container_id = $auth },
        [pscustomobject]@{ service = 'cloudflared'; container_id = $cloud }
    )
}
Stop-BetaGeneration -Plan $plan
if (($script:stops -join ',') -cne (@($cloud, $gateway, $auth) -join ',')) {
    throw 'Beta ingress-first stop order or resume skip was wrong'
}
if (-not $script:running[$postgres] -or $script:identityChecks -ne 4) {
    throw 'Beta PostgreSQL was stopped or Docker identity was not checked'
}
Stop-BetaGeneration -Plan $plan
if ($script:stops.Count -ne 3) {
    throw 'Resuming an already stopped generation repeated a stop'
}
Write-Output 'disposable beta stop and resume rehearsal passed'
