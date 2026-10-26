# Expected startup failures are observations, not deployment exceptions.
function Invoke-BetaDockerReadinessProbe {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $output = @(& docker @Arguments 2>&1)
    return [pscustomobject]@{ exit_code = $LASTEXITCODE; output = @($output | ForEach-Object { [string]$_ }) }
}
