[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ArtifactDir,
      [Parameter(Mandatory = $true)][string]$OutputPath, [switch]$Apply)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'beta-deployment-lock.ps1')
. (Join-Path $PSScriptRoot 'beta-state-volume-plan.ps1')
. (Join-Path $PSScriptRoot 'beta-passport-fence-legacy-boundary.ps1')
$lock = Enter-BetaDeploymentLock -AllowPending
try {
    if (-not (Test-Path -LiteralPath (Get-BetaMutationMarkerPath) -PathType Leaf)) {
        throw 'Unchanged-state recovery requires the pending cutover marker'
    }
    $backup = Get-Content -LiteralPath (Join-Path $ArtifactDir 'backup-manifest.json') -Raw | ConvertFrom-Json
    Assert-BetaStateVolumePlan -Expected @($backup.state_volumes) -SameContainers
    $postgres = @($backup.state_volumes | Where-Object service -eq 'postgres')[0].container_id
    Assert-LegacyBetaDatabaseUnfenced -PostgresContainer $postgres
    $arguments = @((Join-Path $PSScriptRoot 'recover_unchanged_beta_cutover.py'),
        '--artifact-dir', $ArtifactDir, '--output', $OutputPath)
    if ($Apply) { $arguments += '--apply' }
    & python @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Beta recovery failed; retain pending marker and inspect current state' }
    if ($Apply) { Complete-BetaMutation }
}
finally { Exit-BetaDeploymentLock -Lock $lock }
