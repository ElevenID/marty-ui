[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ArtifactDir,
      [Parameter(Mandatory = $true)][string]$SourceRepoRoot,
      [Parameter(Mandatory = $true)][string]$RuntimeConfigRoot,
      [Parameter(Mandatory = $true)][string]$OutputPath, [switch]$Apply)

# Forward completion only: migrations must already have succeeded. Never restore
# databases or rerun the deployment entrypoint against an outstanding mutation.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'beta-deployment-lock.ps1')
. (Join-Path $PSScriptRoot 'beta-state-volume-plan.ps1')
. (Join-Path $PSScriptRoot 'beta-passport-fence-legacy-boundary.ps1')
$lock = Enter-BetaDeploymentLock -AllowPending
try {
    if (-not (Test-Path -LiteralPath (Get-BetaMutationMarkerPath) -PathType Leaf)) {
        throw 'Forward completion requires the pending cutover marker'
    }
    $backup = Get-Content -LiteralPath (Join-Path $ArtifactDir 'backup-manifest.json') -Raw | ConvertFrom-Json
    Assert-BetaStateVolumePlan -Expected @($backup.state_volumes)
    $postgres = @($backup.state_volumes | Where-Object service -eq 'postgres')[0].container_id
    Assert-LegacyBetaDatabaseUnfenced -PostgresContainer $postgres
    $arguments = @((Join-Path $PSScriptRoot 'complete_local_beta_startup.py'),
        '--artifact-dir', $ArtifactDir, '--source-repo-root', $SourceRepoRoot,
        '--runtime-config-root', $RuntimeConfigRoot, '--output', $OutputPath)
    if ($Apply) { $arguments += '--apply' }
    & python @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Forward startup failed; retain pending marker and inspect beta' }
    if ($Apply) { Complete-BetaMutation }
}
finally { Exit-BetaDeploymentLock -Lock $lock }
