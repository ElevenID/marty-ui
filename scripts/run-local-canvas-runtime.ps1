[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ArtifactDir,
      [Parameter(Mandatory = $true)][string]$BetaDeploymentManifest,
      [string]$DockerDesktopDataDiskPath,
      [switch]$Bootstrap)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'beta-deployment-lock.ps1')
$hostGate = [System.Threading.Mutex]::new($false, 'Global\ElevenIDMartyDockerRunner')
$hostOwned = $false
$betaGate = $null
try {
    $hostOwned = $hostGate.WaitOne(0)
    if (-not $hostOwned) { throw 'Another Docker host runner is active' }
    $betaGate = Enter-BetaDeploymentLock
    $arguments = @((Join-Path $PSScriptRoot 'run_local_canvas_runtime.py'),
                   '--artifact-dir', $ArtifactDir, '--beta-deployment-manifest', $BetaDeploymentManifest)
    if ($Bootstrap) { $arguments += '--bootstrap' }
    if ($DockerDesktopDataDiskPath) { $arguments += @('--docker-desktop-data-disk-path', $DockerDesktopDataDiskPath) }
    & python @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Local Canvas runtime failed; inspect its retained evidence before retrying' }
}
finally {
    if ($null -ne $betaGate) { Exit-BetaDeploymentLock -Lock $betaGate }
    if ($hostOwned) { $hostGate.ReleaseMutex() }
    $hostGate.Dispose()
}
