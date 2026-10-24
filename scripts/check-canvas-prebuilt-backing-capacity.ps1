[CmdletBinding()]
param([Parameter(Mandatory = $true)][long]$PrebuiltImageSizeBytes,
      [string]$DockerDesktopDataDiskPath = "$env:LOCALAPPDATA\Docker\wsl\disk\docker_data.vhdx")
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'runner-host-capacity-policy.ps1')
Get-CanvasDockerBackingCapacity -DataDiskPath $DockerDesktopDataDiskPath -Mode PrebuiltRuntime `
    -PrebuiltImageSizeBytes $PrebuiltImageSizeBytes | ConvertTo-Json -Compress
