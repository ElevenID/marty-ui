[CmdletBinding()]
param(
    [string]$GeneratedEnvFile = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env.beta.generated.local")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$resolvedEnvFile = [IO.Path]::GetFullPath($GeneratedEnvFile)
$repoPrefix = $repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $resolvedEnvFile.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Generated beta environment file must stay inside the repository working directory"
}
if (-not (Test-Path -LiteralPath $resolvedEnvFile -PathType Leaf)) {
    throw "Generated beta environment file is missing: $resolvedEnvFile"
}

$lines = @(Get-Content -LiteralPath $resolvedEnvFile)
$tokenLines = @($lines | Where-Object { $_ -match '^GRPC_SERVICE_TOKEN=' })
if ($tokenLines.Count -gt 1) {
    throw "Generated beta environment file contains duplicate GRPC_SERVICE_TOKEN entries"
}
if ($tokenLines.Count -eq 1) {
    $token = ($tokenLines[0] -split '=', 2)[1]
    if ($token.Length -lt 32 -or $token -match '^(?i:change[-_]?me|changeme|replace[-_]?me)') {
        throw "Existing GRPC_SERVICE_TOKEN must be a non-placeholder value of at least 32 characters"
    }
    Write-Host "Beta gRPC service token is already configured; its value was not displayed."
    exit 0
}

$buffer = [byte[]]::new(48)
$generator = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $generator.GetBytes($buffer)
}
finally {
    $generator.Dispose()
}
$token = ([BitConverter]::ToString($buffer) -replace '-', '').ToLowerInvariant()
$updatedLines = @($lines) + "GRPC_SERVICE_TOKEN=$token"
[IO.File]::WriteAllLines($resolvedEnvFile, $updatedLines, [Text.UTF8Encoding]::new($false))
Write-Host "Generated a beta-only gRPC service token without displaying its value."
