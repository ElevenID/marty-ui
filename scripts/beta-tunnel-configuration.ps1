function Get-BetaTunnelInputBinding {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$CredentialEnvFile,
        [object]$Expected,
        [string]$OverrideOutput
    )
    $arguments = @((Join-Path $RepoRoot "scripts/beta_tunnel_configuration.py"),
        "--credential-env-file", $CredentialEnvFile)
    if ($null -ne $Expected) {
        $arguments += @("--expected-fingerprint", [string]$Expected.credential_sha256,
            "--expected-container", [string]$Expected.connector_id)
    }
    if (-not [string]::IsNullOrWhiteSpace($OverrideOutput)) {
        $arguments += @("--override-output", $OverrideOutput)
    }
    $json = & python @arguments
    if ($LASTEXITCODE -ne 0) { throw "Beta tunnel private input validation failed" }
    return (($json -join "`n") | ConvertFrom-Json)
}
