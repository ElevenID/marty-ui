# Pure selection and read-only validation; never reads policy file contents.
function Get-BetaDidcommProfiles {
    param([bool]$Enabled)
    if ($Enabled) {
        "docker-compose.profile.didcomm-authcrypt.yml"
        "docker-compose.profile.didcomm-native-authcrypt.yml"
    }
}

function Assert-BetaDidcommConfiguration {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string[]]$EnvFiles,
        [Parameter(Mandatory = $true)][string[]]$ComposeFiles,
        [bool]$AuthcryptEnabled
    )
    $validationArgs = @(
        (Join-Path $RepoRoot "scripts/validate_beta_didcomm_configuration.py"),
        "--project", "elevenid-beta"
    )
    foreach ($path in $EnvFiles) { $validationArgs += @("--env-file", $path) }
    foreach ($path in $ComposeFiles) { $validationArgs += @("--file", $path) }
    if ($AuthcryptEnabled) { $validationArgs += "--authcrypt-enabled" }
    & python @validationArgs
    if ($LASTEXITCODE -ne 0) { throw "Beta DIDComm configuration validation failed" }
}
