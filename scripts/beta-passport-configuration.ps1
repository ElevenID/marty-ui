# Explicit beta selection and read-only, fail-closed validation.
function Get-BetaPassportProfiles {
    param([bool]$Enabled, [bool]$PhysicalProvider = $false)
    if ($PhysicalProvider -and -not $Enabled) {
        throw "Physical provider beta mode requires native passport selection"
    }
    if ($Enabled -and $PhysicalProvider) {
        "docker-compose.profile.passport-provider-base.yml"
        "docker-compose.profile.passport-native-physical-beta.yml"
    }
    elseif ($Enabled) { "docker-compose.profile.passport-native-beta.yml" }
}

function Assert-BetaPassportConfiguration {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string[]]$EnvFiles,
        [Parameter(Mandatory = $true)][string[]]$ComposeFiles,
        [bool]$PassportEnabled,
        [bool]$PhysicalProvider = $false,
        [string]$PreparedServicesImage = ""
    )
    $validationArgs = @(
        (Join-Path $RepoRoot "scripts/validate_beta_passport_configuration.py"),
        "--project", "elevenid-beta"
    )
    foreach ($path in $EnvFiles) { $validationArgs += @("--env-file", $path) }
    foreach ($path in $ComposeFiles) { $validationArgs += @("--file", $path) }
    if ($PassportEnabled) { $validationArgs += "--passport-enabled" }
    if ($PhysicalProvider) { $validationArgs += "--physical-provider" }
    if ($PreparedServicesImage) {
        if (-not $PassportEnabled -or $PhysicalProvider -or $PreparedServicesImage -cnotmatch '^sha256:[0-9a-f]{64}$') {
            throw "Prepared local passport image requires native simulator selection and an immutable ID"
        }
        $validationArgs += @("--prepared-services-image", $PreparedServicesImage)
    }
    & python @validationArgs
    if ($LASTEXITCODE -ne 0) { throw "Beta passport configuration validation failed" }
}
