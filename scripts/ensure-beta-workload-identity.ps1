[CmdletBinding()]
param(
    [string]$GeneratedEnvFile = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env.beta.generated.local"),
    [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) ".beta-workload-identity")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoPrefix = $repoRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
) + [IO.Path]::DirectorySeparatorChar

function Resolve-RepositoryPath([string]$Path, [string]$Description) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description must stay inside the repository working directory"
    }
    return $resolved
}

function Get-DotEnvValue([string[]]$Lines, [string]$Name) {
    $matches = @($Lines | Where-Object { $_ -match "^$([regex]::Escape($Name))=" })
    if ($matches.Count -ne 1) {
        throw "Generated beta environment file must contain exactly one $Name entry"
    }
    $value = ($matches[0] -split "=", 2)[1].Trim()
    if (-not $value) {
        throw "Generated beta environment file has an empty $Name entry"
    }
    return $value
}

$resolvedEnvFile = Resolve-RepositoryPath $GeneratedEnvFile "Generated beta environment file"
$resolvedOutputDirectory = Resolve-RepositoryPath $OutputDirectory "Beta workload identity directory"
if (-not (Test-Path -LiteralPath $resolvedEnvFile -PathType Leaf)) {
    throw "Generated beta environment file is missing: $resolvedEnvFile"
}
$lines = @(Get-Content -LiteralPath $resolvedEnvFile)
$retiredWorkloadKeys = @(
    @{ Env = "MARTY_WORKLOAD_IDENTITY_CA_KEY_FILE"; File = "workload_identity_ca_key" },
    @{ Env = "SIGNING_KEYS_WORKLOAD_SERVER_KEY_FILE"; File = "signing_keys_workload_server_key" },
    @{ Env = "PP_WORKLOAD_SERVER_KEY_FILE"; File = "pp_workload_server_key" },
    @{ Env = "AUTH_WORKLOAD_CLIENT_KEY_FILE"; File = "auth_workload_client_key" },
    @{ Env = "AUTH_WORKLOAD_SERVER_KEY_FILE"; File = "auth_workload_server_key" },
    @{ Env = "GATEWAY_WORKLOAD_CLIENT_KEY_FILE"; File = "gateway_workload_client_key" },
    @{ Env = "ISSUANCE_WORKLOAD_SERVER_KEY_FILE"; File = "issuance_workload_server_key" },
    @{ Env = "ENVOY_ISSUANCE_CLIENT_KEY_FILE"; File = "envoy_issuance_client_key" },
    @{ Env = "VERIFICATION_WORKLOAD_CLIENT_KEY_FILE"; File = "verification_workload_client_key" },
    @{ Env = "DEPLOYMENT_PROFILE_WORKLOAD_CLIENT_KEY_FILE"; File = "deployment_profile_workload_client_key" },
    @{ Env = "COMPLIANCE_PROFILE_WORKLOAD_CLIENT_KEY_FILE"; File = "compliance_profile_workload_client_key" },
    @{ Env = "FLOW_WORKLOAD_CLIENT_KEY_FILE"; File = "flow_workload_client_key" },
    @{ Env = "FLOW_WORKLOAD_SERVER_KEY_FILE"; File = "flow_workload_server_key" }
)
foreach ($retired in $retiredWorkloadKeys) {
    if (@($lines | Where-Object { $_ -match "^$([regex]::Escape($retired.Env))=" }).Count -gt 0) {
        throw "$($retired.Env) is retired; provision a remote signer and public certificate"
    }
    if (Test-Path -LiteralPath (Join-Path $resolvedOutputDirectory $retired.File) -PathType Leaf) {
        throw "Retired $($retired.File) private-key file remains in beta workload identity directory"
    }
}

foreach ($name in @(
    "MARTY_WORKLOAD_IDENTITY_CA_CERT_FILE",
    "OPENBAO_TLS_CA_CERT_FILE",
    "SIGNING_KEYS_WORKLOAD_SERVER_CERT_FILE",
    "SIGNING_KEYS_TLS_KMS_TOKEN_FILE",
    "AUTH_WORKLOAD_SERVER_CERT_FILE",
    "AUTH_SERVER_TLS_KMS_TOKEN_FILE",
    "GATEWAY_WORKLOAD_CLIENT_CERT_FILE",
    "GATEWAY_TLS_KMS_TOKEN_FILE",
    "ISSUANCE_WORKLOAD_SERVER_CERT_FILE",
    "ISSUANCE_TLS_KMS_TOKEN_FILE",
    "ENVOY_ISSUANCE_CLIENT_CERT_FILE",
    "ENVOY_ISSUANCE_TLS_KMS_TOKEN_FILE",
    "COMPLIANCE_PROFILE_WORKLOAD_CLIENT_CERT_FILE",
    "COMPLIANCE_PROFILE_TLS_KMS_TOKEN_FILE",
    "DEPLOYMENT_PROFILE_WORKLOAD_CLIENT_CERT_FILE",
    "DEPLOYMENT_PROFILE_TLS_KMS_TOKEN_FILE"
)) {
    $path = Get-DotEnvValue $lines $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$name must identify a readable file"
    }
}
foreach ($role in @("SIGNING_KEYS", "AUTH_SERVER", "GATEWAY", "ISSUANCE", "ENVOY_ISSUANCE", "COMPLIANCE_PROFILE", "DEPLOYMENT_PROFILE")) {
    $kmsAddress = Get-DotEnvValue $lines "${role}_TLS_KMS_ADDR"
    $kmsUri = $null
    if (-not [Uri]::TryCreate($kmsAddress, [UriKind]::Absolute, [ref]$kmsUri) -or
        $kmsUri.Scheme -ne "https" -or -not $kmsUri.Host -or
        $kmsUri.UserInfo -or $kmsUri.Query -or $kmsUri.Fragment) {
        throw "${role}_TLS_KMS_ADDR must be a trusted HTTPS OpenBao origin"
    }
    $null = Get-DotEnvValue $lines "${role}_TLS_KMS_KEY_NAME"
    $keyVersion = Get-DotEnvValue $lines "${role}_TLS_KMS_KEY_VERSION"
    $parsedVersion = 0
    if (-not [int]::TryParse($keyVersion, [ref]$parsedVersion) -or $parsedVersion -le 0) {
        throw "${role}_TLS_KMS_KEY_VERSION must be a positive integer"
    }
}

if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "OpenSSL is required to validate beta workload identity certificates"
}
$ca = Get-DotEnvValue $lines "MARTY_WORKLOAD_IDENTITY_CA_CERT_FILE"
$certificate = Get-DotEnvValue $lines "SIGNING_KEYS_WORKLOAD_SERVER_CERT_FILE"
& openssl x509 -checkend 3600 -noout -in $certificate
if ($LASTEXITCODE -ne 0) {
    throw "Signing Keys workload certificate expires within one hour or is invalid"
}
& openssl verify -CAfile $ca $certificate
if ($LASTEXITCODE -ne 0) {
    throw "Signing Keys workload certificate is not trusted by the workload CA"
}
$subjectAltName = & openssl x509 -noout -ext subjectAltName -in $certificate
if ($LASTEXITCODE -ne 0 -or ($subjectAltName -join "`n") -notmatch [regex]::Escape("DNS:signing-keys")) {
    throw "Signing Keys workload certificate must contain the signing-keys DNS SAN"
}
$extendedKeyUsage = & openssl x509 -noout -ext extendedKeyUsage -in $certificate
if ($LASTEXITCODE -ne 0 -or ($extendedKeyUsage -join "`n") -notmatch "TLS Web Server Authentication") {
    throw "Signing Keys workload certificate must permit server authentication"
}

foreach ($identity in @(
    @{ Env = "AUTH_WORKLOAD_SERVER_CERT_FILE"; Label = "Auth server"; San = "DNS:auth"; Usage = "TLS Web Server Authentication" },
    @{ Env = "GATEWAY_WORKLOAD_CLIENT_CERT_FILE"; Label = "Gateway client"; San = "URI:spiffe://marty.internal/service/gateway"; Usage = "TLS Web Client Authentication" },
    @{ Env = "ISSUANCE_WORKLOAD_SERVER_CERT_FILE"; Label = "Issuance server"; San = "DNS:issuance-native"; Usage = "TLS Web Server Authentication" },
    @{ Env = "ENVOY_ISSUANCE_CLIENT_CERT_FILE"; Label = "Envoy Issuance client"; San = "URI:spiffe://marty.internal/service/envoy-issuance-bridge"; Usage = "TLS Web Client Authentication" },
    @{ Env = "COMPLIANCE_PROFILE_WORKLOAD_CLIENT_CERT_FILE"; Label = "Compliance Profile client"; San = "URI:spiffe://marty.internal/service/compliance-profile"; Usage = "TLS Web Client Authentication" },
    @{ Env = "DEPLOYMENT_PROFILE_WORKLOAD_CLIENT_CERT_FILE"; Label = "Deployment Profile client"; San = "URI:spiffe://marty.internal/service/deployment-profile"; Usage = "TLS Web Client Authentication" }
)) {
    $publicCertificate = Get-DotEnvValue $lines $identity.Env
    & openssl x509 -checkend 3600 -noout -in $publicCertificate
    if ($LASTEXITCODE -ne 0) {
        throw "$($identity.Label) certificate expires within one hour or is invalid"
    }
    & openssl verify -CAfile $ca $publicCertificate
    if ($LASTEXITCODE -ne 0) {
        throw "$($identity.Label) certificate is not trusted by the workload CA"
    }
    $san = & openssl x509 -noout -ext subjectAltName -in $publicCertificate
    if ($LASTEXITCODE -ne 0 -or ($san -join "`n") -notmatch [regex]::Escape($identity.San)) {
        throw "$($identity.Label) certificate must contain $($identity.San)"
    }
    $usage = & openssl x509 -noout -ext extendedKeyUsage -in $publicCertificate
    if ($LASTEXITCODE -ne 0 -or ($usage -join "`n") -notmatch [regex]::Escape($identity.Usage)) {
        throw "$($identity.Label) certificate must permit $($identity.Usage)"
    }
}

Write-Host "Beta workload identity references are valid; the private signer remains in KMS."
