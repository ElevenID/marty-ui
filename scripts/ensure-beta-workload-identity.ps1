[CmdletBinding()]
param(
    [string]$GeneratedEnvFile = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env.beta.generated.local"),
    [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) ".beta-workload-identity"),
    [ValidateRange(1, 30)]
    [int]$Days = 14
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

$resolvedEnvFile = Resolve-RepositoryPath $GeneratedEnvFile "Generated beta environment file"
$resolvedOutputDirectory = Resolve-RepositoryPath $OutputDirectory "Beta workload identity directory"
if (-not (Test-Path -LiteralPath $resolvedEnvFile -PathType Leaf)) {
    throw "Generated beta environment file is missing: $resolvedEnvFile"
}
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "OpenSSL is required to provision beta workload identity"
}

$configCandidates = @()
if ($env:OPENSSL_CONF -and (Test-Path -LiteralPath $env:OPENSSL_CONF -PathType Leaf)) {
    $configCandidates += $env:OPENSSL_CONF
}
$configCandidates += @(
    (Join-Path $env:ProgramFiles "Git\usr\ssl\openssl.cnf"),
    (Join-Path $env:ProgramFiles "Git\mingw64\etc\ssl\openssl.cnf")
)
$opensslConfig = $configCandidates |
    Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
    Select-Object -First 1
if (-not $opensslConfig) {
    throw "Could not locate openssl.cnf; set OPENSSL_CONF to a valid OpenSSL configuration file"
}

function Invoke-OpenSsl([string[]]$Arguments) {
    & openssl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed while provisioning beta workload identity"
    }
}

function Set-DotEnvValue([string[]]$Lines, [string]$Name, [string]$Value) {
    $matches = @($Lines | Where-Object { $_ -match "^$([regex]::Escape($Name))=" })
    if ($matches.Count -gt 1) {
        throw "Generated beta environment file contains duplicate $Name entries"
    }
    $replacement = "$Name=$Value"
    if ($matches.Count -eq 0) {
        return @($Lines) + $replacement
    }
    return @($Lines | ForEach-Object {
        if ($_ -match "^$([regex]::Escape($Name))=") { $replacement } else { $_ }
    })
}

$leafCertificates = @(
    [pscustomobject]@{
        Certificate = "pp_workload_server_cert"
        Key = "pp_workload_server_key"
        CommonName = "presentation-policy"
        SubjectAlternativeName = "DNS:presentation-policy"
        ExtendedKeyUsage = "serverAuth"
    },
    [pscustomobject]@{
        Certificate = "flow_workload_client_cert"
        Key = "flow_workload_client_key"
        CommonName = "marty-flow-client"
        SubjectAlternativeName = "URI:spiffe://marty.internal/service/flow"
        ExtendedKeyUsage = "clientAuth"
    },
    [pscustomobject]@{
        Certificate = "flow_workload_server_cert"
        Key = "flow_workload_server_key"
        CommonName = "flow"
        SubjectAlternativeName = "DNS:flow"
        ExtendedKeyUsage = "serverAuth"
    },
    [pscustomobject]@{
        Certificate = "auth_workload_client_cert"
        Key = "auth_workload_client_key"
        CommonName = "marty-auth-client"
        SubjectAlternativeName = "URI:spiffe://marty.internal/service/auth"
        ExtendedKeyUsage = "clientAuth"
    },
    [pscustomobject]@{
        Certificate = "applicant_workload_client_cert"
        Key = "applicant_workload_client_key"
        CommonName = "marty-applicant-client"
        SubjectAlternativeName = "URI:spiffe://marty.internal/service/applicant"
        ExtendedKeyUsage = "clientAuth"
    },
    [pscustomobject]@{
        Certificate = "verification_workload_client_cert"
        Key = "verification_workload_client_key"
        CommonName = "marty-verification-client"
        SubjectAlternativeName = "URI:spiffe://marty.internal/service/verification"
        ExtendedKeyUsage = "clientAuth"
    },
    [pscustomobject]@{
        Certificate = "deployment_profile_workload_client_cert"
        Key = "deployment_profile_workload_client_key"
        CommonName = "marty-deployment-profile-client"
        SubjectAlternativeName = "URI:spiffe://marty.internal/service/deployment-profile"
        ExtendedKeyUsage = "clientAuth"
    },
    [pscustomobject]@{
        Certificate = "compliance_profile_workload_client_cert"
        Key = "compliance_profile_workload_client_key"
        CommonName = "marty-compliance-profile-client"
        SubjectAlternativeName = "URI:spiffe://marty.internal/service/compliance-profile"
        ExtendedKeyUsage = "clientAuth"
    }
)

$caCertificate = Join-Path $resolvedOutputDirectory "workload_identity_ca_cert"
$caKey = Join-Path $resolvedOutputDirectory "workload_identity_ca_key"
$expectedFiles = @($caCertificate, $caKey)
foreach ($leaf in $leafCertificates) {
    $expectedFiles += Join-Path $resolvedOutputDirectory $leaf.Certificate
    $expectedFiles += Join-Path $resolvedOutputDirectory $leaf.Key
}

$regenerate = @($expectedFiles | Where-Object {
    -not (Test-Path -LiteralPath $_ -PathType Leaf)
}).Count -gt 0
if (-not $regenerate) {
    & openssl x509 -checkend 86400 -noout -in $caCertificate *> $null
    $regenerate = $LASTEXITCODE -ne 0
}

$originalOpenSslConf = $env:OPENSSL_CONF
try {
    $env:OPENSSL_CONF = $opensslConfig
    if ($regenerate) {
        New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory | Out-Null
        foreach ($path in $expectedFiles) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                Remove-Item -LiteralPath $path -Force
            }
        }

        Invoke-OpenSsl @(
            "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", $caKey
        )
        Invoke-OpenSsl @(
            "req", "-x509", "-new", "-sha256", "-key", $caKey,
            "-out", $caCertificate, "-days", $Days,
            "-subj", "/CN=ElevenID beta workload identity CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash"
        )

        foreach ($leaf in $leafCertificates) {
            $certificate = Join-Path $resolvedOutputDirectory $leaf.Certificate
            $key = Join-Path $resolvedOutputDirectory $leaf.Key
            $csr = "$certificate.csr"
            $extensions = "$certificate.ext"
            try {
                Invoke-OpenSsl @(
                    "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-out", $key
                )
                Invoke-OpenSsl @(
                    "req", "-new", "-sha256", "-key", $key, "-out", $csr,
                    "-subj", "/CN=$($leaf.CommonName)"
                )
                [IO.File]::WriteAllLines(
                    $extensions,
                    @(
                        "basicConstraints=critical,CA:FALSE",
                        "keyUsage=critical,digitalSignature,keyAgreement",
                        "extendedKeyUsage=$($leaf.ExtendedKeyUsage)",
                        "subjectAltName=$($leaf.SubjectAlternativeName)",
                        "authorityKeyIdentifier=keyid,issuer",
                        "subjectKeyIdentifier=hash"
                    ),
                    [Text.UTF8Encoding]::new($false)
                )
                Invoke-OpenSsl @(
                    "x509", "-req", "-sha256", "-in", $csr,
                    "-CA", $caCertificate, "-CAkey", $caKey,
                    "-CAserial", (Join-Path $resolvedOutputDirectory "workload_identity_ca_serial"),
                    "-CAcreateserial",
                    "-out", $certificate, "-days", $Days, "-extfile", $extensions
                )
                Invoke-OpenSsl @("verify", "-CAfile", $caCertificate, $certificate)
            }
            finally {
                foreach ($temporaryPath in @($csr, $extensions)) {
                    if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
                        Remove-Item -LiteralPath $temporaryPath -Force
                    }
                }
            }
        }
        $serial = Join-Path $resolvedOutputDirectory "workload_identity_ca_serial"
        if (Test-Path -LiteralPath $serial -PathType Leaf) {
            Remove-Item -LiteralPath $serial -Force
        }
    }
}
finally {
    $env:OPENSSL_CONF = $originalOpenSslConf
}

$environmentNames = [ordered]@{
    MARTY_WORKLOAD_IDENTITY_CA_CERT_FILE = "workload_identity_ca_cert"
    PP_WORKLOAD_SERVER_CERT_FILE = "pp_workload_server_cert"
    PP_WORKLOAD_SERVER_KEY_FILE = "pp_workload_server_key"
    FLOW_WORKLOAD_CLIENT_CERT_FILE = "flow_workload_client_cert"
    FLOW_WORKLOAD_CLIENT_KEY_FILE = "flow_workload_client_key"
    FLOW_WORKLOAD_SERVER_CERT_FILE = "flow_workload_server_cert"
    FLOW_WORKLOAD_SERVER_KEY_FILE = "flow_workload_server_key"
    AUTH_WORKLOAD_CLIENT_CERT_FILE = "auth_workload_client_cert"
    AUTH_WORKLOAD_CLIENT_KEY_FILE = "auth_workload_client_key"
    APPLICANT_WORKLOAD_CLIENT_CERT_FILE = "applicant_workload_client_cert"
    APPLICANT_WORKLOAD_CLIENT_KEY_FILE = "applicant_workload_client_key"
    VERIFICATION_WORKLOAD_CLIENT_CERT_FILE = "verification_workload_client_cert"
    VERIFICATION_WORKLOAD_CLIENT_KEY_FILE = "verification_workload_client_key"
    DEPLOYMENT_PROFILE_WORKLOAD_CLIENT_CERT_FILE = "deployment_profile_workload_client_cert"
    DEPLOYMENT_PROFILE_WORKLOAD_CLIENT_KEY_FILE = "deployment_profile_workload_client_key"
    COMPLIANCE_PROFILE_WORKLOAD_CLIENT_CERT_FILE = "compliance_profile_workload_client_cert"
    COMPLIANCE_PROFILE_WORKLOAD_CLIENT_KEY_FILE = "compliance_profile_workload_client_key"
}
$lines = @(Get-Content -LiteralPath $resolvedEnvFile)
foreach ($entry in $environmentNames.GetEnumerator()) {
    $path = (Join-Path $resolvedOutputDirectory $entry.Value).Replace("\", "/")
    $lines = Set-DotEnvValue $lines $entry.Key $path
}
[IO.File]::WriteAllLines($resolvedEnvFile, $lines, [Text.UTF8Encoding]::new($false))

Write-Host "Beta workload identity is configured; private keys and certificate contents were not displayed."
