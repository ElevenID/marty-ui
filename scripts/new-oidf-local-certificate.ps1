[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$DnsName,

    [int]$Days = 7
)

$ErrorActionPreference = 'Stop'

if ($DnsName -notmatch '^[A-Za-z0-9.-]+$') {
    throw 'DnsName must contain only DNS hostname characters.'
}
if ($Days -lt 1 -or $Days -gt 30) {
    throw 'Days must be between 1 and 30 for a disposable local certificate.'
}
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw 'OpenSSL is required to generate a local certificate.'
}

# Some Windows OpenSSL distributions retain a build-machine default for
# OPENSSLDIR. Prefer an explicit valid configuration file so the helper works
# with Chocolatey/Strawberry as well as Git for Windows installations.
$configCandidates = @()
if ($env:OPENSSL_CONF -and (Test-Path -LiteralPath $env:OPENSSL_CONF)) {
    $configCandidates += $env:OPENSSL_CONF
}
$configCandidates += @(
    (Join-Path $env:ProgramFiles 'Git\usr\ssl\openssl.cnf'),
    (Join-Path $env:ProgramFiles 'Git\mingw64\etc\ssl\openssl.cnf')
)
if (Test-Path -LiteralPath $env:ProgramFiles) {
    $configCandidates += Get-ChildItem -Path $env:ProgramFiles -Filter openssl.cnf -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
}
$opensslConfig = $configCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $opensslConfig) {
    throw 'Could not locate openssl.cnf; set OPENSSL_CONF to a valid OpenSSL configuration file.'
}

$target = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $target | Out-Null
$certificate = Join-Path $target 'tls.crt'
$key = Join-Path $target 'tls.key'

$originalOpenSslConf = $env:OPENSSL_CONF
try {
    $env:OPENSSL_CONF = $opensslConfig
    & openssl req -x509 -newkey rsa:3072 -nodes `
        -keyout $key `
        -out $certificate `
        -days $Days `
        -subj "/CN=$DnsName" `
        -addext "subjectAltName=DNS:$DnsName" `
        -addext 'basicConstraints=critical,CA:FALSE' `
        -addext 'keyUsage=critical,digitalSignature,keyEncipherment' `
        -addext 'extendedKeyUsage=serverAuth'
    if ($LASTEXITCODE -ne 0) {
        throw 'OpenSSL certificate generation failed.'
    }
}
finally {
    $env:OPENSSL_CONF = $originalOpenSslConf
}

Write-Output "Created disposable TLS certificate at $target for $DnsName."
Write-Output 'Do not use this self-signed certificate for certification or production.'
