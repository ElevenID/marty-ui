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

$target = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $target | Out-Null
$certificate = Join-Path $target 'tls.crt'
$key = Join-Path $target 'tls.key'

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

Write-Output "Created disposable TLS certificate at $target for $DnsName."
Write-Output 'Do not use this self-signed certificate for certification or production.'
