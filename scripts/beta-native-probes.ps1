# Expected startup failures are observations, not deployment exceptions.
function Invoke-BetaDockerReadinessProbe {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $output = @(& docker @Arguments 2>&1)
    return [pscustomobject]@{ exit_code = $LASTEXITCODE; output = @($output | ForEach-Object { [string]$_ }) }
}

function Read-BetaContainerPublicCertificate {
    param([Parameter(Mandatory = $true)][string]$Container,
          [Parameter(Mandatory = $true)][string]$Path)
    $probe = Invoke-BetaDockerReadinessProbe -Arguments @('exec', $Container, 'cat', $Path)
    if ($probe.exit_code -ne 0) { throw 'Cannot read rehearsal public CA' }
    $certificate = ($probe.output -join "`n") + "`n"
    if ($certificate -cnotmatch '\A-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END CERTIFICATE-----\n\z') {
        throw 'Rehearsal CA must contain exactly one public certificate'
    }
    return $certificate
}
