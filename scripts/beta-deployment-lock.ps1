# One host-wide gate for mutations of the elevenid-beta Compose project.
function Get-BetaMutationMarkerPath {
    $root = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
    } else {
        '/var/tmp'
    }
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw 'A host-wide beta mutation marker location is unavailable'
    }
    return (Join-Path $root 'ElevenID-Marty-elevenid-beta-mutation.pending')
}

function Enter-BetaDeploymentLock {
    param([switch]$AllowPending)
    $name = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        'Global\ElevenID.Marty.ElevenIdBetaDeployment'
    } else {
        'ElevenID.Marty.ElevenIdBetaDeployment'
    }
    $mutex = [System.Threading.Mutex]::new($false, $name)
    $owned = $false
    try {
        if (-not $mutex.WaitOne(0)) {
            throw 'Another elevenid-beta deployment or restore is active'
        }
        $owned = $true
        if (-not $AllowPending -and (Test-Path -LiteralPath (Get-BetaMutationMarkerPath))) {
            throw 'A prior elevenid-beta mutation is pending; inspect and restore beta before deploying'
        }
    }
    catch [System.Threading.AbandonedMutexException] {
        # An abandoned owner may have left a partial maintenance window.
        $mutex.ReleaseMutex()
        $mutex.Dispose()
        throw 'A previous elevenid-beta mutation ended unexpectedly; inspect beta state before retrying'
    }
    catch {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
        throw
    }
    return $mutex
}

function Start-BetaMutation {
    param([switch]$ResumePending)
    $marker = Get-BetaMutationMarkerPath
    if (Test-Path -LiteralPath $marker) {
        if ($ResumePending) { return }
        throw 'A prior elevenid-beta mutation is pending; inspect and restore beta before deploying'
    }
    $stream = [System.IO.File]::Open($marker, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes(
            "elevenid-beta mutation pending since $([DateTime]::UtcNow.ToString('o'))`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Complete-BetaMutation {
    $marker = Get-BetaMutationMarkerPath
    if (-not (Test-Path -LiteralPath $marker)) {
        throw 'The elevenid-beta mutation marker disappeared during maintenance'
    }
    Remove-Item -LiteralPath $marker -ErrorAction Stop
}

function Exit-BetaDeploymentLock {
    param([Parameter(Mandatory = $true)][System.Threading.Mutex]$Lock)
    try {
        $Lock.ReleaseMutex()
    }
    finally {
        $Lock.Dispose()
    }
}
