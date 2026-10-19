param(
  [Parameter(Mandatory=$true)][int]$BrowserProcessId,
  [Parameter(Mandatory=$true)][string]$BrowserExecutable,
  [Parameter(Mandatory=$true)][long]$SpawnedAtMilliseconds
)
$ErrorActionPreference = 'Stop'
# Inspect only process identity; never enumerate command lines or environments.
$ownedProcess = Get-Process -Id $BrowserProcessId -ErrorAction SilentlyContinue
if ($null -eq $ownedProcess) { exit 0 }
$started = ([DateTimeOffset]$ownedProcess.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds()
if ($ownedProcess.ProcessName -ne 'chrome' -or
    $ownedProcess.Path -ne $BrowserExecutable -or
    $started -lt $SpawnedAtMilliseconds -or
    $started -gt ($SpawnedAtMilliseconds + 10000)) {
  throw 'Owned browser identity mismatch; refusing termination'
}
# A fresh unique user-data-dir creates a dedicated browser root. Terminate only
# that validated root and its descendants, never Chrome by name or all sessions.
& "$env:SystemRoot\System32\taskkill.exe" /PID $BrowserProcessId /T /F *> $null
if ($LASTEXITCODE -ne 0 -and (Get-Process -Id $BrowserProcessId -ErrorAction SilentlyContinue)) {
  throw 'Owned browser tree termination did not complete'
}
