# Test the exact receipt writer without executing the operator's beta path.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$operator = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'scripts/start-passport-beta-db-maintenance.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $operator, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Beta operator has a parse error' }
$functions = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Write-DurableJson'
}, $true))
if ($functions.Count -ne 1) { throw 'Atomic receipt writer is absent' }
. ([scriptblock]::Create($functions[0].Extent.Text))
$path = Join-Path $env:TEMP (
    'marty-beta-maintenance-receipt-' + [Guid]::NewGuid().ToString('N') + '.json')
$orphan = $path + '.stage-abandoned'
try {
    [IO.File]::WriteAllText($orphan, 'partial')
    Write-DurableJson -Path $path -Json '{"complete":true}'
    if ([IO.File]::ReadAllText($path) -cne "{`"complete`":true}`n") {
        throw 'Receipt bytes were not published completely'
    }
    $refused = $false
    try { Write-DurableJson -Path $path -Json '{"complete":false}' }
    catch [IO.IOException] { $refused = $true }
    if (-not $refused -or
        [IO.File]::ReadAllText($path) -cne "{`"complete`":true}`n") {
        throw 'Receipt retry replaced existing evidence'
    }
}
finally {
    if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
    if ([IO.File]::Exists($orphan)) { [IO.File]::Delete($orphan) }
}
Write-Output 'atomic maintenance receipt rehearsal passed'
