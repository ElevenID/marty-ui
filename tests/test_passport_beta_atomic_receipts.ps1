# Exercise exact receipt writers without importing either operator's top-level
# mutation path. Files are confined to unique names under the system temp dir.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$operators = @(
    'scripts/start-passport-beta-db-maintenance.ps1',
    'scripts/run-passport-beta-native-db-gates.ps1'
)
foreach ($relative in $operators) {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $root $relative), [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw 'Beta operator has a parse error' }
    $functions = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Write-DurableJson'
    }, $true))
    if ($functions.Count -ne 1) { throw 'Atomic receipt writer is absent' }
    . ([scriptblock]::Create($functions[0].Extent.Text))
    $path = Join-Path $env:TEMP (
        'marty-beta-receipt-' + [Guid]::NewGuid().ToString('N') + '.json')
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
}
$bindings = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$maintenanceBase'
}, $true))
if ($bindings.Count -ne 1) {
    throw 'Native gate has no single maintenance verifier command'
}
$baseArguments = $bindings[0].Right.Extent.Text
foreach ($required in @(
    "'--cutover-snapshot'", '[string]$maintenancePlan.cutover_snapshot_path',
    "'--cutover-report'", '[string]$maintenancePlan.cutover_report_path'
)) {
    if (-not $baseArguments.Contains($required)) {
        throw 'Native gate omits a sealed maintenance readiness input'
    }
}
Write-Output 'atomic beta receipt rehearsal passed'
