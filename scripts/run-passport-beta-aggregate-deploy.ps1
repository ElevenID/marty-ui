param(
    [Parameter(Mandatory = $true)][string]$StackManifest,
    [Parameter(Mandatory = $true)][string]$FenceReceipt,
    [Parameter(Mandatory = $true)][string]$MaintenanceReceipt,
    [Parameter(Mandatory = $true)][string]$NativeReceipt,
    [Parameter(Mandatory = $true)][string]$ApplicationFile,
    [Parameter(Mandatory = $true)][string]$IssuerChainFile,
    [Parameter(Mandatory = $true)][string]$IssuerCeremonyFile,
    [Parameter(Mandatory = $true)][string]$CscaSessionFile,
    [Parameter(Mandatory = $true)][string]$DscSessionFile,
    [Parameter(Mandatory = $true)][string]$FlowFile,
    [Parameter(Mandatory = $true)][string]$SessionFile,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

throw 'Historical passport beta aggregate cutover is retired; use the fresh Rust-owned deployment path'
