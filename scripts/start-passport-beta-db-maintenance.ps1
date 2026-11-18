param(
    [Parameter(Mandatory = $true)][string]$StackManifest,
    [Parameter(Mandatory = $true)][string]$FenceReceipt,
    [Parameter(Mandatory = $true)][string]$CutoverSnapshot,
    [Parameter(Mandatory = $true)][string]$CutoverReport,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [switch]$ResumePending
)

throw 'Historical passport beta database cutover is retired; use the fresh Rust-owned deployment path'
