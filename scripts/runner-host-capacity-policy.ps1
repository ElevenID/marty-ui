# Read-only host prerequisite; this never deletes data or changes a virtual disk.
function Get-CanvasDockerBackingCapacity {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DataDiskPath)

    $disk = Get-Item -LiteralPath $DataDiskPath -ErrorAction Stop
    if ($disk.PSIsContainer -or $disk.Extension -ine '.vhdx' -or $disk.Length -le 0) {
        throw 'DockerDesktopDataDiskPath must identify the existing Docker Desktop WSL data VHDX from Settings > Resources > Advanced'
    }
    # Query the volume containing the actual file, not a drive inferred from cwd.
    # WSL statvfs reports the virtual disk's logical capacity, not Windows backing space.
    $volumes = @(Get-Volume -FilePath $disk.FullName -ErrorAction Stop)
    if ($volumes.Count -ne 1 -or $null -eq $volumes[0].SizeRemaining -or
        $volumes[0].SizeRemaining -is [bool] -or $volumes[0].SizeRemaining -is [string]) {
        throw 'Cannot establish physical free space for the Docker Desktop data disk'
    }
    $available = [decimal]$volumes[0].SizeRemaining
    $minimum = [decimal](80GB)
    if ($available -lt $minimum) {
        throw ('Canvas source build requires at least 80 GiB free on the Windows volume backing Docker Desktop; found {0:N1} GiB. Logical WSL capacity does not satisfy this prerequisite.' -f ($available / 1GB))
    }
    [PSCustomObject]@{
        scope = 'WINDOWS_DOCKER_BACKING_CAPACITY_ONLY'
        production_demo_ready = $false
        required_free_bytes = $minimum
        physical_free_bytes = $available
    }
}
