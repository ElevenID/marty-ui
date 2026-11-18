[CmdletBinding()]
param(
    [ValidateSet('Deploy', 'Rollback')]
    [string]$Mode = 'Deploy'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ProductionSnapshot {
    $ids = @(& docker ps -a --filter 'label=com.docker.compose.project=marty-selfhost-prod' --format '{{.ID}}')
    if ($LASTEXITCODE -ne 0 -or $ids.Count -eq 0) {
        throw 'Production container inventory is unavailable'
    }
    $raw = & docker inspect @ids
    [object[]]$containers = ConvertFrom-Json -InputObject ($raw -join "`n")
    if ($LASTEXITCODE -ne 0 -or $containers.Count -ne $ids.Count) {
        throw 'Production container inspection is incomplete'
    }
    return @($containers | Sort-Object Id | ForEach-Object {
        $container = $_
        $networks = @($container.NetworkSettings.Networks.PSObject.Properties |
            Sort-Object Name | ForEach-Object {
                [ordered]@{
                    name = $_.Name
                    network_id = $_.Value.NetworkID
                    endpoint_id = $_.Value.EndpointID
                    ip_address = $_.Value.IPAddress
                    aliases = @($_.Value.Aliases | Sort-Object)
                }
            })
        $ports = @($container.HostConfig.PortBindings.PSObject.Properties |
            Sort-Object Name | ForEach-Object {
                [ordered]@{
                    container_port = $_.Name
                    host_bindings = @($_.Value | Sort-Object HostIp, HostPort | ForEach-Object {
                        [ordered]@{ host_ip = $_.HostIp; host_port = $_.HostPort }
                    })
                }
            })
        $mounts = @($container.Mounts | Sort-Object Destination, Name | ForEach-Object {
            [ordered]@{
                type = $_.Type
                name = if ($null -ne $_.PSObject.Properties['Name']) { $_.Name } else { $null }
                destination = $_.Destination
                read_write = $_.RW
            }
        })
        [ordered]@{
            name = $container.Name
            id = $container.Id
            image = $container.Image
            started_at = $container.State.StartedAt
            running = [bool]$container.State.Running
            exit_code = [int]$container.State.ExitCode
            health = if ($null -ne $container.State.PSObject.Properties['Health']) {
                $container.State.Health.Status
            } else { $null }
            networks = $networks
            ports = $ports
            mounts = $mounts
        }
    })
}

function Get-BetaUi {
    $ids = @(& docker ps --filter 'label=com.docker.compose.project=elevenid-beta-ui' `
        --filter 'label=com.docker.compose.service=ui-prod' --format '{{.ID}}')
    if ($LASTEXITCODE -ne 0 -or $ids.Count -ne 1) {
        throw 'Exactly one running beta UI container is required'
    }
    $raw = & docker inspect $ids[0]
    [object[]]$item = ConvertFrom-Json -InputObject ($raw -join "`n")
    if ($LASTEXITCODE -ne 0 -or $item.Count -ne 1) {
        throw 'Beta UI container inspection failed'
    }
    $container = $item[0]
    if ($container.Config.Labels.'com.docker.compose.project' -cne 'elevenid-beta-ui' -or
        $container.Config.Labels.'com.docker.compose.service' -cne 'ui-prod' -or
        $container.State.Running -ne $true -or
        $container.State.Health.Status -cne 'healthy') {
        throw 'Selected container is not the healthy beta UI'
    }
    return $container
}

$before = @(Get-ProductionSnapshot)
if ($before.Count -ne 29 -or
    @($before | Where-Object { $_.running }).Count -ne 24 -or
    @($before | Where-Object { $_.running -and $_.health -eq 'healthy' }).Count -ne 22 -or
    @($before | Where-Object { $_.running -and $_.health -and $_.health -ne 'healthy' }).Count -gt 0) {
    throw 'Production is degraded before beta demo publication'
}
$beta = Get-BetaUi
$videoId = [string]$env:ELEVENID_DEMO_VIDEO_ID
if ($videoId -cnotmatch '^[A-Za-z0-9_-]{11}$') {
    throw 'A valid YouTube video ID is required for beta demo publication'
}
$backupRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot (
    "..\tests\artifacts\passport-beta-demo-publication-backups\$($beta.Id)\$videoId")))
$publicationError = $null
try {
    & (Join-Path $PSScriptRoot 'deploy-demo-content.ps1') -Mode $Mode `
        -Container $beta.Id -BackupRoot $backupRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta demo content deployment failed'
    }
    $afterBeta = Get-BetaUi
    if ($afterBeta.Id -cne $beta.Id) {
        throw 'Beta UI container changed during demo publication'
    }
}
catch {
    $publicationError = $_
}
finally {
    $after = @(Get-ProductionSnapshot)
    if ((ConvertTo-Json -InputObject $before -Depth 8 -Compress) -cne
        (ConvertTo-Json -InputObject $after -Depth 8 -Compress)) {
        throw 'Production containers changed during beta demo publication'
    }
}
if ($null -ne $publicationError) {
    throw $publicationError
}
