# Resolve persisted state from actual owned containers, never inferred names.
function Protect-BetaStateBackupDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Beta backup requires a real directory'
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.SetOwner($owner)
        foreach ($sid in @($owner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
                [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl',
                'ContainerInherit, ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
        if (-not (Get-Acl -LiteralPath $Path).AreAccessRulesProtected) { throw 'Backup ACL is not private' }
    }
    else {
        & chmod 700 -- $Path
        if ($LASTEXITCODE -ne 0) { throw 'Could not protect beta backup directory' }
    }
}

function Get-BetaStateVolumePlan {
    $definitions = @(
        @('postgres', 'postgres_data', '/var/lib/postgresql/data'),
        @('redis', 'redis_data', '/data'),
        @('applicant', 'applicant_data', '/app/data'),
        @('openbao', 'openbao_data', '/bao/data')
    )
    foreach ($definition in $definitions) {
        $service, $logical, $destination = $definition
        $ids = @(& docker ps -a --no-trunc --filter 'label=com.docker.compose.project=elevenid-beta' `
            --filter "label=com.docker.compose.service=$service" --format '{{.ID}}')
        if ($LASTEXITCODE -ne 0 -or $ids.Count -ne 1 -or $ids[0] -cnotmatch '^[0-9a-f]{64}$') {
            throw "Expected one owned beta state container: $service"
        }
        $raw = & docker inspect $ids[0]
        if ($LASTEXITCODE -ne 0) { throw "Cannot inspect beta state container: $service" }
        $containers = @($raw | ConvertFrom-Json)
        if ($containers.Count -ne 1) { throw "Ambiguous beta state container: $service" }
        $container = $containers[0]
        if ($container.Id -cne $ids[0] -or
            $container.Config.Labels.'com.docker.compose.project' -cne 'elevenid-beta' -or
            $container.Config.Labels.'com.docker.compose.service' -cne $service) {
            throw "Beta state container ownership changed: $service"
        }
        $mounts = @($container.Mounts | Where-Object { $_.Destination -ceq $destination })
        if ($mounts.Count -ne 1 -or $mounts[0].Type -cne 'volume' -or -not $mounts[0].RW -or
            $mounts[0].Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]+$') {
            throw "Expected one writable named beta state volume: $service"
        }
        $name = $mounts[0].Name
        $raw = & docker volume inspect $name
        if ($LASTEXITCODE -ne 0) { throw "Required beta volume is absent: $name" }
        $volumes = @($raw | ConvertFrom-Json)
        if ($volumes.Count -ne 1 -or $volumes[0].Name -cne $name -or
            $volumes[0].Labels.'com.docker.compose.project' -cne 'elevenid-beta' -or
            $volumes[0].Labels.'com.docker.compose.volume' -cne $logical -or -not $volumes[0].CreatedAt) {
            throw "Refusing an unowned or ambiguous beta state volume: $name"
        }
        $attachments = @(& docker ps -a --no-trunc --filter "volume=$name" --format '{{.ID}}')
        if ($LASTEXITCODE -ne 0 -or $container.Id -cnotin $attachments) {
            throw "Beta state volume is shared with another container: $name"
        }
        foreach ($attachment in @($attachments | Where-Object { $_ -cne $container.Id })) {
            $raw = & docker inspect $attachment
            if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect additional beta volume attachment' }
            $owners = @($raw | ConvertFrom-Json)
            if ($owners.Count -ne 1 -or $service -cne 'openbao' -or
                $owners[0].Config.Labels.'com.docker.compose.project' -cne 'elevenid-beta' -or
                $owners[0].Config.Labels.'com.docker.compose.service' -cnotin @('openbao-init', 'openbao-tls-init') -or
                $owners[0].State.Status -cne 'exited' -or $owners[0].State.ExitCode -ne 0) {
                throw "Beta state volume is shared with an unapproved container: $name"
            }
        }
        [pscustomobject][ordered]@{
            service = $service
            logical_name = $logical
            destination = $destination
            container_id = $container.Id
            volume_name = $name
            volume_created_at = $volumes[0].CreatedAt
        }
    }
}

function Assert-BetaStateVolumePlan {
    param([Parameter(Mandatory = $true)][object[]]$Expected, [switch]$SameContainers)
    $current = @(Get-BetaStateVolumePlan)
    if ($Expected.Count -ne $current.Count) { throw 'Beta state volume coverage changed' }
    foreach ($record in $current) {
        $matches = @($Expected | Where-Object { $_.logical_name -ceq $record.logical_name })
        if ($matches.Count -ne 1) { throw 'Beta state volume binding is absent or duplicated' }
        $keys = @('service', 'logical_name', 'destination', 'volume_name', 'volume_created_at')
        if ($SameContainers) { $keys += 'container_id' }
        foreach ($key in $keys) {
            if ($matches[0].$key -cne $record.$key) { throw "Beta state volume binding changed: $($record.logical_name)" }
        }
    }
}

function ConvertTo-BetaStateVolumeOverride {
    param([Parameter(Mandatory = $true)][object[]]$Plan)
    $volumes = [ordered]@{}
    foreach ($record in $Plan) {
        if ($volumes.Contains($record.logical_name)) { throw 'Duplicate beta volume override' }
        $volumes[$record.logical_name] = [ordered]@{ name = $record.volume_name; external = $true }
    }
    return ([ordered]@{ volumes = $volumes } | ConvertTo-Json -Depth 5)
}

# Change only the exact applicant named volume after the coordinated stop and
# byte-identical quiesced backup. A changed store is preserved for recovery.
function Set-BetaApplicantNonrootState {
    param(
        [Parameter(Mandatory = $true)][object[]]$Expected,
        [Parameter(Mandatory = $true)][string]$BackupFile,
        [Parameter(Mandatory = $true)][string]$HelperImage
    )
    Assert-BetaStateVolumePlan -Expected $Expected -SameContainers
    $owned = @($Expected | Where-Object { $_.service -ceq 'applicant' -and $_.logical_name -ceq 'applicant_data' })
    if ($owned.Count -ne 1 -or $owned[0].destination -cne '/app/data') {
        throw 'Applicant state ownership is ambiguous'
    }
    $raw = & docker inspect $owned[0].container_id
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect stopped applicant' }
    $container = @(($raw -join [Environment]::NewLine) | ConvertFrom-Json)
    if ($container.Count -ne 1 -or $container[0].Id -cne $owned[0].container_id -or
        $container[0].State.Status -cne 'exited' -or $container[0].State.ExitCode -ne 0) {
        throw 'Applicant did not finish a clean maintenance stop'
    }
    if (-not (Test-Path -LiteralPath $BackupFile -PathType Leaf)) {
        throw 'Quiesced applicant backup is absent'
    }
    $backupItem = Get-Item -LiteralPath $BackupFile
    if (($backupItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $backupItem.Length -eq 0) {
        throw 'Quiesced applicant backup is not an ordinary nonempty file'
    }
    $digest = (Get-FileHash -LiteralPath $BackupFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($digest -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid applicant backup digest' }
    $script = @'
set -eu
test -d /data && test ! -L /data
test -f /data/applicant_store.json && test ! -L /data/applicant_store.json
test "$(find /data -mindepth 1 -maxdepth 1 | wc -l)" -eq 1
case "$(stat -c '%u:%g' /data)" in 0:0|10001:10001) ;; *) exit 41;; esac
case "$(stat -c '%u:%g' /data/applicant_store.json)" in 0:0|10001:10001) ;; *) exit 42;; esac
case "$(stat -c '%a' /data)" in 700|750|755|770) ;; *) exit 43;; esac
case "$(stat -c '%a' /data/applicant_store.json)" in 600|640|644|660) ;; *) exit 44;; esac
test "$(sha256sum /data/applicant_store.json | cut -d ' ' -f 1)" = "$EXPECTED_SHA256"
chown 10001:10001 /data /data/applicant_store.json
chmod 0700 /data
chmod 0660 /data/applicant_store.json
test "$(stat -c '%u:%g:%a' /data)" = "10001:10001:700"
test "$(stat -c '%u:%g:%a' /data/applicant_store.json)" = "10001:10001:660"
test "$(sha256sum /data/applicant_store.json | cut -d ' ' -f 1)" = "$EXPECTED_SHA256"
sync
'@
    & docker run --rm --network none --env "EXPECTED_SHA256=$digest" --mount "type=volume,src=$($owned[0].volume_name),dst=/data" $HelperImage sh -lc $script
    if ($LASTEXITCODE -ne 0) {
        throw 'Exact applicant state ownership migration failed; preserve backup and stopped service'
    }
    Assert-BetaStateVolumePlan -Expected $Expected -SameContainers
}
