# Canvas runner backing storage

The Canvas source build requires 80 GiB free on the physical Windows volume
containing Docker Desktop's WSL data disk, in addition to the existing Linux
workspace-space check. WSL reports a virtual disk's logical free space; that
number alone does not establish room for the file to grow.

`register-canvas-oss-runner.ps1` queries `Get-Volume -FilePath` for the data disk
before runner discovery and again before requesting a registration token.
Missing, ambiguous or insufficient capacity fails before registration. The
helper only reads file metadata and volume counters; it never deletes data,
resizes a disk, changes Docker settings or restarts services.

The default is `%LOCALAPPDATA%\Docker\wsl\disk\docker_data.vhdx`. If the disk was
moved, pass `-DockerDesktopDataDiskPath` with the actual location shown in Docker
Desktop **Settings > Resources > Advanced**. This is a trusted operator input;
it must identify Docker Desktop's real data disk, not an unrelated VHDX. It is
not a production demo attestation or proof that WSL integration is configured.

Do not substitute a large logical Linux free-space value for physical capacity,
or delete unowned volumes to make the check pass. Enable supported WSL
integration separately and verify the runner reaches beta's actual daemon,
network and tunnel before admitting a job. No production demo succeeds merely
because either host check passes.

References: [Docker data location and WSL integration](https://docs.docker.com/desktop/features/wsl/),
[Docker WSL data file](https://docs.docker.com/desktop/settings-and-maintenance/backup-and-restore/),
[Windows volume lookup by file path](https://learn.microsoft.com/en-us/powershell/module/storage/get-volume).
