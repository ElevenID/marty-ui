# Optional disposable rootless VM qualification

The existing SSH acceptance path can target an independently prepared AWS host.
It does not require a nested VM. The QEMU path is an additional way to create a
disposable guest with retained image, disk, process and SSH evidence.

The rootless QEMU path requires an explicit resource-profile selection. Its
records distinguish configured VM size from measurements inside the guest.
Neither a successful seed operation, a running VM nor a passing host preflight
establishes application readiness or release acceptance.

## Profiles and versioned records

| Selection | Guest runtime | Nominal RAM | Admission measurements | Scope |
| --- | --- | --- | --- | --- |
| Omitted, historical v1 | System Docker | 4,096 MiB | Existing engineering or legacy qualification policy | Original interpretation retained |
| `rootless-startup-8gib` | Docker user service, UID 1001 | 8,192 MiB | Guest and Docker each at least 7 GiB; Docker filesystem at least 20 GiB free | Startup qualification profile |
| `rootless-functional-recovery-8gib` | Docker user service, UID 1001 | 8,192 MiB | Same measured resource floors | Separately named functional and recovery qualification profile |

Both rootless profiles require at least 10 GiB available on the QEMU controller
before launching: the 8 GiB guest allocation plus 2 GiB controller headroom.
This is a launch admission check, not a memory reservation or a product capacity
claim. The rootless guest's filesystem must still have 20 GiB free after its
bootstrap packages are installed; a nominal 20 GiB disk cannot establish that
fact. The existing creation policy and disk identity checks remain in force.

The same explicit `resource_profile` must be passed to seed preparation, launch,
host preflight, nonce consumption and retained consumption verification. A
different profile, an omitted selection for rootless records or a legacy record
relabeled as v2 is refused. Startup and functional profiles cannot be exchanged
after the seed is retained. Existing engineering calls without this parameter
retain their v1 schemas and original generated seed bytes.

The new chain uses seed v2, launch v2 and guest-readiness/pre-dispatch/process-check
v2. It retains the existing exact PID record, all nine provisioning record hashes,
the held disk descriptor, controller boot identity, process start ticks and pinned
SSH keys. The signed controller target still contains exactly `guest_id`,
`disk_id`, `engine_id` and `installation_id`.

Runtime and resource facts are separate fields in the authenticated VM evidence:

- `runtime`: rootless profile, exact UID, `unix:///run/user/1001/docker.sock`,
  socket device and inode.
- `rootless_resource_controls`: cgroup version 2, systemd cgroup driver and an
  observed enabled memory controller.
- `resource_profile`, `guest_memory_bytes`, `docker_memory_bytes` and
  `docker_data_filesystem` containing the filesystem device and measured free
  bytes.

Repeated pre-dispatch observations retain the same runtime, socket, engine,
filesystem and memory identities. Free bytes may change; every required
measurement still has to meet its floor. A rootless user service must be active
and enabled, linger must be enabled, and the system Docker service and socket
must be inactive. The runtime directory must be private and owned by UID 1001;
the observed socket must belong to that user and exclude access by others.

## Closed disposable guest bootstrap

Only an explicitly selected, newly created disposable seed renders rootless
setup commands. The controller does not run those commands or modify an existing
SSH/AWS host. The seed selects the `installer` user at UID 1001 with a private
home, without Docker group membership or passwordless sudo.

The legacy Ubuntu package pins are retained. The rootless policy additionally
pins RootlessKit, UID mapping helpers, slirp4netns, fuse-overlayfs, the systemd
D-Bus user session and AppArmor. The Ubuntu 24.04 Docker package's file list does
not include the rootless setup scripts, while Ubuntu's documented packaged helper
path applies to newer releases. The seed therefore carries the two exact Moby
Docker Engine 29.1.3 scripts with their SHA-256 hashes, license and notice. See
[`scripts/installer_candidate_vm_assets/moby-docker-v29.1.3/README.md`](../scripts/installer_candidate_vm_assets/moby-docker-v29.1.3/README.md).

Generated guest prerequisites verify the expected account, exact package
versions, at least 65,536 nonoverlapping subordinate UIDs and GIDs, the memory
controller, the distribution's RootlessKit AppArmor profile, and the exact helper
bytes. The guest then disables its disposable system Docker service, enables the
user manager and linger, and invokes the upstream setup helper as the nonroot
user. Its user service receives explicit cgroup delegation. The upstream helper
also performs its own namespace and systemd checks.

Missing prerequisites, unavailable pinned packages or incompatible namespace
policy stop the generated bootstrap and prevent a clean guest-readiness result.
There is no `--force`, `--skip-iptables`, global security disabling, runtime
download-and-execute step or automatic adoption of an existing daemon. Retained
partial seed/launch evidence follows the original recovery rules; it does not
authorize another launch or guest initialization.

Official references used for this policy:

- [Docker rootless prerequisites](https://docs.docker.com/engine/security/rootless/)
  and [systemd user-service persistence](https://docs.docker.com/engine/security/rootless/tips/).
- [Ubuntu Docker administration and rootless packaging](https://ubuntu.com/server/docs/how-to/containers/docker-for-system-admins/)
  and the [Ubuntu 24.04 Docker package file list](https://packages.ubuntu.com/noble-updates/amd64/docker.io/filelist).
- [Ubuntu RootlessKit](https://packages.ubuntu.com/noble/rootlesskit),
  [UID mapping helpers](https://packages.ubuntu.com/noble-updates/uidmap),
  [slirp4netns](https://packages.ubuntu.com/noble/slirp4netns) and
  [fuse-overlayfs](https://packages.ubuntu.com/noble/fuse-overlayfs).

## Admission and observations

Host preflight continues to authenticate the signed candidate inputs and exact
source-bound host probe, reobserve the same live VM before and after that probe,
retain the raw observation, and consume its nonce only under the held controller
lease. V2 preflight and consumption records pin the selected profile and exact
rootless runtime. Consumption verification rechecks the original provisioning
chain and raw measurement bindings. No preflight or consumption record claims
that application startup, browser trust or the functional recovery journey has
passed.

The older standalone `installer_candidate_qemu_observe.py` gains an explicit v3
rootless diagnostic mode. It still reports `capacity_qualified`,
`clean_host_qualified` and `dispatch_authorized` as false and cannot substitute
for the root-controlled provisioning chain or a signed acceptance grant.

## Verification boundary for this change

Focused tests cover legacy seed byte preservation, 4 GiB versus 8 GiB launch
arguments and controller headroom, source-asset substitution, user-service and
socket drift, cgroup/resource refusal, all nine provisioning records, distinct
resource profiles, unchanged four-field targets, and preflight through retained
nonce verification. These are rendering, local filesystem and simulated SSH
tests; they do not establish that a deployed guest or application has started.

The existing root-owned VM CI lane supplies `qemu-img`, `cloud-init` and
`cloud-localds`. The new seed tests exercise actual schema validation, seed media
creation and readback there without starting a VM. The development session did
not install these tools, launch a guest, execute the generated guest bootstrap,
contact a live CA, alter an AWS host or obtain release qualification. A real
disposable guest and the selected installed-application journey remain required
acceptance work.
