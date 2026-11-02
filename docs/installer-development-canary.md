# Installer development canary

This procedure tests the installer capability checks and rootless ownership canary
on a disposable Linux amd64 host. It uses unsigned development builds and does
not qualify a release, install the complete application, or grant installation
readiness. Use disposable data and preserve every failed attempt.

See the [canary implementation](../rust/crates/deployment-catalog/src/installer_rootless_storage_canary.rs)
and [development tests](../rust/crates/deployment-catalog/src/installer_rootless_storage_canary_development_tests.rs)
for the exact contracts exercised here.

The development harness is a Rust test behind `#[cfg(test)]`, ignored by default.
There is no canary-only installer CLI flag. It calls `qualify_candidate` directly;
the signed `--candidate-test` installer path described in
[Installer bootstrap](installer-bootstrap.md) continues into application
provisioning after a successful canary and is a separate operation.

## Capability checks and creation evidence

`HostConfig.CapAdd` must contain exactly `CHOWN` and `DAC_OVERRIDE`, in either
order. Each name may have one optional `CAP_` prefix. Mixed representations are
accepted; duplicates, extra capabilities, unknown names, multiple prefixes,
wrong case, and malformed values are refused. The other container identity,
mount, environment, network, and security checks remain mandatory. A refusal
names the field and expected contract without echoing untrusted inspect values.

After Docker returns a valid exact container ID, `create_container` must persist
and read back a private, exclusive creation record before the first container
inspection. Each role has its own evidence file:

- `rootless-canary-transition-created-unvalidated.json`
- `rootless-canary-restore-created-unvalidated.json`

These records bind the intent hash, role, name, and ID, with `validated`,
`cleanup_authorized`, and `installation_ready` all false. Successful inspection
still requires a separate validated receipt. A provisional record cannot
authorize start, adoption, recovery, or removal. A write/readback failure stops
before inspection; existing evidence is never overwritten.

Docker creation and evidence persistence are not an atomic transaction. A lost
Docker response or interruption before persistence can leave a helper without
this record. Preserve uncertain state; a missing receipt does not prove that
nothing was created.

## Audited development build and focused tests

The recorded run used an isolated installer-only workspace and Rust 1.95.0 in an
existing rootless builder, pinned to
`docker.io/library/rust@sha256:e98196986adced5602f6e21c54babdbf2a8700400c7a78868324a3630e0c5d15`.
The commands below run inside that builder, whose native toolchain provides
`x86_64-unknown-linux-musl`. The separately reviewed workspace retained the
required dependency features and original source revisions; the canonical
repository manifests and lockfile were preserved.

Replace the two path placeholders with existing dedicated development
directories. No builder creation or host package installation is implied here.

```sh
marty_dev_workspace=/absolute/path/to/audited-installer-workspace
marty_dev_cache=/absolute/path/to/private-build-cache
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CC_x86_64_unknown_linux_musl=cc
export CARGO_HOME="$marty_dev_cache/cargo"
export CARGO_TARGET_DIR="$marty_dev_cache/target"

cargo metadata --manifest-path "$marty_dev_workspace/build-src/rust/Cargo.toml" \
  --format-version 1 --filter-platform x86_64-unknown-linux-musl
```

Audit the resolved metadata and development lock before building. This metadata
step may resolve the isolated lock; subsequent build commands use `--locked`.
The recorded strict audit found 246 registry packages with zero version or
checksum changes, seven local packages, and 185 copied source/fixture files.
This is an **isolated audited development lock**, not the canonical release/CI
workspace or evidence of a reproducible signed release build. Record all source,
dependency, manifest, and lockfile inputs. Preserve the host's absolute source
path when building in a container because tests use `CARGO_MANIFEST_DIR`.

After the audit, the recorded formatting and musl build commands were:

```sh
cargo fmt --manifest-path "$marty_dev_workspace/build-src/rust/Cargo.toml" \
  -p marty-deployment-catalog -- --check

cargo test --locked --manifest-path "$marty_dev_workspace/build-src/rust/Cargo.toml" \
  -p marty-deployment-catalog --lib --target x86_64-unknown-linux-musl \
  --no-run --message-format=json-render-diagnostics

cargo build --locked --manifest-path "$marty_dev_workspace/build-src/rust/Cargo.toml" \
  -p marty-deployment-catalog --bin marty-deploy \
  --target x86_64-unknown-linux-musl --message-format=json-render-diagnostics
```

Use the exact test executable reported by Cargo. Run the focused tests on the
host as its ordinary non-root user under no-new-privileges:

```sh
/usr/bin/setpriv --no-new-privs /absolute/path/to/the/compiled-test-binary \
  installer_rootless --test-threads=1
```

The capability matrix includes all eight accepted order/prefix combinations,
malformed and unknown values, diagnostic redaction using synthetic secret
markers, and rejection of unrelated contract drift. Four development tests use
an executable fake Docker to exercise actual creation-record persistence,
inspection failures, exclusive-write and locked-readback failures, and refusal
of provisional or incomplete recovery chains. They do not contact a daemon or
change filesystem ownership. The live test remains ignored in this focused run.

## One explicitly selected live test

First pass the focused tests. Use the separately built static `marty-deploy`
helper from the musl build above. Preserve its unsigned `unknown:unreleased` development
identity; never inject a released tag or signed source identity. Independently
verify that embedded identity and record the helper's SHA-256. The harness binds
and copies the exact helper bytes and checks its AMD64 ELF format and absence of
`PT_INTERP`; it explicitly records that it has not observed or authenticated the
embedded build identity. Do not substitute the host test executable for the
in-container helper.

Set and review these inputs locally; do not publish private paths or daemon
identifiers in a public result:

| Environment variable | Required value |
| --- | --- |
| `MARTY_DEV_CANARY_OPT_IN` | `I_ACCEPT_UNSIGNED_DEVELOPMENT_CANARY` |
| `MARTY_DEV_CANARY_PARENT` | Dedicated absolute, canonical, owned mode-0700 directory outside every existing installation |
| `MARTY_DEV_CANARY_DOCKER` | Absolute canonical trusted Docker CLI executable |
| `MARTY_DEV_CANARY_STATIC_HELPER` | Owned ordinary mode-0700 static AMD64 helper in a private mode-0700 directory |
| `MARTY_DEV_CANARY_HELPER_SHA256` | Independently verified SHA-256 of that helper |
| `MARTY_DEV_CANARY_SERVICES_IMAGE` | Already-cached `ghcr.io/elevenid/marty-ui-oss/services@sha256:…` immutable reference |
| `MARTY_DEV_CANARY_ENGINE_ID` | Independently reviewed identity of the existing user-owned rootless daemon |

Run as an ordinary non-root user under no-new-privileges, selecting only the exact
ignored test. Replace the executable placeholder with Cargo's reported path:

```sh
setpriv --no-new-privs -- /absolute/path/to/the/compiled-test-binary \
  --ignored --exact \
  installer_rootless_storage_canary::development_tests::development_rootless_canary_transition_restore \
  --nocapture --test-threads=1
```

Actual process and Docker preflight checks remain enforced: matching non-root
user/group identities, zero effective/permitted/ambient capabilities, the user's
fixed `/run/user/<uid>/docker.sock`, rootless Docker, Compose, cgroup v2, systemd
cgroups, and memory-limit support.

The harness creates a fresh persistent development scope and rejects a parent
inside an existing installation. Synthetic journal fields are explicitly marked
as development data. It runs one actual create/inspect/ownership-transition/
restore/host-traversal sequence. The production canary **re-pulls the same pinned
services digest**, even after the cached-image check; allow for that network
request. There is no no-pull bypass.

On success, the existing canary removes only its two fully validated helper IDs
through its durable removal-intent path. Host evidence remains. Failure triggers
no harness cleanup, ownership repair, recovery, or retry. Preserve the printed
scope, remaining helpers, and private outcome/evidence records. The harness
checks the existing container IDs and cached image ID after the attempt.

Keep the existing bounded Docker waits. Do not add a blanket kill timeout or
intentionally interrupt ownership transition; a timed-out Docker client does
not establish that its daemon-side helper stopped. Confirm sufficient host
lifetime before starting. Never use global container, image, or volume pruning.

Recovery is a separate reviewed operation. The host test executable has a
different digest from the retained static helper and must not impersonate it.
Any later recovery must satisfy the original identity, inventory, operator,
container, layout, and durable-chain checks. Provisional records alone provide
no authority. This procedure neither resumes the original failed installation
nor establishes that recovery from this development scope is admissible.

## Recorded unsigned development results

The following results were recorded on 2026-10-30 on Ubuntu 24.04 Linux amd64,
with two vCPUs, 8 GiB RAM, rootless Docker 29.9.2, Compose 5.6.1, and cgroup v2
with the systemd driver. They apply to this scoped development build and test
window.

| Check | Observed result |
| --- | --- |
| Metadata, strict development-lock audit, formatting | Passed; no registry version/checksum updates |
| Static musl test executable and operator builds | Both exited 0 |
| Focused tests under the ordinary host user and no-new-privileges | 15 passed, 0 failed, 1 ignored |
| Explicitly selected live canary | Passed, exit 0; 6.032 seconds recorded by the harness; 7.698 seconds for the outer invocation |
| Ownership restoration | Original UID/GID, mode `0700`, inode and device restored; production marker verification passed |
| Canary helpers | Two created and validated; transition and restore completed; both removed through the actual validated canary path |
| Original failed scope | All 178 retained files unchanged; original helper remained created and never started |
| Live resource window, eight samples | Peak sampled host memory used 0.766521 GiB; minimum available 6.827 GiB; no observed OOM or swap activity |
| Filesystem growth | 35,901,440 bytes, mostly the retained development operator |
| Complete application installation and journey | Not exercised by this procedure |
| Signed release qualification and admission | Not established by these results |

The static helper independently reported `unknown:unreleased`. Its SHA-256 was
`7e74dcb23412982e856e80a174ed81d979e16dd9c26807e9189d0258817c5b27`.
The memory observations cover the live canary window; they do not describe the
build peak or the application's operating envelope.

Record the reviewed commit, build inputs and hashes, host capacity, Docker and
Compose versions, test exit status, elapsed time, resource observations, and the
first failing stage. Publish a redacted summary, not raw logs or private evidence.
A passing development canary establishes only the observations made on that
host; it does not establish a supported application memory minimum, complete
application readiness, or signed release acceptance. A patched source build can
exercise this harness before publication. A subsequent signed installer trial
still requires the exact authenticated release inputs and its separate gates;
see the [disposable qualification runbook](selfhost-disposable-qualification-runbook.md).
