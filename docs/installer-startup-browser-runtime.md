# Isolated browser runtime for signed startup observations

The installed startup profile uses a browser on the qualification controller to
visit the configured public IP endpoint. The AWS guest runs the signed installer
and its retained operator; it does not need Node, Chromium, QEMU, or a browser
package manager. The controller needs direct network access to the configured IP
and canonical DNS origins.

Use the same exact harness checkout authorized by the candidate grant. The
controller verifies the browser runner, runtime policy, and complete file
manifest against that harness source before using them. A runtime descriptor
supplied by a caller does not authorize a different browser.

## Pinned runtime

The Linux x64 runtime is defined by
`scripts/installer_browser_runtime_policy.py` and
`scripts/installer_browser_runtime_manifest.json`.

| Component | Exact version | Source of the pin |
| --- | --- | --- |
| Node | 24.22.1 | Official release archive, checked against the release SHASUMS256 file |
| Playwright core | 1.62.1 | The existing test lockfile's npm SHA-512 integrity and the exact package archive |
| Chromium | 151.0.7922.34, Playwright revision 1234 | The verified package's browser registry and Google's exact Chrome for Testing archive |

The manifest contains 416 files and 40 directories, totaling 547,326,437 extracted
bytes. It includes the browser's supporting resources and the complete
Playwright package, along with Node and its license. It is authenticated by the
code-bound manifest digest:

```text
ba70f33e77e6139e1ae52d81c2839a887456a1ca7a4dae1852c8fe45956ff4ba
```

The reviewed source URLs are recorded in the policy. Relevant upstream records
are the [Node release checksums](https://nodejs.org/dist/v24.22.1/SHASUMS256.txt),
the [Playwright npm package](https://registry.npmjs.org/playwright-core/-/playwright-core-1.62.1.tgz),
and the [Chrome for Testing archive](https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.34/linux64/chrome-linux64.zip).
Browser versions must match their Playwright release; see the
[upstream browser documentation](https://playwright.dev/docs/browsers).

## Prepare one private controller runtime

Run these commands as the ordinary controller account from the exact authorized
harness checkout. Python 3.12 and curl are preparation prerequisites. The
commands use a new private directory and fetch only the three pinned public
archives. The installer independently verifies each archive's exact size and
digest before creating the runtime; it runs no npm or archive lifecycle scripts.

```bash
set -euo pipefail
umask 077
marty_browser_parent="$(mktemp -d "$HOME/marty-installer-browser.XXXXXXXX")"
mkdir -m 700 "$marty_browser_parent/archives"

curl --fail --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 20 --max-time 180 --max-filesize 100000000 \
  https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz \
  --output "$marty_browser_parent/archives/node.tar.xz"
curl --fail --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 20 --max-time 180 --max-filesize 16000000 \
  https://registry.npmjs.org/playwright-core/-/playwright-core-1.62.1.tgz \
  --output "$marty_browser_parent/archives/playwright.tgz"
curl --fail --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 20 --max-time 180 --max-filesize 600000000 \
  https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.34/linux64/chrome-linux64.zip \
  --output "$marty_browser_parent/archives/chromium.zip"

python3 scripts/installer_browser_runtime.py install \
  --runtime-root "$marty_browser_parent/runtime" \
  --node-archive "$marty_browser_parent/archives/node.tar.xz" \
  --playwright-archive "$marty_browser_parent/archives/playwright.tgz" \
  --chromium-archive "$marty_browser_parent/archives/chromium.zip"
python3 scripts/installer_browser_runtime.py check \
  --runtime-root "$marty_browser_parent/runtime"
```

Keep the printed runtime path with the controller's qualification inputs. An
existing runtime destination is not adopted or overwritten. A failed extraction
remains an incomplete private preparation; use a new directory after correcting
the cause. Existing customer files are not removed by this installer.

The runtime has this fixed layout:

| Purpose | Relative path |
| --- | --- |
| Node executable | `node/bin/node` |
| Browser executable | `chrome-linux64/chrome` |
| Playwright package | `playwright-core/` |

Directories are owned by the controller account with mode `0700`; files have
their manifest-selected `0444` or `0555` mode. Admission refuses root or set-ID
execution, symlinks, hard links, extra or missing entries, changed contents,
incorrect ownership or mode, and path replacement. The admission context retains
the file and directory descriptors and checks their identities and contents
again after the browser process ends.

## Connect it to the startup profile

Select `execute=true` and `execution_result=startup-observation` in the installer
acceptance workflow. This result requires the signed v2 hosting input to specify
production ACME and a public IP entry origin, without staging trust. The
ordinary incomplete-checkpoint workflow remains the default.

Supply `--browser-runtime "$marty_browser_parent/runtime"` to the existing
controller acceptance-runner invocation, together with its normal signed grant,
exact source/run/attempt, SSH, target, and retained installation arguments. The
runner derives the two origins and certificate identity from authenticated
native observations. There are no browser URL, alternate executable, proxy,
saved-login-state, or trust-bypass flags.

The fixed browser runner uses Chromium's sandbox and a clean nonpersistent
context. Its host must have the normal shared-library and sandbox prerequisites
for this Chromium build. The runtime preparation command does not install host
packages or change kernel security settings.

Each attempt has a separate Linux process owner. It stops and reaps detached
browser descendants after launcher exit, timeout, cancellation, or controller
death, and returns evidence only after the kernel confirms that no owned child
remains. Process discovery requires a matching Linux PID namespace and readable
process identities; it supports kernels without the optional procfs `children`
file. A task that the kernel cannot stop and reap produces a cleanup-pending
failure while its isolated owner remains responsible. That result cannot pass
the startup profile.

Initial ACME issuance may return a known pending order before the application
and user-systemd lifecycle are installed. In browser mode, the controller may
continue that exact retained order through the fixed operator command while the
original signed grant and workflow invocation are active. It observes native
retry times and stops after its bounded wait or an uncertain outcome. It does
not retry the original installation. Explicit customer continuation remains a
separate retained local operation, as described in
[the signed acceptance guide](installer-signed-rootless-acceptance.md).

The five startup cases require actual artifact verification, isolated native
installation, fresh runtime checks, a rendered IP landing page with working
assets and normal public TLS trust, and real sign-in and Console navigation to
canonical DNS. Native observations before and after the browser run must retain
the same authority, runtime, configuration, generation, and certificate.

## What the result establishes

A successful controller run returns `installer-startup-observation.json` through
the original authenticated transport. The workflow admits that payload while
its exact invocation is active, then signs and archives the distinct startup
artifact. A final consumer additionally requires that exact invocation to have
completed successfully and verifies the returned signature and provenance.

Startup observation keeps the installation in `Provisioning` and records
`installation_ready=false`. It cannot satisfy the separate functional/recovery,
root-retirement, load, release-admission, or channel-promotion gates. Runtime
installation, a local data-page browser smoke test, and fixture tests are
component checks; the installed IP-page result must come from the actual signed
candidate and the configured public endpoint.
