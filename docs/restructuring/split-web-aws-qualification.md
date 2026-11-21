# Split website qualification on the existing AWS development host

This runner closes the real browser and container checks that the local executor
could not perform. It runs only diagnostics against two exact source revisions:

| Repository | Commit | Tree |
| --- | --- | --- |
| `ElevenID/marty-ui` | `b1095e8c86389929cf1a93c4ed04d9eb784f3a6d` | `f450e69dd64fc5e6bad0226bc3c1d4ec8d7d5635` |
| `ElevenID/website` | `14ec367ea74048f40a709d7c2b4415181dc454e5` | `819242ebcd0de1d196f5325dec12f2506c54e016` |

The runner lives in a separate checkout. It neither provisions EC2 nor changes
the selected instance, account plan, Docker daemon, K3s installation, public
ingress or production deployment. It does not invoke GitHub Actions, sign or
publish a release, push an image, or remove source code.

## Prepare the existing host

Retain the existing automatic-stop deadline and the account's authorized cost
boundary. An EC2 instance size or a passing script is not evidence that the
account qualifies for free usage. Account eligibility and remaining credits
must be observed separately by the operator.

Run as the prepared non-root user, with its active and enabled rootless Docker
user service, linger, private `/run/user/UID` directory and owned
`/run/user/UID/docker.sock`. The daemon must report rootless mode, cgroup v2 and
the systemd cgroup driver. Existing containers are allowed: the runner records
their complete IDs and requires the same set after qualification. It never
stops them, restarts the daemon, changes their configuration, or performs a
Docker prune. Every existing test uses its own random loopback-only container
name. A pre-existing image at the exact website output tag is refused so that
another run's tag cannot be overwritten.

The host needs Linux x86_64, Python 3.10+, Git, Node 24, Bun **1.4.4**, npm only
for the retained dependency scanner, and a regular Chrome installation at
`/usr/bin/google-chrome`. Node **24.22.1** is the website CI reference version;
the report records the actual Node version. The ordinary Chrome channel must
support its sandbox without disabling AppArmor or supplying `--no-sandbox` to
the application check. `systemd-run` must be version 254 or later. The host also
needs normal outbound access to the pinned npm/GitHub release inputs and the
digest-pinned public nginx images.

Use fresh, separate source worktrees or checkouts for the exact commits above.
Do not reuse a live development mount or another run's installed dependencies.
Create those checkouts with an explicit `umask 022`, inside a private `0700`
parent directory. Preflight checks every tracked ordinary file against its exact
Git mode: `100644` requires `0644`, and `100755` requires `0755`. Git's ordinary
clean-status check does not detect permission differences such as `0664` or
`0600`; the source exporter intentionally rejects them. A failed run's source
and evidence must be preserved, with fresh correctly created checkouts used for
the next attempt. The runner never changes file modes to make admission pass.
The runner rejects dirty source, untracked source files, existing application
or website `node_modules`, existing website output/evidence and unreviewed dotenv
files. The tracked Marty baseline inputs `.env.native` and `ui/.env.test` are
admitted only with their exact reviewed SHA-256 hashes, after the clean source
commit/tree check. Other actual dotenv files, including ignored `.env` and
`.env.local`, remain refused. Checked-in `.env*.example` files remain allowed. Place the evidence
directory outside all checkouts; it must not exist before execution.

Use a short evidence path under a private parent, such as `/home/marty/q3/e`.
The complete temporary base `<evidence-root>/temporary` must be at most **60
UTF-8 bytes**. Chrome adds its own random directory and `SingletonSocket` path;
longer bases can exceed Linux's Unix-socket pathname limit even when ordinary
files fit. Non-ASCII characters can consume several bytes each. `plan`,
`preflight`, and `run` reject an overlong base before starting diagnostics or
creating evidence. The runner records the selected base and byte count in its
preflight report. Keep each failed attempt and choose a fresh short path for
the next attempt; do not relax the application browser sandbox.

The frontend checks do not require a healthy application backend. The application
browser gate intentionally observes the static runtime's real unavailable
session state. The website handoff test uses its existing isolated fixture.
Repairing unrelated shared backend services is not part of this qualification.

The runner records host and Docker memory and free disk, but makes no installer
capacity claim. The separate `rootless-startup-8gib` and
`rootless-functional-recovery-8gib` profiles in
[the installer runbook](../selfhost-disposable-rootless-vm.md) apply to full-stack
installer acceptance and require their own signed inputs and admission chain.

## Inspect and run

The following paths and deadline are examples. Use the prepared user's actual
paths and the existing authorized stop window. The runner must be in its own
checkout; the two source directories must retain the pinned commits above.

```sh
export PATH=/home/marty/development/toolchains/node-v24.22.1-linux-x64/bin:/home/marty/development/toolchains/bun-1.4.4:$PATH
export XDG_RUNTIME_DIR=/run/user/1001
export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus
export DOCKER_HOST=unix:///run/user/1001/docker.sock

python3 /home/marty/development/split-web-runner/scripts/qualify_split_web_aws.py plan \
  --marty-root /home/marty/development/split-web-marty-b1095e8c \
  --website-root /home/marty/development/split-web-website-14ec367 \
  --evidence-root /home/marty/q3/e \
  --docker-socket /run/user/1001/docker.sock
```

Replace `plan` with `preflight` to perform read-only source, tool and rootless
host checks. This does not create the evidence directory or start a test
container. Then invoke the same command with `run` and an explicit UTC deadline:

```sh
python3 /home/marty/development/split-web-runner/scripts/qualify_split_web_aws.py run \
  --marty-root /home/marty/development/split-web-marty-b1095e8c \
  --website-root /home/marty/development/split-web-website-14ec367 \
  --evidence-root /home/marty/q3/e \
  --docker-socket /run/user/1001/docker.sock \
  --deadline-utc 2026-11-21T08:50:00Z
```

Choose a deadline before the host's automatic stop, leaving time to retain and
inspect evidence. The runner accepts a deadline between five minutes and eight
hours ahead, starts no new stage with less than a minute available, and reserves
90 seconds for stopping and reporting. This application deadline does not
replace the host stop timer. An optional `--aws-instance-id` is only an operator
label; the runner does not claim to have authenticated it through AWS.

Stages run sequentially. Each uses a uniquely named transient systemd user
service, a bounded runtime and control-group cleanup. No shell interprets the
command arguments. AWS credentials, GitHub credentials, Node injection settings,
arbitrary Bun configuration and application environment variables are not
forwarded. Each Bun install uses an empty home/config, a new cache and the frozen
reviewed lock. The main checkout's diagnostic Puppeteer installation is a
separate frozen Bun install after full/profile/restored-source qualification;
it does not rebuild the application contexts under browser test.

The existing scripts retain their own normal process and container cleanup.
The systemd deadline is an outer emergency bound. A failed or interrupted step
stops the sequence and cannot acquire successful qualification. Uncertain
cleanup is recorded explicitly; do not retry automatically or remove shared
resources to hide the failure. Preserve the evidence and identify the exact
owned resource before any subsequent cleanup.

## Gates and evidence

| Stage group | Actual observation |
| --- | --- |
| Full and reduced application | Independent frozen Bun installs, dependency/lifecycle/SDK checks, selected tests, build/resource checks and exact output parity |
| Portable source | Source export, independent restore/install/build/test, runtime context parity and Node/Python release-plan validation |
| Application nginx | Actual container build and HTTP probes for full, reduced and restored contexts |
| Application Chrome | Real sandboxed `/login` and `/console` startup, unavailable-session Retry, exact SDK WASM execution and blocked-WASM recovery for reduced/restored contexts |
| Application production recipe | Actual production Dockerfile build plus the same browser gate |
| Website fixtures | Standalone tests, digest-pinned nginx policy tests, real rendered development pages and isolated application handoff |
| Website production | Complete public-route prerender, public assets, pinned-image build, exact-image HTTP checks, aggregate qualification and release-plan validation |

The website scripts at the exact pinned revision already pass `--no-sandbox`.
Their fresh profiles, disabled background networking and loopback-only host
resolution remain in place, but this is **not sandboxed website browser
qualification**. The runner records that limit explicitly and does not silently
modify the tested source. The separate application gate continues to require
sandboxed Chrome. Neither handoff fixture nor static startup qualifies a live
OIDC sign-in, successful authenticated user journey, or full-stack recovery.

`qualification.json` records source trees, tool versions, host observations,
every stage's status, elapsed time, log hashes and final report/archive hashes.
`plan.json` retains exact command arguments. Application reports and the source
ZIP are under `application/`; copied website receipts are under `website/`.
The actual nginx/runtime contexts and website output remain available in their
owned directories. The final website image is retained locally for inspection.
Nothing is pushed to a registry. Successful completion requires unchanged
source commits and tracked bytes, preserved pre-existing container identities,
and no remaining diagnostic containers.

These artifacts are unsigned host diagnostics. They do not impersonate a GitHub
run, satisfy signed production intake by renaming files, or establish permission
to switch routing. The existing signed release/composition and host activation
contracts remain the next stage after reviewing the real results.

Systemd process-boundary behavior follows the upstream
[systemd-run](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html)
and [systemd.kill](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html)
documentation. The existing application observation contract is documented in
[Application browser startup boundary](application-browser-boundary.md).
