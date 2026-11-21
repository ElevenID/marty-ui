#!/usr/bin/env python3
"""Run the reviewed split-web diagnostics on an already prepared disposable host.

This runner creates no AWS resources, signs or publishes nothing, and never
changes either source checkout's tracked files. It is deliberately separate
from the two exact source commits being qualified.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid


MARTY_SHA = "b1095e8c86389929cf1a93c4ed04d9eb784f3a6d"
MARTY_TREE = "f450e69dd64fc5e6bad0226bc3c1d4ec8d7d5635"
WEBSITE_SHA = "14ec367ea74048f40a709d7c2b4415181dc454e5"
WEBSITE_TREE = "819242ebcd0de1d196f5325dec12f2506c54e016"
NGINX_FIXTURE = "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606"
CHROME = "/usr/bin/google-chrome"
SCHEMA = "marty.split-web-host-qualification/v1"
KEEP_ENV = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(filename: Path, value: object, *, replace: bool = False) -> None:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    temporary = filename.with_name(filename.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("xb") as destination:
        os.chmod(temporary, 0o600)
        destination.write(raw)
    if not replace:
        require(not os.path.lexists(filename), "Evidence destination already exists")
    os.replace(temporary, filename)


def fingerprint(filename: Path) -> dict:
    metadata = filename.lstat()
    require(stat.S_ISREG(metadata.st_mode), "Evidence must be an ordinary file")
    digest = hashlib.sha256()
    with filename.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return {"bytes": metadata.st_size, "sha256": digest.hexdigest()}


def ordinary_path(value: str, *, exists: bool) -> Path:
    result = Path(value)
    require(result.is_absolute() and str(result) == str(result.resolve()),
            "Use normalized absolute paths without symlinks")
    require(not any(ord(character) < 32 for character in value), "Control characters in path")
    if exists:
        require(result.is_dir(), "Source directory is unavailable")
    else:
        require(not os.path.lexists(result) and result.parent.is_dir(),
                "Evidence root must be a new directory under an existing parent")
    return result


def paths(options) -> tuple[Path, Path, Path]:
    marty = ordinary_path(options.marty_root, exists=True)
    website = ordinary_path(options.website_root, exists=True)
    evidence = ordinary_path(options.evidence_root, exists=False)
    roots = (marty, website, evidence, Path(__file__).resolve().parents[1])
    for index, left in enumerate(roots):
        for right in roots[index + 1:]:
            require(left != right and left not in right.parents and right not in left.parents,
                    "Runner, source checkouts, and evidence must be separate directories")
    return marty, website, evidence


def environment(options, evidence: Path) -> dict[str, str]:
    result = {name: os.environ[name] for name in KEEP_ENV if name in os.environ}
    runtime = "/run/user/" + str(os.getuid())
    result.update({
        "XDG_RUNTIME_DIR": runtime,
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + runtime + "/bus",
        "DOCKER_HOST": "unix://" + options.docker_socket,
        "DOCKER_CONFIG": str(evidence / "docker-config"),
        "DOCKER_BUILDKIT": "1", "BUILDX_BUILDER": "default",
        "PYTHONDONTWRITEBYTECODE": "1", "PUPPETEER_SKIP_DOWNLOAD": "true",
        "CHROME_PATH": CHROME, "CI": "true",
    })
    return result


def capture(argv: list[str], env: dict, *, cwd: Path | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=30, check=False)
    require(result.returncode == 0, "Read-only prerequisite failed: " + Path(argv[0]).name)
    require(len(result.stdout) <= 4 * 1024 * 1024, "Prerequisite output exceeded its bound")
    return result.stdout.strip()


def container_ids(docker: list[str], env: dict) -> list[str]:
    identifiers = capture(docker + ["container", "ls", "--all", "--quiet", "--no-trunc"], env).splitlines()
    require(all(re.fullmatch(r"[a-f0-9]{64}", value) for value in identifiers), "Unexpected Docker container identity")
    return sorted(identifiers)


def source_identity(root: Path, sha: str, tree: str, env: dict) -> dict:
    git = shutil.which("git", path=env.get("PATH"))
    require(git is not None, "Git is required")
    command = [git, "-C", str(root)]
    require(capture(command + ["rev-parse", "--show-toplevel"], env) == str(root),
            "Source path is not its Git checkout root")
    require(capture(command + ["rev-parse", "HEAD"], env) == sha, "Wrong source commit: " + str(root))
    require(capture(command + ["rev-parse", "HEAD^{tree}"], env) == tree, "Wrong source tree")
    require(capture(command + ["status", "--porcelain=v1", "--untracked-files=all"], env) == "",
            "Source checkout has tracked changes or untracked source files: " + str(root))
    return {"root": str(root), "commit": sha, "tree": tree, "clean": True}


def preflight(options, roots) -> tuple[dict, dict, dict]:
    marty, website, evidence = roots
    require(sys.platform == "linux" and platform.machine() == "x86_64", "Linux x86_64 is required")
    require(os.getuid() != 0 and os.getuid() == os.geteuid(), "Run as the prepared non-root Docker user")
    require(sys.version_info >= (3, 10), "Python 3.10 or later is required")
    env = environment(options, evidence)
    require(Path(env.get("HOME", "")).is_absolute() and Path(env["HOME"]).is_dir(), "An ordinary HOME is required")
    tools = {}
    for name in ("node", "bun", "npm", "docker", "systemd-run", "systemctl", "loginctl", "env"):
        executable = shutil.which(name, path=env.get("PATH"))
        require(executable is not None, "Missing prerequisite: " + name)
        tools[name] = executable
    tools["python"] = sys.executable
    node = capture([tools["node"], "--version"], env)
    require(re.fullmatch(r"v24\.\d+\.\d+", node) is not None, "Node 24 is required")
    bun = capture([tools["bun"], "--version"], env)
    require(bun == "1.4.4", "Bun must be exactly 1.4.4")
    systemd = capture([tools["systemd-run"], "--version"], env).splitlines()[0]
    require(int(systemd.split()[1]) >= 254, "systemd 254+ is required for literal command arguments")
    chrome = capture([CHROME, "--version"], env)
    source = {
        "marty": source_identity(marty, MARTY_SHA, MARTY_TREE, env),
        "website": source_identity(website, WEBSITE_SHA, WEBSITE_TREE, env),
    }
    for root, forbidden in ((marty, ("ui/node_modules",)),
                            (website, ("node_modules", ".qualification", "ui/dist-website"))):
        for relative in forbidden:
            require(not os.path.lexists(root / relative), "Use a fresh dedicated checkout: " + str(root / relative))
        for directory in (root, root / "ui"):
            for candidate in directory.glob(".env*"):
                require(candidate.name.endswith(".example"), "Existing dotenv file is not an admitted test input")
    runtime = Path(env["XDG_RUNTIME_DIR"])
    socket = Path(options.docker_socket)
    require(socket == runtime / "docker.sock", "Select this user's /run/user/UID/docker.sock")
    require(runtime.is_dir() and not runtime.is_symlink(), "Rootless runtime directory is unavailable")
    metadata = runtime.stat()
    require(metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077,
            "Rootless runtime directory must be private and owned by the current user")
    metadata = socket.lstat()
    require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.getuid() and not metadata.st_mode & 0o007,
            "Rootless Docker socket ownership or permissions differ")
    require(capture([tools["systemctl"], "--user", "is-active", "docker.service"], env) == "active",
            "Rootless Docker user service is not active")
    require(capture([tools["systemctl"], "--user", "is-enabled", "docker.service"], env) == "enabled",
            "Rootless Docker user service is not enabled")
    require(capture([tools["loginctl"], "show-user", str(os.getuid()), "--property=Linger", "--value"], env) == "yes",
            "Prepared user must have linger enabled; the runner does not provision it")
    docker = [tools["docker"], "--host", env["DOCKER_HOST"]]
    info = json.loads(capture(docker + ["info", "--format", "{{json .}}"], env))
    require("name=rootless" in info.get("SecurityOptions", []), "Docker daemon is not rootless")
    require(info.get("OSType") == "linux" and info.get("Architecture") in ("x86_64", "amd64"),
            "Docker must target Linux amd64")
    require(str(info.get("CgroupVersion")) == "2" and info.get("CgroupDriver") == "systemd",
            "Rootless Docker requires cgroup v2 and systemd delegation")
    initial_containers = container_ids(docker, env)
    require(capture(docker + ["image", "ls", "--quiet", "elevenid-website:" + WEBSITE_SHA], env) == "",
            "The exact website output tag already exists; do not overwrite another run's image")
    memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    report = {
        "sources": source,
        "tools": {"node": node, "bun": bun, "python": platform.python_version(),
                  "chrome": chrome, "systemd": systemd, "docker": info.get("ServerVersion")},
        "host": {"kernel": platform.release(), "architecture": platform.machine(), "uid": os.getuid(),
                 "memory_total_kib": int(memory["MemTotal"].split()[0]),
                 "memory_available_kib": int(memory["MemAvailable"].split()[0]),
                 "source_filesystem_free_bytes": shutil.disk_usage(evidence.parent).free,
                 "operator_supplied_instance_id": options.aws_instance_id},
        "docker": {"endpoint": env["DOCKER_HOST"], "engine_id": info.get("ID"),
                   "rootless": True, "cgroup_version": info["CgroupVersion"], "cgroup_driver": info["CgroupDriver"],
                   "memory_bytes": info.get("MemTotal"), "cpu_count": info.get("NCPU"),
                   "data_filesystem_free_bytes": shutil.disk_usage(info["DockerRootDir"]).free,
                   "initial_containers": initial_containers},
        "full_stack_installer_capacity_qualified": False,
    }
    return report, tools, env


def stages(roots, tools: dict) -> list[dict]:
    marty, website, evidence = roots
    app = evidence / "application"
    node, bun, python, docker = (tools.get(name, name) for name in ("node", "bun", "python", "docker"))
    commands = []

    def add(name, cwd, argv, *, seconds=900, env=None, stdout=None):
        commands.append({"name": name, "cwd": str(cwd), "argv": [str(value) for value in argv],
                         "maximum_seconds": seconds, "environment": env or {},
                         "stdout_artifact": str(stdout) if stdout else None})

    def runtime(name, context, report, *, browser=None, release=False):
        argv = [node, "ui/scripts/application-runtime-context.mjs", "--context", app / context,
                "--report", app / report, "--check-container"]
        if browser:
            argv += ["--browser-startup", "--browser-report", app / browser, "--browser-channel", "chrome"]
        if release:
            argv += ["--build-release-image"]
        add(name, marty, argv, seconds=660)

    add("application-full", marty, [node, "ui/scripts/application-source-closure.mjs", "--fresh-install",
        "--package-manager", "bun", "--runtime-context", app / "application-runtime-context",
        "--report", app / "application-source-closure.json"], seconds=3600)
    runtime("application-full-nginx", "application-runtime-context", "application-runtime.json")
    add("application-dependency-audit", marty, [python, "scripts/ci/audit-application-dependencies.py"], seconds=180)
    add("application-profile", marty, [node, "ui/scripts/application-source-closure.mjs", "--fresh-install",
        "--package-manager", "bun", "--dependency-profile", "application", "--baseline-report",
        app / "application-source-closure.json", "--runtime-context", app / "application-profile-runtime-context",
        "--report", app / "application-profile-source-closure.json"], seconds=3600)
    runtime("application-profile-nginx", "application-profile-runtime-context", "application-profile-runtime.json")
    common = ["--archive", app / "application-source-package.zip", "--manifest", app / "application-source-origin.json",
              "--baseline-report", app / "application-profile-source-closure.json"]
    add("application-export", marty, [node, "ui/scripts/export-application-source.mjs", *common,
        "--report", app / "application-source-package.json"])
    add("application-consumer", marty, [node, "ui/scripts/application-package-consumer.mjs", *common,
        "--producer-report", app / "application-source-package.json", "--report", app / "application-package-consumer.json",
        "--runtime-context", app / "application-package-runtime-context"], seconds=3600)
    runtime("application-consumer-nginx", "application-package-runtime-context", "application-package-runtime.json")
    add("application-manifest-copy", marty, [python, "-c",
        "from pathlib import Path; import sys; source=Path(sys.argv[1]); target=Path(sys.argv[2]); "
        "assert source.is_file() and not source.is_symlink(); "
        "target.open('xb').write(source.read_bytes()); target.chmod(0o600)",
        app / "application-package-runtime-context/application-runtime-context.json", app / "application-runtime-context.json"])
    add("application-release-inputs", marty, [node, "scripts/application_release_inputs.mjs", "--source-sha", MARTY_SHA,
        "--assets", app, "--context", app / "application-package-runtime-context"], stdout=app / "application-release-inputs.json")
    add("application-release-plan", marty, [python, "scripts/application_release.py", "plan", "--source-sha", MARTY_SHA,
        "--assets", app, "--context", app / "application-package-runtime-context", "--output", app / "application-build-plan.json"])

    def install(name, cwd):
        state = evidence / name
        add(name, cwd, [bun, "install", "--frozen-lockfile", "--linker=hoisted", "--backend=copyfile", "--no-env-file",
            "--config=" + str(evidence / "bunfig.toml"), "--cache-dir=" + str(state / "cache"),
            "--registry=https://registry.npmjs.org"], seconds=660,
            env={"HOME": str(state / "home"), "XDG_CONFIG_HOME": str(state / "home"),
                 "BUN_INSTALL_CACHE_DIR": str(state / "cache"), "BUN_CONFIG_REGISTRY": "https://registry.npmjs.org"})

    install("application-browser-tooling", marty / "ui")
    add("application-tooling-inspection", marty, [node, "ui/scripts/application-dependency-install.mjs",
        "--inspect-installed", marty / "ui", "full", "bun"], stdout=app / "application-browser-tooling.json")
    runtime("application-profile-browser", "application-profile-runtime-context", "application-browser-runtime.json",
            browser="application-browser-startup.json")
    runtime("application-consumer-browser", "application-package-runtime-context", "application-package-browser-runtime.json",
            browser="application-package-browser-startup.json")
    runtime("application-release-image-browser", "application-package-runtime-context", "application-image-check.json",
            browser="application-image-browser.json", release=True)

    site_env = {"MARTY_WEBSITE_SOURCE_SHA": WEBSITE_SHA, "MARTY_PRODUCTION_PAGES": "public",
                "HOME": str(evidence / "website-dependencies/home"),
                "XDG_CONFIG_HOME": str(evidence / "website-dependencies/home")}
    add("website-package-manager", website, [node, "scripts/verify-package-manager.mjs"], env=site_env)
    install("website-dependencies", website)
    add("website-tests", website, [bun, "run", "--no-env-file", "test"], seconds=1800, env=site_env)
    add("website-nginx-fixture-pull", website, [docker, "pull", "--platform=linux/amd64", NGINX_FIXTURE], seconds=660)
    add("website-nginx-tests", website, [bun, "run", "--no-env-file", "test:nginx"], env=site_env)
    add("website-development-build", website, [bun, "run", "--no-env-file", "build:website"],
        env={**site_env, "MARTY_WEBSITE_SOURCE_SHA": "development", "MARTY_WEBSITE_ALLOW_DEVELOPMENT": "true"})
    for name, script in (("website-development-bundle", "verify-standalone-bundle.mjs"),
                         ("website-development-assets", "verify-public-assets.mjs"),
                         ("website-rendered-handoff", "qualify-rendered-website.mjs")):
        add(name, website, [node, "scripts/" + script], env=site_env)
    add("website-production-prerender", website, [bun, "run", "--no-env-file", "build:website:production"],
        seconds=7200, env=site_env)
    for name, script in (("website-production-assets", "verify-public-assets.mjs"),
                         ("website-image", "build-website-image.mjs"),
                         ("website-image-nginx", "qualify-website-nginx.mjs")):
        add(name, website, [node, "scripts/" + script], env=site_env)
    add("website-finalize", website, [node, "scripts/website-qualification.mjs", "finalize"], env=site_env)
    add("website-release-plan", website, [node, "scripts/website-release-contract.mjs", "plan"],
        env=site_env, stdout=evidence / "website-build-plan.json")
    return commands


def systemd_command(stage: dict, unit: str, env: dict, tools: dict, seconds: int) -> list[str]:
    return [tools["systemd-run"], "--user", "--wait", "--pipe", "--collect", "--quiet",
            "--expand-environment=no", "--service-type=exec", "--unit=" + unit,
            "--description=Split web diagnostic " + stage["name"], "--property=UMask=0022",
            "--working-directory=" + stage["cwd"], "--property=KillMode=control-group",
            "--property=TimeoutStopSec=30s", "--property=RuntimeMaxSec=" + str(seconds) + "s",
            tools["env"], "-i", *[key + "=" + value for key, value in sorted(env.items())], *stage["argv"]]


def run(options, roots, initial: dict, tools: dict, env: dict) -> dict:
    marty, website, evidence = roots
    require(options.deadline_utc is not None, "run requires the operator's bounded UTC deadline")
    deadline = datetime.strptime(options.deadline_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    require(300 <= deadline - time.time() <= 8 * 3600, "Deadline must be 5 minutes to 8 hours ahead")
    evidence.mkdir(mode=0o700)
    for name in ("application", "logs", "temporary", "docker-config"):
        (evidence / name).mkdir(mode=0o700)
    for name in ("application-browser-tooling", "website-dependencies"):
        for relative in (name, name + "/home", name + "/cache"):
            (evidence / relative).mkdir(mode=0o700)
    (evidence / "bunfig.toml").write_text("")
    os.chmod(evidence / "bunfig.toml", 0o600)
    env = {**env, "TMPDIR": str(evidence / "temporary"), "TMP": str(evidence / "temporary"),
           "TEMP": str(evidence / "temporary")}
    plan = stages(roots, tools)
    report = {"schema": SCHEMA, "status": "running", "started_at": now(), "deadline_utc": options.deadline_utc,
              "runner": fingerprint(Path(__file__).resolve()), "initial": initial, "steps": [],
              "scope": {"unsigned_diagnostic_only": True, "website_browser_sandbox_enabled": False,
                        "website_browser_sandbox_reason": "The exact reviewed website scripts pass --no-sandbox",
                        "application_browser_sandbox_required": True, "production_deployed": False,
                        "registry_published": False, "signed_release_issued": False, "source_deleted": False,
                        "oidc_journey_qualified": False, "full_stack_recovery_qualified": False}}
    write_json(evidence / "plan.json", plan)
    write_json(evidence / "qualification.json", report)
    run_id = uuid.uuid4().hex[:12]
    try:
        for number, stage in enumerate(plan, start=1):
            seconds = min(stage["maximum_seconds"], int(deadline - time.time()) - 90)
            require(seconds >= 60, "Execution deadline reached; no new stage was started")
            unit = "marty-splitweb-" + run_id + "-" + str(number) + ".service"
            stdout = Path(stage["stdout_artifact"]) if stage["stdout_artifact"] else evidence / "logs" / (stage["name"] + ".stdout.log")
            stderr = evidence / "logs" / (stage["name"] + ".stderr.log")
            step = {"name": stage["name"], "unit": unit, "started_at": now(), "status": "running",
                    "maximum_seconds": seconds, "stdout": str(stdout.relative_to(evidence)),
                    "stderr": str(stderr.relative_to(evidence))}
            report["steps"].append(step)
            write_json(evidence / "qualification.json", report, replace=True)
            print(f"[{number}/{len(plan)}] {stage['name']}", flush=True)
            command_env = {**env, **stage["environment"]}
            command = systemd_command(stage, unit, command_env, tools, seconds)
            started = time.monotonic()
            with stdout.open("xb") as out, stderr.open("xb") as err:
                os.chmod(stdout, 0o600)
                os.chmod(stderr, 0o600)
                try:
                    result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                            timeout=seconds + 75, check=False)
                    step["exit_code"] = result.returncode
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    # Stop only the named service created for this step. This is
                    # an outer emergency deadline, never successful gate cleanup.
                    subprocess.run([tools["systemctl"], "--user", "stop", unit], env=env,
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=45, check=False)
                    step["exit_code"] = None
                    step["cleanup_unproven"] = True
                    raise ValueError("Stage interrupted or its outer deadline expired") from None
            step.update(status="passed" if result.returncode == 0 else "failed", finished_at=now(),
                        elapsed_seconds=round(time.monotonic() - started, 3),
                        stdout_digest=fingerprint(stdout), stderr_digest=fingerprint(stderr))
            write_json(evidence / "qualification.json", report, replace=True)
            require(result.returncode == 0, "Qualification stage failed: " + stage["name"])
        report["final_sources"] = {
            "marty": source_identity(marty, MARTY_SHA, MARTY_TREE, env),
            "website": source_identity(website, WEBSITE_SHA, WEBSITE_TREE, env),
        }
        remaining = container_ids([tools["docker"], "--host", env["DOCKER_HOST"]], env)
        require(remaining == initial["docker"]["initial_containers"],
                "Container identities changed; retain evidence and inspect ownership without pruning")
        destination = evidence / "website"
        destination.mkdir(mode=0o700)
        for source in sorted((website / ".qualification").iterdir()):
            require(source.suffix == ".json" and source.is_file() and not source.is_symlink(),
                    "Unexpected website qualification output")
            with (destination / source.name).open("xb") as target:
                target.write(source.read_bytes())
            os.chmod(destination / source.name, 0o600)
        report["artifacts"] = {
            str(filename.relative_to(evidence)): fingerprint(filename)
            for directory in (evidence / "application", destination)
            for filename in sorted(directory.iterdir()) if filename.is_file()
        }
        report["artifacts"]["website-build-plan.json"] = fingerprint(evidence / "website-build-plan.json")
        report.update(status="passed", finished_at=now(), diagnostic_containers_remaining=False,
                      existing_container_identities_preserved=True,
                      website_local_image_retained=True)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="failed", finished_at=now(), failure=str(error), cleanup_unproven=True)
        if report["steps"] and report["steps"][-1]["status"] == "running":
            report["steps"][-1].update(status="failed", finished_at=now())
    finally:
        write_json(evidence / "qualification.json", report, replace=True)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "preflight", "run"))
    parser.add_argument("--marty-root", required=True)
    parser.add_argument("--website-root", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--docker-socket", required=True)
    parser.add_argument("--deadline-utc", help="Existing authorized stop window, e.g. 2026-11-21T18:00:00Z")
    parser.add_argument("--aws-instance-id", help="Operator-supplied label; not independently authenticated by this runner")
    options = parser.parse_args()
    try:
        require(options.aws_instance_id is None or re.fullmatch(r"i-[a-f0-9]{8,17}", options.aws_instance_id) is not None,
                "Invalid EC2 instance label")
        require(Path(options.docker_socket).is_absolute(), "Docker socket must be absolute")
        roots = paths(options)
        if options.mode == "plan":
            print(json.dumps({"schema": SCHEMA, "status": "plan-only", "marty_sha": MARTY_SHA,
                              "website_sha": WEBSITE_SHA, "steps": stages(roots, {})}, indent=2))
            return 0
        initial, tools, env = preflight(options, roots)
        if options.mode == "preflight":
            print(json.dumps({"schema": SCHEMA, "status": "prerequisites-passed", **initial}, indent=2))
            return 0
        report = run(options, roots, initial, tools, env)
        print(json.dumps({"status": report["status"], "report": str(roots[2] / "qualification.json"),
                          "failure": report.get("failure")}, indent=2))
        return 0 if report["status"] == "passed" else 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "refused", "reason": str(error)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
