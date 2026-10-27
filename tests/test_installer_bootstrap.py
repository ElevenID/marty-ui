"""Execute early bootstrap refusals; these are not installation/crypto proof."""
import os
import json
import re
import shutil
import subprocess
import time
import hashlib
import shlex
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install.sh"
SHELL = (r"C:\Program Files\Git\usr\bin\sh.exe" if os.name == "nt" else shutil.which("sh"))


def run(args=(), source=None):
    command = [SHELL, str(SCRIPT), *args] if source is None else [SHELL, "-s", "--", *args]
    environment = dict(os.environ)
    if os.name == "nt":
        environment["PATH"] = str(Path(SHELL).parent) + os.pathsep + environment.get("PATH", "")
    return subprocess.run(command, input=source, capture_output=True, text=True, timeout=15, env=environment)


def test_help_does_not_require_docker_or_downloads():
    result = run(["--help"])
    assert result.returncode == 0
    assert "--channel nightly|stable" in result.stdout


@pytest.mark.parametrize("args,reason", [
    (["--version"], "Missing value"),
    (["--channel", "preview"], "Channel must"),
    (["--channel", "stable", "--version", "v1.2.3"], "Choose one"),
    (["--version", "../../attacker"], "Invalid version"),
    (["--version", "v1.2.3?x=y"], "Invalid version"),
    (["--install-dir", "/one", "--install-dir", "/two"], "Repeated"),
    (["--skip-verification"], "Unknown option"),
])
def test_invalid_arguments_refused_before_host_mutation(args, reason):
    # Keep argument-policy checks independent of the test runner's actual OS.
    host = 'uname() { case "$1" in -s) echo Linux;; -m) echo x86_64;; esac; }\n'
    result = run(args, source=host + SCRIPT.read_text())
    assert result.returncode != 0
    assert reason in result.stderr


@pytest.mark.parametrize("system,machine", [
    ("Darwin", "arm64"), ("Darwin", "x86_64"), ("Linux", "aarch64"),
    ("Linux", "unknown"), ("MINGW64_NT", "x86_64"), ("FreeBSD", "amd64"),
])
def test_unsupported_platform_stops_before_dependencies_or_download(system, machine):
    setup = f'''uname() {{ case "$1" in -s) echo {shlex.quote(system)};; -m) echo {shlex.quote(machine)};; esac; }}
id() {{ echo UNEXPECTED_ID >&2; return 91; }}
grep() {{ echo UNEXPECTED_DEPENDENCY >&2; return 91; }}
docker() {{ echo UNEXPECTED_DOCKER >&2; return 91; }}
mktemp() {{ echo UNEXPECTED_STAGING >&2; return 91; }}
curl() {{ echo UNEXPECTED_DOWNLOAD >&2; return 91; }}
'''
    result = run(["--version", "v1.2.3"], source=setup + SCRIPT.read_text())
    assert result.returncode != 0
    assert f"Unsupported platform: {system}/{machine}" in result.stderr
    assert "UNEXPECTED" not in result.stdout + result.stderr


@pytest.mark.parametrize("failed_option,reason", [
    ("-s", "Cannot detect host operating system"),
    ("-m", "Cannot detect host architecture"),
])
def test_failed_platform_detection_stops_before_host_actions(failed_option, reason):
    setup = f'''uname() {{
    [ "$1" != {shlex.quote(failed_option)} ] || return 1
    case "$1" in -s) echo Linux;; -m) echo x86_64;; esac
}}
id() {{ echo UNEXPECTED_ID >&2; return 91; }}
curl() {{ echo UNEXPECTED_DOWNLOAD >&2; return 91; }}
'''
    result = run(source=setup + SCRIPT.read_text())
    assert result.returncode != 0 and reason in result.stderr
    assert "UNEXPECTED" not in result.stdout + result.stderr


@pytest.mark.parametrize("machine", ["x86_64", "amd64"])
def test_linux_adapter_selects_coherent_pinned_tools_and_payload(machine, monkeypatch):
    for key in ("platform", "operator_asset", "jq_url", "jq_sha", "gh_member"):
        monkeypatch.setenv(key, "untrusted-environment-value")
    setup = f'''uname() {{ case "$1" in -s) echo Linux;; -m) echo {machine};; esac; }}
id() {{
    printf 'PROFILE:%s\\n' "$platform" "$operator_asset" "$preflight" "$digest_adapter" \\
        "$jq_url" "$jq_sha" "$jq_size" "$cosign_url" "$cosign_sha" "$cosign_size" \\
        "$gh_url" "$gh_sha" "$gh_size" "$gh_member" >&2
    echo 0
}}
docker() {{ echo UNEXPECTED_DOCKER >&2; return 91; }}
curl() {{ echo UNEXPECTED_DOWNLOAD >&2; return 91; }}
'''
    result = run(source=setup + SCRIPT.read_text())
    # Stop at the actual regular-user check after observing the selected adapter.
    assert result.returncode != 0 and "regular Docker-enabled user" in result.stderr
    selected = [line.removeprefix("PROFILE:") for line in result.stderr.splitlines()
                if line.startswith("PROFILE:")]
    assert selected == [
        "linux/amd64", "marty-deploy-linux-amd64", "linux_preflight", "linux_digest",
        "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-amd64",
        "020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d", "2255816",
        "https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64",
        "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa", "145688404",
        "https://github.com/cli/cli/releases/download/v2.103.2/gh_2.103.2_linux_amd64.tar.gz",
        "62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8", "15031001",
        "gh_2.103.2_linux_amd64/bin/gh",
    ]
    assert "UNEXPECTED" not in result.stdout + result.stderr


def test_help_does_not_probe_platform():
    setup = 'uname() { echo UNEXPECTED_HOST_PROBE >&2; return 91; }\n'
    result = run(["--help"], source=setup + SCRIPT.read_text())
    assert result.returncode == 0
    assert "UNEXPECTED" not in result.stdout + result.stderr


@pytest.mark.skipif(shutil.which("jq") is None, reason="actual bootstrap admission JSON policy")
@pytest.mark.parametrize("platform", ["darwin/arm64", "linux/arm64", "windows/amd64"])
def test_admission_must_match_selected_platform(platform):
    source = SCRIPT.read_text()
    match = re.search(r'--arg tag "\$version" --arg platform "\$platform" \'([^\']*)\' "\$stage/admission.json"', source, re.S)
    assert match
    record = dict(schema="elevenid.installer-admission/v1", repository="ElevenID/marty-ui",
                  release_tag="v1.2.3", platform="linux/amd64", status="accepted",
                  operator_sha256="a" * 64, inventory_sha256="b" * 64)
    command = ["jq", "-e", "--arg", "tag", "v1.2.3", "--arg", "platform", "linux/amd64", match[1]]
    def check():
        return subprocess.run(command, input=json.dumps(record), text=True,
                              capture_output=True, timeout=10).returncode
    assert check() == 0
    record["platform"] = platform
    assert check() != 0


def test_truncated_script_cannot_enter_main():
    source = SCRIPT.read_text()
    definition, invocation = source.rsplit('\nmain "$@" --bootstrap-complete', 1)
    assert invocation.strip() == ""
    # A complete function definition alone is inert. An incomplete final command
    # that still parses (bare main, main with forwarded arguments) must refuse.
    for suffix in ("", "\nmain", '\nmain "$@"', '\nmain "$@" --bootstrap-comp'):
        result = run(source=definition + suffix)
        if suffix:
            assert result.returncode != 0
            assert "Incomplete bootstrap" in result.stderr or "Unknown option" in result.stderr
        else:
            assert result.returncode == 0 and not result.stdout and not result.stderr


def test_no_ambient_verifier_or_unsigned_download_execution():
    source = SCRIPT.read_text()
    assert source.index('"$(digest "$2")" = "$3"') < source.index('chmod 700 "$stage/jq"')
    assert source.index('verify "$stage/marty-deploy"') < source.index('"$stage/marty-deploy" --build-identity')
    assert "--skip-verification" not in source


@pytest.mark.parametrize("endpoint,security,reason", [
    ("ssh://example.invalid", "name=seccomp", "remote contexts are refused"),
    ("tcp://127.0.0.1:2375", "name=seccomp", "remote contexts are refused"),
    ("unix:///run/user/1000/docker.sock", "name=rootless", "Rootless Docker"),
    ("unix:///var/run/docker.sock", "name=rootless,detail=true", "Rootless Docker"),
    ("unix:///var/run/docker.sock", "name=userns", "user namespace remapping"),
    ("unix:///var/run/docker.sock", "name=userns,remapped=true", "user namespace remapping"),
])
def test_wrong_docker_target_refused_before_download(endpoint, security, reason):
    source = SCRIPT.read_text()
    # Override host observations only; execute the actual argument/preflight code.
    setup = f'''
unset DOCKER_CONTEXT DOCKER_HOST
uname() {{ case "$1" in -s) echo Linux;; -m) echo x86_64;; esac; }}
id() {{ echo 1000; }}
docker() {{
    case "$1:${{2:-}}" in
        context:inspect) echo '{endpoint}';;
        info:--format) echo '{security}';;
        *) return 0;;
    esac
}}
curl() {{ echo UNEXPECTED_DOWNLOAD >&2; return 1; }}
'''
    source = source.replace('\nmain "$@" --bootstrap-complete', setup + '\nmain "$@" --bootstrap-complete')
    result = run(source=source)
    assert result.returncode != 0 and reason in result.stderr
    assert "UNEXPECTED_DOWNLOAD" not in result.stderr


@pytest.mark.skipif(shutil.which("jq") is None, reason="requires jq for actual bootstrap JSON policy")
@pytest.mark.parametrize("field,value", [
    ("runInvocationURI", "https://github.com/ElevenID/marty-ui/actions/runs/43/attempts/1"),
    ("runInvocationURI", "https://github.com/ElevenID/marty-ui/actions/runs/42/attempts/2"),
    ("sourceRepositoryIdentifier", "999"), ("runnerEnvironment", "self-hosted"),
    ("sourceRepositoryRef", "refs/heads/feature"), ("sourceRepositoryDigest", "b" * 40),
    ("buildSignerURI", "https://github.com/attacker/repo/workflow"),
])
def test_actual_bootstrap_certificate_policy_rejects_mismatch(field, value):
    source = SCRIPT.read_text()
    match = re.search(r'--arg invocation "[^"\n]+" \'(.*?)\' "\$1.verified.json"', source, re.S)
    assert match, "bootstrap verification policy must remain exercised"
    signer = "https://github.com/ElevenID/marty-ui/.github/workflows/nightly-release.yml@refs/heads/main"
    invocation = "https://github.com/ElevenID/marty-ui/actions/runs/42/attempts/1"
    certificate = dict(issuer="https://token.actions.githubusercontent.com",
                       runnerEnvironment="github-hosted", sourceRepositoryIdentifier="1140864197",
                       sourceRepositoryURI="https://github.com/ElevenID/marty-ui",
                       sourceRepositoryDigest="a" * 40, sourceRepositoryRef="refs/heads/main",
                       buildSignerURI=signer, runInvocationURI=invocation)
    command = ["jq", "-e", "--arg", "source", "a" * 40, "--arg", "signer", signer,
               "--arg", "invocation", invocation, match[1]]
    def check():
        evidence = [{"verificationResult": {"signature": {"certificate": certificate}}}]
        return subprocess.run(command, input=json.dumps(evidence), text=True,
                              capture_output=True, timeout=10).returncode
    assert check() == 0
    certificate[field] = value
    assert check() != 0


@pytest.mark.skipif(shutil.which("jq") is None, reason="requires jq for actual bootstrap JSON policy")
@pytest.mark.parametrize("field,value", [
    ("channel", "stable"), ("generation", 0), ("generation", True),
    ("repository", "attacker/marty-ui"), ("admission_sha256", "bad"),
    ("expires_at", 1), ("issued_at", 9999999999), ("expires_at", 9999999999),
])
def test_actual_bootstrap_channel_policy_rejects_stale_or_wrong_metadata(field, value):
    source = SCRIPT.read_text()
    match = re.search(r'--arg channel "\$channel" \'([^\']*)\' "\$stage/channel.json"', source, re.S)
    assert match
    record = dict(schema="elevenid.installer-channel/v1", repository="ElevenID/marty-ui",
                  channel="nightly", generation=1, admission_sha256="a" * 64,
                  issued_at=int(time.time()) - 60, expires_at=int(time.time()) + 300)
    command = ["jq", "-e", "--arg", "channel", "nightly", match[1]]
    def check():
        return subprocess.run(command, input=json.dumps(record), text=True,
                              capture_output=True, timeout=10).returncode
    assert check() == 0
    record[field] = value
    assert check() != 0


@pytest.mark.parametrize("channel,version,accepted", [
    ("nightly", "v1.2.3-nightly.20261025.1", True),
    ("stable", "v1.2.3", True),
    ("nightly", "v1.2.3", False),
    ("stable", "v1.2.3-nightly.20261025.1", False),
])
def test_actual_bootstrap_tier_refusal(channel, version, accepted):
    checks = "\n".join(line for line in SCRIPT.read_text().splitlines()
                       if 'case "$channel:$version"' in line)
    assert checks.count("case ") == 2
    result = run(source=f'''fail() {{ exit 1; }}
channel='{channel}'
version='{version}'
{checks}
''')
    assert (result.returncode == 0) == accepted

@pytest.mark.skipif(os.name != "posix" or shutil.which("jq") is None, reason="actual Linux shell and jq routing")
@pytest.mark.parametrize("change,accepted", [
    ("none", True), ("pointer-race", False), ("digest", False), ("generation", False),
    ("channel", False), ("extra", False), ("boolean-generation", False),
    ("unsafe-integer", False), ("url", False),
])
def test_channel_pointer_resolves_immutable_metadata_and_refuses_races(tmp_path, change, accepted):
    source=SCRIPT.read_text()
    helpers=source[source.index('    select_channel() {'):source.index('    if [ -z "$version" ]; then')]
    channel=json.dumps(dict(generation=7)).encode()
    pointer=dict(schema="elevenid.installer-channel-pointer/v1", repository="ElevenID/marty-ui",
                 channel="nightly", generation=7, record_sha256=hashlib.sha256(channel).hexdigest())
    if change=="digest": pointer["record_sha256"]="0"*64
    if change=="generation": pointer["generation"]=8
    if change=="channel": pointer["channel"]="stable"
    if change=="extra": pointer["extra"]=True
    if change=="boolean-generation": pointer["generation"]=True
    if change=="unsafe-integer": pointer["generation"]=9007199254740992
    if change=="url": pointer["generation"]="https://attacker.invalid"
    raw=json.dumps(pointer).encode()
    (tmp_path/"pointer").write_bytes(raw)
    (tmp_path/"pointer-again").write_bytes(raw+b" " if change=="pointer-race" else raw)
    (tmp_path/"record").write_bytes(channel)
    stage=tmp_path/"stage"; stage.mkdir()
    q=shlex.quote
    script=f'''set -eu
stage={q(str(stage))}
fixtures={q(str(tmp_path))}
jq={q(shutil.which("jq"))}
channel=nightly
repo=ElevenID/marty-ui
base=https://github.com/ElevenID/marty-ui/releases/download
count=0
fail() {{ echo "$*" >&2; exit 1; }}
digest() {{ sha256sum < "$1" | cut -d ' ' -f 1; }}
fetch() {{
  [ "$1" = "https://raw.githubusercontent.com/ElevenID/marty-ui/installer-channel/nightly.json" ] || exit 90
  count=$((count+1))
  if [ "$count" = 1 ]; then cp "$fixtures/pointer" "$2"; else cp "$fixtures/pointer-again" "$2"; fi
}}
signed_download() {{
  echo "$1"
  cp "$fixtures/record" "$2"
}}
{helpers}
select_channel
recheck_channel_pointer
'''
    result=run(source=script)
    assert (result.returncode==0)==accepted, result.stderr
    if accepted:
        assert result.stdout.strip()=="https://github.com/ElevenID/marty-ui/releases/download/installer-channel-nightly-7/installer-channel.json"
    if change=="pointer-race": assert "Channel changed during download" in result.stderr


def test_version_admission_uses_separate_metadata_release_without_changing_payload_location():
    source=SCRIPT.read_text()
    line=next(line for line in source.splitlines() if 'signed_download "$base/installer-admission-' in line)
    result=run(source='''base=https://github.com/ElevenID/marty-ui/releases/download
version=v1.2.3
stage=/private/stage
signed_download() { printf '%s\\n' "$1"; }
'''+line)
    assert result.returncode==0
    assert result.stdout.strip()=="https://github.com/ElevenID/marty-ui/releases/download/installer-admission-v1.2.3/installer-admission.json"
    payload_line=next(line for line in source.splitlines()
                      if 'signed_download "$base/$version/$operator_asset"' in line)
    result=run(source='''base=https://github.com/ElevenID/marty-ui/releases/download
version=v1.2.3
stage=/private/stage
operator_asset=marty-deploy-linux-amd64
signed_download() { printf '%s\\n' "$1"; }
'''+payload_line)
    assert result.returncode==0
    assert result.stdout.strip()=="https://github.com/ElevenID/marty-ui/releases/download/v1.2.3/marty-deploy-linux-amd64"
    assert source.index('        recheck_channel_pointer\n') < source.index('    chmod 700 "$stage/marty-deploy"')
