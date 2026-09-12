"""Immutable API/migration binding: pure validation and closed fake deployment.

No registry access, real kubectl, secret lookup or deployment occurs. The real
envsubst executable renders only checked-in manifests with synthetic variables.
"""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest
import yaml

from scripts import check_kubernetes_issuance_image as binding
from scripts import prepare_official_beta_release as official

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = "synthetic-private-value-never-echo"


def lock():
    return json.loads((ROOT / "release/stack-lock.json").read_text(encoding="utf-8"))


def issuance(value):
    return next(
        item for item in value["components"] if item["name"] == binding.COMPONENT_NAME
    )


def canonical():
    artifact = next(
        item for item in issuance(lock())["artifacts"] if item["type"] == "oci"
    )
    return artifact["uri"] + "@" + artifact["digest"]


def mirror(repository="registry.example:5443/renamed/nested/external-api"):
    return repository + "@" + canonical().split("@", 1)[1]


@pytest.mark.parametrize(
    "repository",
    [
        "ghcr.io/elevenid/marty-credentials-issuance",
        "registry.example:5443/renamed/nested/external-api",
        "127.0.0.1:5000/owned/image",
        "[::1]:5000/owned/image",
        "localhost:5000/nested/other_name",
    ],
)
def test_exact_content_digest_accepts_canonical_and_explicit_mirrors_unchanged(
    repository,
):
    reference = mirror(repository)
    original = lock()
    before = deepcopy(original)
    assert binding.validate_issuance_binding(reference, original) == reference
    assert original == before


@pytest.mark.parametrize(
    "reference",
    [
        None,
        True,
        "",
        PRIVATE,
        "repo/image@sha256:" + "a" * 64,
        "registry.example/image:latest",
        "${MARTY_ISSUANCE_IMAGE}",
        "https://registry.example/image@sha256:" + "a" * 64,
        "registry.example/image@sha256:" + "a" * 64,
        mirror() + "\n",
        " " + mirror(),
        mirror() + "?" + PRIVATE,
        mirror() + "#" + PRIVATE,
        mirror("user:password@registry.example/image"),
        mirror("registry.example:0/image"),
        mirror("registry.example:65536/image"),
        mirror("registry.example:abc/image"),
        mirror("registry.example/../image"),
        mirror("registry.example//image"),
        mirror("registry.example/IMAGE"),
        mirror("registry.example/image:tag"),
        mirror("registry.example/image/"),
        mirror("registry.example/" + "a" * 4096),
    ],
    ids=lambda value: (
        None if isinstance(value, str) and len(value) < 100 else "bounded-input"
    ),
)
def test_bad_reference_fails_with_only_fixed_diagnostic(reference):
    with pytest.raises(ValueError) as error:
        binding.validate_issuance_binding(reference, lock())
    assert str(error.value) == binding.REFUSAL
    assert PRIVATE not in str(error.value)


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "hold",
        "missing-state",
        "missing-component",
        "duplicate-component",
        "repository",
        "commit",
        "missing-artifact",
        "duplicate-artifact",
        "artifact-type",
        "canonical-host",
        "canonical-path",
        "canonical-tag",
        "digest",
        "components-shape",
        "component-shape",
        "artifact-shape",
        "unrelated-invalid-provenance",
    ],
)
def test_reviewed_lock_authority_is_required_and_not_mutated(mutation):
    value = lock()
    component = issuance(value)
    artifact = next(item for item in component["artifacts"] if item["type"] == "oci")
    if mutation == "schema":
        value["schema"] = PRIVATE
    elif mutation == "hold":
        value["release_state"] = "hold"
    elif mutation == "missing-state":
        value.pop("release_state")
    elif mutation == "missing-component":
        value["components"].remove(component)
    elif mutation == "duplicate-component":
        value["components"].append(deepcopy(component))
    elif mutation in {"repository", "commit"}:
        component[mutation] = PRIVATE
    elif mutation == "missing-artifact":
        component["artifacts"] = []
    elif mutation == "duplicate-artifact":
        component["artifacts"].append(deepcopy(artifact))
    elif mutation == "artifact-type":
        artifact["type"] = PRIVATE
    elif mutation.startswith("canonical-"):
        artifact["uri"] = {
            "canonical-host": "mirror.example/elevenid/marty-credentials-issuance",
            "canonical-path": "ghcr.io/other/marty-credentials-issuance",
            "canonical-tag": "ghcr.io/elevenid/marty-credentials-issuance:latest",
        }[mutation]
    elif mutation == "digest":
        artifact["digest"] = "sha256:" + "d" * 64
    elif mutation == "components-shape":
        value["components"] = PRIVATE
    elif mutation == "component-shape":
        value["components"].append(None)
    elif mutation == "artifact-shape":
        component["artifacts"].append(None)
    else:
        value["components"][0]["artifacts"][0]["provenance"] = PRIVATE
    before = deepcopy(value)
    with pytest.raises(ValueError) as error:
        binding.validate_issuance_binding(canonical(), value)
    assert str(error.value) == binding.REFUSAL
    assert value == before


def test_official_formatter_keeps_ghcr_policy_and_existing_alias():
    artifact = deepcopy(issuance(lock())["artifacts"][0])
    assert official.image_reference(
        artifact, binding.COMPONENT_NAME
    ) == official._image_reference(artifact, binding.COMPONENT_NAME)
    artifact["uri"] = "registry.example/marty-credentials-issuance"
    with pytest.raises(official.OfficialReleaseError):
        official.image_reference(artifact, binding.COMPONENT_NAME)
    assert binding.validate_issuance_binding(mirror(), lock()) == mirror()


@pytest.mark.parametrize(
    "mode",
    [
        "valid",
        "missing",
        "malformed",
        "duplicate",
        "nonfinite",
        "overflow-float",
        "encoding",
        "oversized",
        "deep",
        "args",
    ],
)
def test_cli_fixed_lock_bounded_strict_json_and_private_errors(
    mode, tmp_path, monkeypatch, capsys
):
    script = tmp_path / "scripts/check_kubernetes_issuance_image.py"
    target = tmp_path / "release/stack-lock.json"
    target.parent.mkdir()
    raw = json.dumps(lock()).encode()
    if mode == "malformed":
        raw = (PRIVATE + "{").encode()
    elif mode == "duplicate":
        raw = b'{"schema":"private","schema":"private"}'
    elif mode in {"nonfinite", "overflow-float"}:
        raw = (
            raw[:-1]
            + b',"private":'
            + (b"NaN" if mode == "nonfinite" else b"1e999")
            + b"}"
        )
    elif mode == "encoding":
        raw = b"\xff" + PRIVATE.encode()
    elif mode == "oversized":
        raw = b" " * (binding.MAX_LOCK_BYTES + 1)
    elif mode == "deep":
        raw = b"[" * 2000 + b"0" + b"]" * 2000
    if mode != "missing":
        target.write_bytes(raw)
    monkeypatch.setattr(binding, "__file__", str(script))
    monkeypatch.setattr(
        sys, "argv", [str(script)] + ([PRIVATE] if mode == "args" else [])
    )
    reads = []

    class CapturedEnvironment(dict):
        def get(self, key, default=None):
            reads.append(key)
            return mirror() if len(reads) == 1 else PRIVATE

    monkeypatch.setattr(binding.os, "environ", CapturedEnvironment())
    result = binding.main()
    output = capsys.readouterr()
    assert reads == ([] if mode == "args" else ["MARTY_ISSUANCE_IMAGE"])
    assert result == (0 if mode == "valid" else 1)
    assert output.out == (mirror() + "\n" if mode == "valid" else "")
    assert output.err == ("" if mode == "valid" else binding.REFUSAL + "\n")
    assert PRIVATE not in output.out + output.err


def extracted(name):
    source = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    matches = re.findall(
        r"^" + re.escape(name) + r"\(\) \{\n.*?^\}", source, re.M | re.S
    )
    assert len(matches) == 1
    return matches[0]


def binaries():
    if os.name == "nt":
        bash = Path("C:/Program Files/Git/bin/bash.exe")
        envsubst = Path("C:/Program Files/Git/mingw64/bin/envsubst.exe")
    else:
        bash = Path(shutil.which("bash") or "/missing/bash")
        envsubst = Path(shutil.which("envsubst") or "/missing/envsubst")
    if not bash.is_file() or not envsubst.is_file():
        pytest.skip("Real Bash and envsubst are required for config-only shell tests")
    return bash, envsubst


@pytest.mark.parametrize(
    "case",
    ["canonical", "mirror", "missing", "mutable", "wrong-digest", "private-input"],
)
def test_actual_full_deploy_validates_once_before_any_write_and_renders_same_pin(
    case, tmp_path
):
    bash, envsubst = binaries()
    # No operator environment is inherited, and PATH cannot find real kubectl.
    env = {
        "PATH": tmp_path.as_posix(),
        "REPO_ROOT": ROOT.as_posix(),
        "K8S_DIR": (ROOT / "k8s/oracle").as_posix(),
        "PYTHON_BIN": "checked_python",
        "REAL_PYTHON": Path(sys.executable).as_posix(),
        "REAL_ENVSUBST": envsubst.as_posix(),
        "NAMESPACE": "marty-prod",
        "IMAGE_TAG": "2026.08.0",
        "OCIR_REGISTRY": "synthetic.registry.invalid",
        "UI_BASE_URL": "https://ui.invalid",
        "PUBLIC_API_URL": "https://api.invalid",
        "OIDC_ISSUER_URL_EXTERNAL": "https://auth.invalid",
        "WRITES": (tmp_path / "writes").as_posix(),
        "RENDERED": (tmp_path / "rendered").as_posix(),
        "VALIDATIONS": (tmp_path / "validations").as_posix(),
    }
    selected = canonical() if case == "canonical" else mirror()
    if case != "missing":
        env["MARTY_ISSUANCE_IMAGE"] = {
            "mutable": "registry.example/image:latest",
            "wrong-digest": "registry.example/image@sha256:" + "e" * 64,
            "private-input": PRIVATE,
        }.get(case, selected)
    if os.name == "nt":
        env["SystemRoot"] = os.environ["SystemRoot"]
    prelude = r"""
set -euo pipefail
step() { :; }; info() { :; }; success() { :; }; warn() { :; }
error() { printf '%s\n' "$*" >&2; exit 1; }
basename() { printf '%s' "${1##*/}"; }
command_not_found_handle() { return 91; }
checked_python() {
  [[ $# == 1 && "$1" == "$REPO_ROOT/scripts/check_kubernetes_issuance_image.py" ]] || return 92
  printf 'validate\n' >> "$VALIDATIONS"
  "$REAL_PYTHON" "$@"
}
cmd_setup_secrets() { printf 'setup-secrets\n' >> "$WRITES"; }
resolve_secret_input() { [[ $# == 1 && "$1" == CLOUDFLARE_TUNNEL_TOKEN ]] || return 93; printf ''; }
is_placeholder_secret() { [[ -z "$1" ]]; }
envsubst() { [[ $# == 0 ]] || return 94; "$REAL_ENVSUBST"; }
kubectl() {
  case "$1:$2" in
    create:configmap)
      case "$3" in keycloak-realm-config|keycloak-setup-scripts|marty-runtime-scripts) ;; *) return 95 ;; esac
      printf 'create-configmap\n' >> "$WRITES"
      printf 'kind: ConfigMap\nmetadata:\n  name: synthetic-config\n' ;;
    apply:-f)
      [[ $# == 3 && "$3" == - ]] || return 96
      printf 'apply\n' >> "$WRITES"
      printf '\n---\n' >> "$RENDERED"
      while IFS= read -r line || [[ -n "$line" ]]; do printf '%s\n' "$line" >> "$RENDERED"; done ;;
    rollout:status)
      case "$3" in statefulset/postgres|statefulset/redis|statefulset/rabbitmq|deployment/keycloak|deployment/gateway|deployment/auth|deployment/ui) ;; *) return 97 ;; esac ;;
    delete:job)
      case "$3" in revocation-profile-migrations|db-migrate|issuance-migrations) ;; *) return 98 ;; esac
      printf 'delete-job\n' >> "$WRITES" ;;
    wait:--for=condition=complete)
      case "$3" in job/revocation-profile-migrations|job/db-migrate|job/issuance-migrations) ;; *) return 99 ;; esac ;;
    *) printf 'UNEXPECTED-KUBECTL\n' >> "$WRITES"; return 100 ;;
  esac
}
readonly -f kubectl checked_python envsubst
"""
    program = (
        prelude
        + "\n".join(
            extracted(name)
            for name in (
                "resolve_kubernetes_issuance_image",
                "apply_manifest",
                "cmd_deploy",
            )
        )
        + "\ncmd_deploy\n"
    )
    result = subprocess.run(
        [str(bash), "--noprofile", "--norc", "-s"],
        input=program,
        text=True,
        encoding="utf-8",
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )
    assert (tmp_path / "validations").read_text().splitlines() == ["validate"]
    assert PRIVATE not in result.stdout + result.stderr
    if case not in {"canonical", "mirror"}:
        assert result.returncode != 0
        assert not (tmp_path / "writes").exists()
        assert not (tmp_path / "rendered").exists()
        return
    assert result.returncode == 0, result.stderr
    writes = (tmp_path / "writes").read_text().splitlines()
    assert writes[0] == "apply"  # Namespace is the first write, after validation.
    assert set(writes) == {"apply", "setup-secrets", "create-configmap", "delete-job"}
    rendered = [
        item for item in yaml.safe_load_all((tmp_path / "rendered").read_text()) if item
    ]
    api = next(
        item
        for item in rendered
        if item.get("kind") == "Deployment" and item["metadata"]["name"] == "issuance"
    )
    migration = next(
        item
        for item in rendered
        if item.get("kind") == "Job"
        and item["metadata"]["name"] == "issuance-migrations"
    )
    worker = next(
        item
        for item in rendered
        if item.get("kind") == "Deployment"
        and item["metadata"]["name"] == "canvas-sync-worker"
    )

    def container(item):
        return item["spec"]["template"]["spec"]["containers"][0]

    assert container(api)["image"] == container(migration)["image"] == selected
    assert container(migration)["command"] == [
        "python",
        "manage_migrations.py",
        "upgrade",
    ]
    assert (
        container(worker)["image"]
        == "synthetic.registry.invalid/marty-ui/canvas-sync-worker:2026.08.0"
    )
    assert container(worker)["command"] == ["/usr/local/bin/marty-canvas-sync-worker"]
    assert not container(worker).get("args")
    assert lock()["release"] != "marty-ui@" + env["IMAGE_TAG"]
