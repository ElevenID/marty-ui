"""Repo-local source/reference guards, not Kubernetes runtime qualification."""

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

import pytest
import yaml

from scripts.prepare_official_beta_release import image_reference, OfficialReleaseError

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "rust/crates/release-evidence/src/kubernetes_native.rs"
CONTRACT = json.loads(
    (ROOT / "contracts/kubernetes-native-image-reference.json").read_text()
)


def resources(path):
    return [v for v in yaml.safe_load_all((ROOT / path).read_text()) if v]


def deployment(values, name):
    return next(
        v for v in values if v["kind"] == "Deployment" and v["metadata"]["name"] == name
    )


def owner(value):
    return value["spec"]["template"]["spec"]["containers"][0]


def constants(name):
    source = NATIVE.read_text()
    matched = re.findall(rf"pub const {name}: &\[&str\] = &\[(.*?)\];", source, re.S)
    assert len(matched) == 1
    names = re.findall(r'"([A-Z][A-Z0-9_]+)"', matched[0])
    assert len(names) == len(set(names))
    return set(names)


def test_reference_replays_actual_unchanged_formatter_and_preserves_new_policy_distinction():
    source = (ROOT / "scripts/prepare_official_beta_release.py").read_text(
        encoding="utf-8"
    )
    function = next(
        n
        for n in ast.parse(source).body
        if isinstance(n, ast.FunctionDef) and n.name == "image_reference"
    )
    assert (
        hashlib.sha256(ast.get_source_segment(source, function).encode()).hexdigest()
        == CONTRACT["source_function_utf8_lf_sha256"]
    )
    assert len(CONTRACT["cases"]) == 8
    for case in CONTRACT["cases"]:
        try:
            image_reference(
                {"uri": case["uri"], "digest": "sha256:" + "a" * 64}, "services"
            )
            accepted = True
        except OfficialReleaseError:
            accepted = False
        assert accepted == case["legacy_formatter_accepts"]
    assert (
        sum(
            c["legacy_formatter_accepts"] != c["native_selector_accepts"]
            for c in CONTRACT["cases"]
        )
        == 4
    )


def native_inventory(value):
    selected = owner(value)
    assert selected["envFrom"] == [{"configMapRef": {"name": "issuance-native-config"}}]
    entries = selected["env"]
    assert len(entries) == len({v["name"] for v in entries})
    refs = {
        v["name"]: v["valueFrom"]["configMapKeyRef"]
        for v in entries
        if "configMapKeyRef" in v.get("valueFrom", {})
    }
    assert set(refs) == constants("INHERITED_SETTINGS") | {"ISSUER_BASE_URL"}
    assert refs == {
        name: {
            "name": "marty-config",
            "key": "PUBLIC_API_URL" if name == "ISSUER_BASE_URL" else name,
        }
        for name in refs
    }
    secret_refs = {
        v["name"]: v["valueFrom"]["secretKeyRef"]
        for v in entries
        if "secretKeyRef" in v.get("valueFrom", {})
    }
    assert set(secret_refs) == constants("SECRET_SETTINGS") | {
        "CANVAS_CREDENTIALS_API_TOKEN"
    }
    for name, ref in secret_refs.items():
        assert ref == {
            "name": "marty-secrets",
            "key": name,
            **({"optional": True} if name == "CANVAS_CREDENTIALS_API_TOKEN" else {}),
        }
    assert not any(
        "BAO" in v["name"] or v["name"] == "CANVAS_SYNC_PROCESSOR" for v in entries
    )
    assert value["spec"]["template"]["spec"]["automountServiceAccountToken"] is False


@pytest.mark.parametrize(
    "fault",
    [None, "broad-config", "custody", "missing-key", "duplicate-key", "wrong-secret"],
)
def test_native_inventory_is_complete_and_custody_free(fault):
    value = deployment(
        resources("k8s/oracle/07a-issuance-native.yaml"), "issuance-native"
    )
    native_inventory(value)
    if fault == "broad-config":
        owner(value)["envFrom"].append({"configMapRef": {"name": "marty-config"}})
    elif fault == "custody":
        owner(value)["env"].append(
            {
                "name": "BAO_TOKEN",
                "valueFrom": {
                    "secretKeyRef": {"name": "marty-secrets", "key": "BAO_TOKEN"}
                },
            }
        )
    elif fault == "missing-key":
        owner(value)["env"].pop(0)
    elif fault == "duplicate-key":
        owner(value)["env"].append(deepcopy(owner(value)["env"][0]))
    elif fault == "wrong-secret":
        next(v for v in owner(value)["env"] if v["name"] == "ISSUANCE_API_KEY")[
            "valueFrom"
        ]["secretKeyRef"]["key"] = "OTHER_KEY"
    if fault:
        with pytest.raises(AssertionError):
            native_inventory(value)


def test_all_production_native_configuration_inputs_have_a_classification():
    source = (
        (ROOT / "rust/services/issuance/src/config.rs")
        .read_text()
        .split("#[cfg(test)]")[0]
    )
    inputs = set(re.findall(r'"([A-Z][A-Z0-9_]+)"', source))
    native = owner(
        deployment(resources("k8s/oracle/07a-issuance-native.yaml"), "issuance-native")
    )
    covered = {v["name"] for v in native["env"]}
    for category in (
        "OPTIONAL_SETTINGS",
        "INHERITED_SETTINGS",
        "SECRET_SETTINGS",
        "NATIVE_SETTINGS",
    ):
        covered |= constants(category)
    assert inputs - covered == {
        "APP_ENV",
        "CANVAS_ADMIN_API_TOKEN",
        "CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK",
        "CANVAS_CREDENTIALS_API_TOKEN_FILE",
        "CANVAS_CREDENTIALS_SHARED_SECRET_FILE",
        "CARGO_PKG_VERSION",
        "DIDCOMM_ENCRYPTION_POLICY_FILE",
        "DIDCOMM_TLS_CA_FILE",
        "GRPC_SERVICE_TOKEN_FILE",
        "INTEGRATION_SECRET_MASTER_KEY_ENV",
        "MARTY_ISSUANCE__",
    }


def test_existing_three_way_management_identity_and_legacy_owner_are_preserved():
    original = resources("k8s/oracle/07-microservices.yaml")
    native = resources("k8s/oracle/07a-issuance-native.yaml")
    key = {
        "name": "ISSUANCE_API_KEY",
        "valueFrom": {
            "secretKeyRef": {"name": "marty-secrets", "key": "ISSUANCE_API_KEY"}
        },
    }
    for values, name in [
        (original, "gateway"),
        (original, "issuance"),
        (native, "issuance-native"),
    ]:
        assert [
            v
            for v in owner(deployment(values, name))["env"]
            if v["name"] == "ISSUANCE_API_KEY"
        ] == [key]
    legacy = deployment(original, "issuance")
    assert owner(legacy)["image"] == "${MARTY_ISSUANCE_IMAGE}"
    assert legacy["spec"]["selector"]["matchLabels"] == {"app": "issuance"}
    assert {v["containerPort"] for v in owner(legacy)["ports"]} == {8005, 9005}
    flow = owner(deployment(original, "flow"))
    assert (
        next(v for v in flow["env"] if v["name"] == "ISSUANCE_GRPC_TARGET")["value"]
        == "issuance:9005"
    )
    assert "ISSUANCE_NATIVE_SERVICE_URL" not in {
        v["name"] for v in owner(deployment(original, "gateway"))["env"]
    }


def test_operational_owner_is_rust_and_existing_binary_preflight_is_connected():
    assert not (ROOT / "scripts/kubernetes_native_issuance.py").exists()
    manifest = (ROOT / "rust/crates/release-evidence/Cargo.toml").read_text()
    assert 'name = "kubernetes-native-issuance"' in manifest
    assert 'path = "src/kubernetes_native_cli.rs"' in manifest
    script = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    assert 'command -v "$K8S_NATIVE_ISSUANCE_BIN"' in script
    assert (
        '"$K8S_NATIVE_ISSUANCE_BIN" render --repo-root "$REPO_ROOT" --manifest-dir "$K8S_DIR"'
        in script
    )
    body = script.split("cmd_deploy() {", 1)[1].split("\n}", 1)[0]
    assert body.index("prepare_kubernetes_native_issuance") < body.index(
        'apply_manifest "${K8S_DIR}/00-namespace.yaml"'
    )
    assert body.index("job/issuance-migrations") < body.index(
        'apply_manifest "${K8S_DIR}/07-microservices.yaml"'
    )


def ci_prerequisites(workflow):
    matches = []
    for job in workflow["jobs"].values():
        steps = job.get("steps", [])
        if any(
            step.get("name") == "Compile reusable Rust test executables"
            for step in steps
        ):
            matches.append(steps)
    assert len(matches) == 1
    steps = matches[0]
    found = [
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Require Kubernetes deployment contract executables"
    ]
    assert len(found) == 1
    selected = steps[found[0]]
    assert selected.get("shell") == "bash"
    assert "if" not in selected and "continue-on-error" not in selected
    assert selected["run"].strip().splitlines() == [
        "set -euo pipefail",
        "command -v bash",
        "command -v envsubst",
    ]
    compile_index = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Compile reusable Rust test executables"
    )
    assert found[0] < compile_index
    assert "cargo test --locked --workspace --no-run" in steps[compile_index]["run"]
    assert any(
        "cargo test --locked --workspace >" in step.get("run", "") for step in steps
    )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing",
        "duplicate",
        "conditional",
        "optional",
        "bash",
        "envsubst",
        "late",
        "disconnected",
    ],
)
def test_ci_prerequisites_are_required_before_actual_workspace_gates(fault):
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    ci_prerequisites(workflow)
    steps = next(
        job["steps"]
        for job in workflow["jobs"].values()
        if any(
            step.get("name") == "Require Kubernetes deployment contract executables"
            for step in job.get("steps", [])
        )
    )
    step = next(
        step
        for step in steps
        if step.get("name") == "Require Kubernetes deployment contract executables"
    )
    if fault == "missing":
        steps.remove(step)
    elif fault == "duplicate":
        steps.append(deepcopy(step))
    elif fault == "conditional":
        step["if"] = "false"
    elif fault == "optional":
        step["continue-on-error"] = True
    elif fault in {"bash", "envsubst"}:
        step["run"] = step["run"].replace(f"command -v {fault}", ":")
    elif fault == "late":
        steps.remove(step)
        steps.append(step)
    elif fault == "disconnected":
        for candidate in steps:
            candidate["run"] = candidate.get("run", "").replace(
                "cargo test --locked --workspace >", "echo disconnected >"
            )
    if fault:
        with pytest.raises(AssertionError):
            ci_prerequisites(workflow)
