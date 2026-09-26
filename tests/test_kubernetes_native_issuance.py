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
# The passport selector remains disabled in Kubernetes until tenant keyring and
# provider secrets have a closed Secret-backed binding in the renderer.
PASSPORT_NOT_KUBERNETES_BOUND = {
    "PASSPORT_NATIVE_HTTP_ENABLED",
    "PASSPORT_KMS_CALLBACKS_ENABLED",
    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE",
    "PASSPORT_TENANT_API_KEYS",
    "ICAO_DOCUMENT_SIGNER_URL",
    "ICAO_DOCUMENT_SIGNER_API_KEY",
    "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED",
    "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
    "PERSONALIZATION_BUREAU_URL",
    "PERSONALIZATION_BUREAU_API_KEY",
    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
}


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


def test_duplicate_common_organization_binding_cleanup_preserves_complete_mapping():
    source = (ROOT / "k8s/oracle/01-configmap.yaml").read_text(encoding="utf-8")
    binding = '  MARTY_ORG_ID: "${MARTY_ORG_ID}"\n'
    anchor = '  MARTY_MIGRATION_PROFILE: "${MARTY_MIGRATION_PROFILE}"\n'
    assert source.count(binding) == source.count(anchor) == 1
    original = source.replace(anchor, anchor + binding)
    assert hashlib.sha256(original.encode()).hexdigest() == (
        "94188015aa6a471d6aba8c8713cd38ede22531676e588dd21da913bf266c3259"
    )
    # This historical parser overwrites the identical duplicate; the actual
    # Rust renderer's separate test still refuses duplicate mappings strictly.
    assert yaml.safe_load(source) == yaml.safe_load(original)
    assert yaml.safe_load(source)["data"]["MARTY_ORG_ID"] == "${MARTY_ORG_ID}"


def signing_inventory(values):
    assert len(values) == 2
    value = deployment(values, "signing-keys")
    selected = owner(value)
    entries = selected["env"]
    assert len(entries) == len({v["name"] for v in entries}) == 7
    actual = {v["name"]: v for v in entries}
    expected = {
        "SERVICE_NAME": {"name": "SERVICE_NAME", "value": "signing-keys"},
        "SIGNING_KEYS_SERVICE_PORT": {
            "name": "SIGNING_KEYS_SERVICE_PORT",
            "value": "8017",
        },
        "SIGNING_KEYS_REDIS_URL": {
            "name": "SIGNING_KEYS_REDIS_URL",
            "value": "redis://redis:6379/2",
        },
    }
    for name in ("SIGNING_KEYS_INTERNAL_API_KEY", "OPENBAO_SERVICE_TOKEN"):
        expected[name] = {
            "name": name,
            "valueFrom": {"secretKeyRef": {"name": "marty-secrets", "key": name}},
        }
    for name in ("BAO_ADDR", "PUBLIC_DOMAIN"):
        expected[name] = {
            "name": name,
            "valueFrom": {"configMapKeyRef": {"name": "marty-config", "key": name}},
        }
    assert actual == expected
    assert selected["image"] == "${MARTY_SERVICES_IMAGE}"
    assert selected["envFrom"] == []
    assert len(value["spec"]["template"]["spec"]["containers"]) == 1
    assert value["spec"]["selector"]["matchLabels"] == {"app": "signing-keys"}
    service = next(v for v in values if v["kind"] == "Service")
    assert service["spec"] == {
        "type": "ClusterIP",
        "selector": {"app": "signing-keys"},
        "ports": [{"name": "http", "port": 8017, "targetPort": 8017}],
    }
    for name in ("livenessProbe", "readinessProbe"):
        assert selected[name]["httpGet"] == {"path": "/health", "port": 8017}


@pytest.mark.parametrize(
    "fault", [None, "missing-token", "wrong-redis", "broad-env", "sidecar"]
)
def test_signing_dependency_has_only_existing_declared_bindings(fault):
    values = resources("k8s/oracle/07b-signing-keys.yaml")
    signing_inventory(values)
    selected = owner(deployment(values, "signing-keys"))
    if fault == "missing-token":
        selected["env"] = [
            v for v in selected["env"] if v["name"] != "OPENBAO_SERVICE_TOKEN"
        ]
    elif fault == "wrong-redis":
        next(v for v in selected["env"] if v["name"] == "SIGNING_KEYS_REDIS_URL")[
            "value"
        ] = "redis://localhost:6379/2"
    elif fault == "broad-env":
        selected["envFrom"] = [{"configMapRef": {"name": "marty-config"}}]
    elif fault == "sidecar":
        deployment(values, "signing-keys")["spec"]["template"]["spec"][
            "containers"
        ].append({"name": "other"})
    if fault:
        with pytest.raises(AssertionError):
            signing_inventory(values)


def test_signing_existing_service_and_kubernetes_dependency_sources_are_connected():
    for path in ("docker-compose.base.yml", "docker-compose.selfhost.prod.yml"):
        service = yaml.safe_load((ROOT / path).read_text())["services"]["signing-keys"]
        assert service["build"]["args"]["SERVICE_NAME"] == "signing-keys"
        assert service["environment"]["SIGNING_KEYS_SERVICE_PORT"] == "8017"
        assert (
            service["environment"]["SIGNING_KEYS_REDIS_URL"] == "redis://redis:6379/2"
        )
        assert (
            service["depends_on"]["db-migrate"]["condition"]
            == "service_completed_successfully"
        )
    config = (ROOT / "rust/services/signing-keys/src/config.rs").read_text()
    assert (
        'secret_value(values, "BAO_TOKEN")?.or(secret_value(values, "OPENBAO_SERVICE_TOKEN")?)'
        in config
    )
    main = (ROOT / "rust/services/signing-keys/src/main.rs").read_text()
    assert "OpenBaoEnvelopeProvider" in main
    common = resources("k8s/oracle/01-configmap.yaml")[0]["data"]
    assert common["BAO_ADDR"] == "${BAO_ADDR}"
    assert (
        "BAO_ADDR=https://vault.example.com"
        in (ROOT / ".env.production.example").read_text()
    )
    original = resources("k8s/oracle/07-microservices.yaml")
    assert not any(v["metadata"]["name"] == "signing-keys" for v in original)
    gateway = owner(deployment(original, "gateway"))
    assert [v for v in gateway["env"] if v["name"] == "AUTH_GRPC_TARGET"] == [
        {"name": "AUTH_GRPC_TARGET", "value": "auth:9001"}
    ]
    cli = (
        ROOT / "rust/crates/release-evidence/src/kubernetes_native_cli.rs"
    ).read_text()
    assert '"07b-signing-keys.yaml"' in cli
    script = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    assert "OPENBAO_SERVICE_TOKEN=" in script


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
    assert PASSPORT_NOT_KUBERNETES_BOUND.isdisjoint(covered)
    assert PASSPORT_NOT_KUBERNETES_BOUND.isdisjoint(
        {v["name"] for v in native["env"]}
    )
    assert PASSPORT_NOT_KUBERNETES_BOUND <= inputs
    covered |= PASSPORT_NOT_KUBERNETES_BOUND
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
    assert constants("OPTIONAL_SETTINGS") >= {
        "CANVAS_MIRROR_WORKER_ENABLED",
        "CANVAS_MIRROR_WORKER_ORGANIZATION_ID",
        "CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS",
        "CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS",
        "CANVAS_MIRROR_WORKER_BATCH_LIMIT",
        "CANVAS_MIRROR_WORKER_RETRY_FAILED",
        "CANVAS_MIRROR_WORKER_RUN_ON_STARTUP",
        "CANVAS_MIRROR_FAILURE_WARNING_ATTEMPTS",
        "CANVAS_MIRROR_FAILURE_CRITICAL_ATTEMPTS",
        "CANVAS_MIRROR_ALERT_WEBHOOK_URL",
        "CANVAS_MIRROR_ALERT_WEBHOOK_TIMEOUT_SECONDS",
    }
    publication_controls = {
        "CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE",
        "CANVAS_CREDENTIALS_ASSERTION_NARRATIVE",
        "CANVAS_CREDENTIALS_PROVENANCE_BASE_URL",
        "CANVAS_CREDENTIALS_RECIPIENT_HASHED",
        "CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS",
    }
    assert constants("INHERITED_SETTINGS") >= publication_controls
    assert constants("OPTIONAL_SETTINGS").isdisjoint(publication_controls)


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
