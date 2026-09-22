"""Pure source/inventory and negative-model guards, not a Compose emulator."""

from copy import deepcopy
import json
from pathlib import Path
import runpy

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/test_base_native_issuance_compose.py"))


def sources():
    return tuple(
        GATE["source"](path)
        for path in ("docker-compose.base.yml", GATE["PROFILE"], GATE["RUNTIME"])
    )


def test_source_inventory_is_complete_and_base_profile_is_opt_in():
    GATE["assert_sources"](*sources())
    assert "issuance-native" not in sources()[0]["services"]
    command = GATE["EXTRACTION"]["OWNER"]["compose_command"](
        "marty-conformance-default"
    )
    assert GATE["PROFILE"] not in command
    assert GATE["IMAGES"] not in command


@pytest.mark.parametrize(
    "fault",
    [
        "offer-ttl-precedence",
        "auth-ttl-precedence",
        "redirect-precedence",
        "missing-env",
        "extra-secret",
        "flow-target",
        "sibling",
        "readiness-missing",
        "readiness-extra",
        "beta-env",
        "structural-env",
        "structural-network",
        "extends",
        "token",
        "public-port",
    ],
)
def test_source_guard_rejects_config_drift(fault):
    base, profile, runtime = sources()
    native = profile["services"]["issuance-native"]
    edge = profile["services"]["gateway"]["environment"]
    if fault == "offer-ttl-precedence":
        native["environment"]["ISSUANCE_OFFER_TTL_MINUTES"] = (
            "${ISSUANCE_OFFER_TTL_MINUTES-10080}"
        )
    elif fault == "auth-ttl-precedence":
        native["environment"]["ISSUANCE_AUTH_SESSION_TTL_MINUTES"] = (
            "${ISSUANCE_AUTH_SESSION_TTL_MINUTES-60}"
        )
    elif fault == "redirect-precedence":
        native["environment"]["ALLOWED_REDIRECT_URIS"] = (
            "${ALLOWED_REDIRECT_URIS:-https://permissive.invalid}"
        )
    elif fault == "missing-env":
        native["environment"].pop("CANVAS_CREDENTIALS_STATUS_SYNC_URL")
    elif fault == "extra-secret":
        native["environment"]["BAO_TOKEN"] = "synthetic"
    elif fault == "flow-target":
        profile["services"]["flow"]["environment"]["ISSUANCE_GRPC_TARGET"] = (
            "issuance:9005"
        )
    elif fault == "sibling":
        profile["services"]["applicant"] = {"environment": {}}
    elif fault == "readiness-missing":
        edge["GATEWAY_REQUIRED_READY_SERVICES"] = "issuance-native"
    elif fault == "readiness-extra":
        edge["GATEWAY_REQUIRED_READY_SERVICES"] += ",unowned"
    elif fault == "beta-env":
        native["environment"]["TOKEN_HMAC_KEY"] = "${TOKEN_HMAC_KEY:?required for beta}"
    elif fault == "structural-env":
        runtime["services"]["issuance-native"]["environment"] = {"ENVIRONMENT": "beta"}
    elif fault == "structural-network":
        runtime["services"]["issuance-native"]["networks"] = ["marty-network"]
    elif fault == "extends":
        native["extends"]["file"] = GATE["EXTRACTION"]["COMMON"]
    elif fault == "token":
        edge["GRPC_SERVICE_TOKEN"] = ""
    else:
        native["ports"] = ["8005:8005"]
    with pytest.raises(AssertionError):
        GATE["assert_sources"](base, profile, runtime)


@pytest.fixture
def modeled(tmp_path):
    # This deliberately small input tests the closed comparator, not rendering.
    # The separate mandatory Compose script supplies actual complete models.
    baseline = {
        "services": {
            name: {"environment": {}} for name in GATE["NATIVE"]["TOKEN_CONSUMERS"]
        },
        "networks": {"marty-network": {}},
        "volumes": {"preserved": {}},
    }
    baseline["services"]["issuance"]["environment"] = {
        "ALLOWED_REDIRECT_URIS": "",
        "DIDCOMM_ALLOW_PRIVATE_IPS": "false",
        "ISSUANCE_AUTH_SESSION_TTL_MINUTES": "60",
        "TOKEN_RATE_LIMIT": "30",
    }
    baseline["services"]["issuance"]["ports"] = [
        {"host_ip": "127.0.0.1", "published": "8005", "target": 8005}
    ]
    baseline["services"]["issuance"]["healthcheck"] = {
        "test": ["CMD", "curl", "-f", "http://localhost:8005/health"]
    }
    baseline["services"]["gateway"].update(
        environment={"ISSUANCE_SERVICE_URL": GATE["NATIVE"]["LEGACY_URL"]},
        depends_on={},
    )
    baseline["services"]["flow"]["environment"] = {
        "ISSUANCE_GRPC_TARGET": "issuance:9005",
        "ISSUANCE_SERVICE_URL": GATE["NATIVE"]["LEGACY_URL"],
    }
    options = {
        "local": True,
        "authcrypt": True,
        "inputs": {},
        "policy_directory": tmp_path,
    }
    actual = GATE["expected_model"](baseline, **options)
    GATE["assert_model"](baseline, actual, **options)
    return baseline, actual, options


@pytest.mark.parametrize(
    "fault",
    [
        "native-alias",
        "legacy-url",
        "physical-url",
        "flow-grpc",
        "loopback",
        "health",
        "migration",
        "signing-dependency",
        "database",
        "redirect-allowlist",
        "auth-session-ttl",
        "token",
        "management-key",
        "discovery",
        "canvas",
        "build",
        "entrypoint",
        "image",
        "native-port",
        "private-ip",
        "ca",
        "policy-unpaired",
        "policy-writable",
        "policy-create",
        "policy-outside",
        "readiness",
        "unowned-volume",
    ],
)
def test_model_guard_rejects_every_unowned_delta(modeled, fault):
    baseline, actual, options = modeled
    native = actual["services"]["issuance-native"]
    edge = actual["services"]["gateway"]
    flow = actual["services"]["flow"]
    if fault == "native-alias":
        edge["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] = GATE["NATIVE"][
            "LEGACY_URL"
        ]
    elif fault == "legacy-url":
        edge["environment"]["ISSUANCE_SERVICE_URL"] = GATE["NATIVE"]["NATIVE_URL"]
    elif fault == "physical-url":
        flow["environment"]["ISSUANCE_SERVICE_URL"] = GATE["NATIVE"]["NATIVE_URL"]
    elif fault == "flow-grpc":
        flow["environment"]["ISSUANCE_GRPC_TARGET"] = "issuance:9005"
    elif fault == "loopback":
        actual["services"]["issuance"]["ports"][0]["host_ip"] = "0.0.0.0"
    elif fault == "health":
        native["healthcheck"]["test"] = ["CMD", "true"]
    elif fault == "migration":
        native["depends_on"]["issuance-migrations"]["condition"] = "service_started"
    elif fault == "signing-dependency":
        native["depends_on"].pop("signing-keys")
    elif fault == "database":
        native["environment"]["DATABASE_URL"] = "synthetic-foreign"
    elif fault == "redirect-allowlist":
        native["environment"]["ALLOWED_REDIRECT_URIS"] = "https://other.invalid"
    elif fault == "auth-session-ttl":
        native["environment"]["ISSUANCE_AUTH_SESSION_TTL_MINUTES"] = "600"
    elif fault == "token":
        actual["services"]["organization"]["environment"]["GRPC_SERVICE_TOKEN"] = (
            "unpaired"
        )
    elif fault == "management-key":
        native["environment"]["ISSUANCE_API_KEY"] = "unpaired"
    elif fault == "discovery":
        native["environment"]["ISSUER_BASE_URL"] = "https://beta.elevenidllc.com"
    elif fault == "canvas":
        native["environment"]["CANVAS_CREDENTIALS_STATUS_SYNC_URL"] = "unpaired"
    elif fault == "build":
        native["build"]["args"]["SERVICE_NAME"] = "issuance"
    elif fault == "entrypoint":
        native["entrypoint"] = ["python"]
    elif fault == "image":
        native["image"] = "unreviewed:latest"
    elif fault == "native-port":
        native["ports"] = ["8005:8005"]
    elif fault == "private-ip":
        native["environment"]["DIDCOMM_ALLOW_PRIVATE_IPS"] = "true"
    elif fault == "ca":
        native["environment"]["DIDCOMM_TLS_CA_FILE"] = "/conformance.pem"
    elif fault == "policy-unpaired":
        native["environment"]["DIDCOMM_ENCRYPTION_POLICY_FILE"] = "/other.json"
    elif fault == "policy-writable":
        native["volumes"][0]["read_only"] = False
    elif fault == "policy-create":
        native["volumes"][0]["bind"]["create_host_path"] = True
    elif fault == "policy-outside":
        flow["volumes"] = deepcopy(native["volumes"])
    elif fault == "readiness":
        edge["environment"]["GATEWAY_REQUIRED_READY_SERVICES"] = "issuance-native"
    else:
        actual["volumes"].pop("preserved")
    with pytest.raises(AssertionError):
        GATE["assert_model"](baseline, actual, **options)


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_policy_source_must_exist_as_directory(modeled, tmp_path, kind):
    baseline, actual, options = modeled
    path = tmp_path / kind
    if kind == "file":
        path.write_text("synthetic")
    options["policy_directory"] = path
    with pytest.raises(AssertionError, match="must already exist"):
        GATE["assert_model"](baseline, actual, **options)
    assert path.is_file() if kind == "file" else not path.exists()


def test_expected_model_selects_the_retained_legacy_issuance_owner_exactly(modeled):
    baseline, actual, _ = modeled
    selector_names = {"DIDCOMM_DELIVERY_OWNER", "ISSUANCE_NATIVE_SERVICE_URL"}
    baseline_environment = baseline["services"]["issuance"]["environment"]
    actual_environment = actual["services"]["issuance"]["environment"]

    assert selector_names.isdisjoint(baseline_environment)
    assert {name: actual_environment[name] for name in selector_names} == {
        "DIDCOMM_DELIVERY_OWNER": "native",
        "ISSUANCE_NATIVE_SERVICE_URL": GATE["NATIVE"]["NATIVE_URL"],
    }


def test_shared_images_are_not_duplicated_and_packaging_paths_resolve():
    old = ROOT / "docker-compose.profile.conformance-native-images.yml"
    assert not old.exists()
    assert GATE["EXTRACTION"]["OWNER"]["NATIVE_IMAGES_FILE"] == GATE["IMAGES"]
    for name in (GATE["PROFILE"], GATE["EXTRACTION"]["COMMON"]):
        entry = GATE["source"](name)["services"]["issuance-native"]["extends"]
        assert entry == {"file": GATE["RUNTIME"], "service": "issuance-native"}
        assert (ROOT / name).parent.joinpath(entry["file"]).is_file()
    image = (ROOT / GATE["IMAGES"]).read_text()
    assert "build: !reset null" in image and "MARTY_SERVICES_IMAGE:?" in image
    assert "pull_policy: always" in image
    assert "DIDCOMM" not in image and "ports:" not in image


def test_migrated_canvas_publication_routes_are_selected_without_legacy_signing_inputs():
    document = json.loads((ROOT / GATE["NATIVE"]["CAPABILITY_PATH"]).read_text())
    selected = {(item["method"], item["path"]) for item in document["native_http"]}
    template_contract = json.loads(
        (ROOT / "contracts/issuance-application-templates.json").read_text()
    )
    template_routes = {
        (item["method"], item["path"])
        for item in template_contract["surface"]["routes"]
    }
    template_base = template_contract["surface"]["base_path"]
    selected_template_routes = {
        (method, path)
        for method, path in selected
        if path == template_base or path.startswith(f"{template_base}/")
    }
    assert len(template_routes) == 8
    assert selected_template_routes == template_routes
    canvas_contract = json.loads(
        (ROOT / "contracts/issuance-canvas-mirror.json").read_text()
    )
    canvas_routes = {
        (item["method"], item["path"]) for item in canvas_contract["routes"]
    }
    assert len(canvas_routes) == 6
    assert canvas_routes <= selected
    # Actual native signer consumes the same organization/DID identity, not
    # unreferenced legacy static key/profile-ID environment fields.
    signer = (
        ROOT / "rust/services/issuance/src/canvas_lti_tool_signing.rs"
    ).read_text()
    assert (
        "resolve" in signer and "issuer_did" in signer and "organization_id" in signer
    )
    for key in (
        "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS",
        "CANVAS_LTI_TOOL_ACTIVE_KID",
        "CANVAS_LTI_TOOL_PUBLIC_JWKS",
    ):
        assert key in GATE["LEGACY_ONLY"]
        assert key not in signer


def assert_ci(workflow):
    job = workflow["jobs"]["test-rust-service-images"]
    assert not job.get("continue-on-error", False)
    name = "Verify opt-in base native issuance configuration"
    matches = [i for i, item in enumerate(job["steps"]) if item.get("name") == name]
    assert len(matches) == 1
    index = matches[0]
    assert job["steps"][index] == {
        "name": name,
        "run": 'python3 scripts/test_base_native_issuance_compose.py --compose-command "$RUNNER_TEMP/compose-render-v5.4.0"',
    }
    assert index > next(
        i
        for i, item in enumerate(job["steps"])
        if item.get("name") == "Verify explicit native conformance selection"
    )
    assert index < next(
        i
        for i, item in enumerate(job["steps"])
        if "docker/build-push-action@" in item.get("uses", "")
    )


@pytest.mark.parametrize(
    "fault", [None, "removed", "optional", "conditional", "command", "duplicate"]
)
def test_render_ci_cannot_be_disconnected(fault):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert_ci(workflow)
    steps = workflow["jobs"]["test-rust-service-images"]["steps"]
    step = next(
        item
        for item in steps
        if item.get("name") == "Verify opt-in base native issuance configuration"
    )
    if fault == "removed":
        steps.remove(step)
    elif fault == "optional":
        step["continue-on-error"] = True
    elif fault == "conditional":
        step["if"] = "false"
    elif fault == "command":
        step["run"] = "echo skipped"
    elif fault == "duplicate":
        steps.append(deepcopy(step))
    if fault:
        with pytest.raises(AssertionError):
            assert_ci(workflow)
