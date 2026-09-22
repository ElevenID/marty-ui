"""Native selection guards and controlled CLI orchestration, never deployment."""

from copy import deepcopy
import json
import subprocess
from types import SimpleNamespace

import pytest

from scripts import conformance_native as native
from scripts import conformance_stack as stack

PROJECT = "marty-conformance-native-test"
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
ID = "b" * 64
REVISION = "c" * 40
PLAN = {"marty_ui_sha": REVISION, "release_version": "1.2.3"}


def coverage():
    return {
        "schema": "marty.issuance-native-coverage/v1",
        "native_http": [
            {
                "method": "POST",
                "path": "/v1/issuance/initiate",
                "operation": "initiate_issuance",
                "initiation_behavior_contract": True,
            },
            {
                "method": "POST",
                "path": "/v1/issuance/didcomm/deliver",
                "operation": "didcomm_deliver",
                "didcomm_behavior_contract": True,
            },
            {
                "method": "POST",
                "path": "/v1/issued-credentials/{credential_id}/renew",
                "operation": "renew_issued_credential",
                "renewal_behavior_contract": True,
            },
            *[
                {
                    "method": method,
                    "path": path,
                    "operation": operation,
                    "issued_credential_adapter_behavior_contract": True,
                }
                for method, path, operation in [
                    ("GET", "/v1/issued-credentials", "list_issued_credentials"),
                    (
                        "GET",
                        "/v1/issued-credentials/{credential_id}",
                        "get_issued_credential",
                    ),
                    (
                        "POST",
                        "/v1/issued-credentials/{credential_id}/revoke",
                        "revoke_issued_credential",
                    ),
                    (
                        "POST",
                        "/v1/issued-credentials/{credential_id}/suspend",
                        "suspend_issued_credential",
                    ),
                    (
                        "POST",
                        "/v1/issued-credentials/{credential_id}/reinstate",
                        "reinstate_issued_credential",
                    ),
                ]
            ],
        ],
    }


@pytest.mark.parametrize("key", native.REQUIRED_ENVIRONMENT)
@pytest.mark.parametrize("empty", [None, "", "  "])
def test_both_owners_missing_mandatory_configuration_fail(key, empty):
    value = model()
    for name in ("issuance", "issuance-native"):
        value["services"][name]["environment"][key] = empty
    with pytest.raises(ValueError):
        native.validate_model(
            value, project=PROJECT, authcrypt=False, local_build=False
        )


@pytest.mark.parametrize("name", native.TOKEN_CONSUMERS)
@pytest.mark.parametrize("token", [None, "", "different-synthetic-token-0123456789"])
def test_every_existing_client_requires_paired_token(name, token):
    value = model()
    value["services"][name]["environment"]["GRPC_SERVICE_TOKEN"] = token
    with pytest.raises(ValueError):
        native.validate_model(
            value, project=PROJECT, authcrypt=False, local_build=False
        )


@pytest.mark.parametrize("rate", ["30", "1200", "0"])
def test_token_capacity_is_paired_without_rejecting_legacy_zero(rate):
    value = model()
    for name in ("issuance", "issuance-native"):
        value["services"][name]["environment"]["TOKEN_RATE_LIMIT"] = rate
    native.validate_model(value, project=PROJECT, authcrypt=False, local_build=False)
    value["services"]["issuance-native"]["environment"]["TOKEN_RATE_LIMIT"] = (
        "different"
    )
    with pytest.raises(ValueError):
        native.validate_model(
            value, project=PROJECT, authcrypt=False, local_build=False
        )


@pytest.mark.parametrize(
    "fault", [None, "rate", "authorization", "other-field", "rewritten-before"]
)
def test_beta_shared_setting_guard_accepts_only_source_derived_deltas(fault):
    import runpy

    gate = runpy.run_path(
        str(native.ROOT / "scripts/test_conformance_native_compose.py")
    )
    previous = model()
    previous["services"]["issuance"]["environment"]["TOKEN_RATE_LIMIT"] = "1200"
    for setting in (
        "ALLOWED_REDIRECT_URIS",
        "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
        "TOKEN_RATE_LIMIT",
    ):
        previous["services"]["issuance-native"]["environment"].pop(setting)
    actual = deepcopy(previous)
    for setting in (
        "ALLOWED_REDIRECT_URIS",
        "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
        "TOKEN_RATE_LIMIT",
    ):
        actual["services"]["issuance-native"]["environment"][setting] = previous[
            "services"
        ]["issuance"]["environment"][setting]
    gate["assert_beta_shared_setting_repairs"](previous, actual)
    if fault == "rate":
        actual["services"]["issuance-native"]["environment"]["TOKEN_RATE_LIMIT"] = "30"
    elif fault == "authorization":
        actual["services"]["issuance-native"]["environment"][
            "ISSUANCE_AUTH_SESSION_TTL_MINUTES"
        ] = "different"
    elif fault == "other-field":
        actual["services"]["gateway"]["environment"]["ISSUANCE_API_KEY"] = "changed"
    elif fault == "rewritten-before":
        previous["services"]["issuance-native"]["environment"][
            "ALLOWED_REDIRECT_URIS"
        ] = "already-present"
    if fault:
        with pytest.raises(AssertionError):
            gate["assert_beta_shared_setting_repairs"](previous, actual)


def model(*, local=False, authcrypt=False):
    env = {
        key: "synthetic"
        for key in (
            "DATABASE_URL",
            "TOKEN_HMAC_KEY",
            "ISSUANCE_API_KEY",
            "INTEGRATION_SECRET_MASTER_KEY",
            "SIGNING_KEYS_INTERNAL_URL",
            "SIGNING_KEYS_INTERNAL_API_KEY",
            "ORG_GRPC_TARGET",
            "CT_GRPC_TARGET",
            "RP_GRPC_TARGET",
            "CREDENTIAL_TEMPLATE_SERVICE_URL",
            "REVOCATION_PROFILE_SERVICE_URL",
            "ISSUANCE_OFFER_TTL_MINUTES",
            "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
            "ALLOWED_REDIRECT_URIS",
            "VCDM_RELATED_RESOURCE_URLS",
            "UNIVERSAL_RESOLVER_URL",
            "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
        )
    }
    env.update(
        TOKEN_RATE_LIMIT="30",
        GRPC_SERVICE_TOKEN="synthetic-conformance-token-0123456789",
        ISSUER_BASE_URL="https://conformance.example",
        DIDCOMM_ALLOW_PRIVATE_IPS="true",
        DIDCOMM_TLS_CA_FILE=native.CA_TARGET,
    )
    ca = {
        "type": "bind",
        "source": "/synthetic/tls/root-ca.pem",
        "target": native.CA_TARGET,
        "read_only": True,
        "bind": {"create_host_path": False},
    }
    legacy = {"environment": deepcopy(env), "volumes": [deepcopy(ca)]}
    candidate = {
        "environment": {**env, "SERVICE_NAME": "issuance_native"},
        "volumes": [ca],
        "entrypoint": ["/app/services/entrypoint.sh"],
        "command": [],
        "image": f"{PROJECT}-issuance-native" if local else IMAGE,
        "healthcheck": {
            "test": ["CMD", "curl", "--fail", "http://localhost:8005/health"]
        },
        "depends_on": {
            "issuance-migrations": {"condition": "service_completed_successfully"},
            "postgres": {"condition": "service_healthy"},
        },
    }
    if local:
        candidate["build"] = {
            "dockerfile": "services/Dockerfile",
            "args": {"SERVICE_NAME": "issuance-native"},
        }
    else:
        candidate["pull_policy"] = "always"
    if authcrypt:
        for service in (legacy, candidate):
            service["environment"]["DIDCOMM_ENCRYPTION_POLICY_FILE"] = (
                "/run/secrets/didcomm-authcrypt/didcomm-encryption-policy.json"
            )
            service["volumes"].append(
                {
                    "type": "bind",
                    "source": "/synthetic/policy",
                    "target": "/run/secrets/didcomm-authcrypt",
                    "read_only": True,
                    "bind": {"create_host_path": False},
                }
            )
    return {
        "services": {
            **{
                name: {"environment": {"GRPC_SERVICE_TOKEN": env["GRPC_SERVICE_TOKEN"]}}
                for name in native.TOKEN_CONSUMERS
            },
            "issuance": legacy,
            "issuance-native": candidate,
            "gateway": {
                "image": IMAGE,
                "environment": {
                    "GRPC_SERVICE_TOKEN": env["GRPC_SERVICE_TOKEN"],
                    "ISSUANCE_NATIVE_SERVICE_URL": native.NATIVE_URL,
                    "ISSUANCE_SERVICE_URL": native.LEGACY_URL,
                    "ISSUANCE_API_KEY": "synthetic",
                    "SIGNING_KEYS_INTERNAL_API_KEY": "synthetic",
                },
                "depends_on": {"issuance-native": {"condition": "service_healthy"}},
            },
        }
    }


@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize("authcrypt", [False, True])
def test_explicit_owner_pairs_files_and_models(local, authcrypt):
    command = stack.compose_command(
        PROJECT,
        issuance_owner="native",
        use_ghcr=not local,
        include_didcomm_authcrypt=authcrypt,
    )
    files = [command[i + 1] for i, value in enumerate(command) if value == "--file"]
    assert files[-1].endswith(stack.ISOLATION_FILE)
    for path in (stack.NATIVE_FILE, stack.NATIVE_CA_FILE):
        assert sum(item.endswith(path) for item in files) == 1
    assert any(item.endswith(stack.NATIVE_IMAGES_FILE) for item in files) is (not local)
    for path in (stack.DIDCOMM_AUTHCRYPT_FILE, stack.NATIVE_AUTHCRYPT_FILE):
        assert any(item.endswith(path) for item in files) is authcrypt
    native.validate_model(
        model(local=local, authcrypt=authcrypt),
        project=PROJECT,
        authcrypt=authcrypt,
        local_build=local,
    )


@pytest.mark.parametrize("owner", ["", "rust", "native-legacy", None])
def test_unknown_owner_never_aliases_legacy(owner):
    with pytest.raises(ValueError):
        stack.compose_command(PROJECT, issuance_owner=owner)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: m["services"].pop("issuance-native"),
        lambda m: m["services"]["gateway"]["environment"].pop(
            "ISSUANCE_NATIVE_SERVICE_URL"
        ),
        lambda m: m["services"]["gateway"]["environment"].update(
            ISSUANCE_NATIVE_SERVICE_URL=native.LEGACY_URL
        ),
        lambda m: m["services"]["issuance-native"]["environment"].update(
            SERVICE_NAME="issuance"
        ),
        lambda m: m["services"]["issuance-native"].update(entrypoint=["python"]),
        lambda m: m["services"]["issuance-native"].update(
            image="ghcr.io/elevenid/marty-ui-oss/services:latest"
        ),
        lambda m: m["services"]["issuance-native"].update(image=IMAGE[:-1] + "b"),
        lambda m: m["services"]["issuance-native"].update(build={"context": "."}),
        lambda m: m["services"]["issuance-native"].update(
            ports=[{"target": 8005, "published": "8005"}]
        ),
        lambda m: m["services"]["issuance-native"]["depends_on"].pop(
            "issuance-migrations"
        ),
        lambda m: m["services"]["gateway"]["depends_on"].clear(),
        lambda m: m["services"]["issuance-native"]["environment"].update(
            ISSUANCE_API_KEY="different"
        ),
        lambda m: m["services"]["issuance-native"]["environment"].update(
            DATABASE_URL="different"
        ),
        lambda m: m["services"]["issuance-native"]["environment"].update(
            CT_GRPC_TARGET="different:9003"
        ),
        lambda m: m["services"]["issuance-native"]["environment"].update(
            ISSUANCE_OFFER_TTL_MINUTES="1"
        ),
        lambda m: m["services"]["issuance-native"]["environment"].update(
            ISSUANCE_AUTH_SESSION_TTL_MINUTES="1"
        ),
        lambda m: m["services"]["issuance-native"]["environment"].update(
            ALLOWED_REDIRECT_URIS="https://different.example/callback"
        ),
        lambda m: m["services"]["issuance-native"]["environment"].update(
            DIDCOMM_ALLOW_PRIVATE_IPS="false"
        ),
        lambda m: m["services"]["issuance-native"]["volumes"].clear(),
        lambda m: m["services"]["issuance-native"]["volumes"].append(
            deepcopy(m["services"]["issuance-native"]["volumes"][0])
        ),
        lambda m: m["services"]["issuance-native"]["volumes"][0].update(
            source="/other/ca.pem"
        ),
        lambda m: m["services"]["issuance-native"]["volumes"][0].update(
            read_only=False
        ),
        lambda m: m["services"]["issuance-native"]["volumes"][0]["bind"].update(
            create_host_path=True
        ),
    ],
)
def test_native_model_rejects_drift(mutation):
    value = model()
    mutation(value)
    with pytest.raises(ValueError):
        native.validate_model(
            value, project=PROJECT, authcrypt=False, local_build=False
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: m["services"]["issuance-native"]["environment"].pop(
            "DIDCOMM_ENCRYPTION_POLICY_FILE"
        ),
        lambda m: m["services"]["issuance-native"]["volumes"][1].update(
            source="/other/policy"
        ),
        lambda m: m["services"]["gateway"].update(
            volumes=[deepcopy(m["services"]["issuance-native"]["volumes"][1])]
        ),
    ],
)
def test_policy_is_paired_and_confined(mutation):
    value = model(authcrypt=True)
    mutation(value)
    with pytest.raises(ValueError):
        native.validate_model(value, project=PROJECT, authcrypt=True, local_build=False)


@pytest.mark.parametrize("index", range(8))
def test_capability_floor_requires_every_real_selected_operation(index):
    value = coverage()
    native.validate_capabilities(value)
    row = value["native_http"].pop(index)
    with pytest.raises(ValueError):
        native.validate_capabilities(value)
    value["native_http"].append({**row, "operation": "legacy_alias"})
    with pytest.raises(ValueError):
        native.validate_capabilities(value)
    value["native_http"][-1] = row
    value["native_http"].append(row)
    with pytest.raises(ValueError):
        native.validate_capabilities(value)


def test_probe_isolated_and_cleans_exact_id_on_failure():
    for fails in (False, True):
        calls = []
        ownership = {}

        def runner(command, **kwargs):
            calls.append(command)
            assert kwargs["stdin"] is subprocess.DEVNULL
            assert kwargs["stderr"] is subprocess.DEVNULL
            stdout = ""
            code = 0
            if command[1:3] == ["image", "inspect"]:
                stdout = json.dumps(
                    [
                        {
                            "Os": "linux",
                            "RepoDigests": [IMAGE],
                            "Config": {
                                "Labels": {
                                    "org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
                                    "org.opencontainers.image.revision": REVISION,
                                    "org.opencontainers.image.version": "1.2.3",
                                }
                            },
                        }
                    ]
                )
            elif command[1] == "create":
                ownership["name"] = command[command.index("--name") + 1]
                ownership["token"] = command[command.index("--label") + 1].split(
                    "=", 1
                )[1]
                assert command[command.index("--network") + 1] == "none"
                assert (
                    "--read-only" in command
                    and "--mount" not in command
                    and "--env" not in command
                )
                assert (
                    "/usr/local/bin/marty-issuance-service" in command[-1]
                    and "ldd" in command[-1]
                )
                stdout = ID
            elif command[1] == "start":
                assert command == ["docker", "start", "--attach", ID]
                code = int(fails)
            elif command[1:3] == ["container", "inspect"]:
                assert command[-1] == ownership["name"]
                stdout = json.dumps(
                    [
                        {
                            "Id": ID,
                            "Config": {
                                "Labels": {
                                    "marty.conformance.native-probe": ownership["token"]
                                }
                            },
                        }
                    ]
                )
            elif command[1] == "rm":
                assert command == ["docker", "rm", "--force", ID]
            else:
                raise AssertionError(command)
            return SimpleNamespace(returncode=code, stdout=stdout)

        if fails:
            with pytest.raises(ValueError):
                native.probe_image(IMAGE, PROJECT, plan=PLAN, runner=runner)
        else:
            native.probe_image(IMAGE, PROJECT, plan=PLAN, runner=runner)
        assert calls[-1] == ["docker", "rm", "--force", ID]


@pytest.mark.parametrize(
    "fault",
    [
        "returned-id",
        "create-timeout",
        "foreign-owner",
        "different-id",
        "malformed-inspection",
        "cleanup-failure",
        "labels-null",
    ],
)
def test_probe_failures_never_delete_unverified_resources(fault):
    calls, owned = [], {}

    def runner(command, **kwargs):
        calls.append(command)
        code, stdout = 0, ""
        if command[1:3] == ["image", "inspect"]:
            if fault == "labels-null":
                stdout = json.dumps(
                    [
                        {
                            "Os": "linux",
                            "RepoDigests": [IMAGE],
                            "Config": {"Labels": None},
                        }
                    ]
                )
            else:
                stdout = json.dumps([{"Os": "linux"}])
        elif command[1] == "create":
            owned["token"] = command[command.index("--label") + 1].split("=", 1)[1]
            if fault == "create-timeout":
                raise subprocess.TimeoutExpired(command, 60)
            stdout = "invalid-id" if fault == "returned-id" else ID
        elif command[1] == "start":
            assert fault not in {"returned-id", "create-timeout"}
            code = 1
        elif command[1:3] == ["container", "inspect"]:
            if fault == "labels-null":
                code = 1
            elif fault == "malformed-inspection":
                stdout = "{}"
            else:
                stdout = json.dumps(
                    [
                        {
                            "Id": "d" * 64 if fault == "different-id" else ID,
                            "Config": {
                                "Labels": {
                                    "marty.conformance.native-probe": "foreign"
                                    if fault == "foreign-owner"
                                    else owned["token"]
                                }
                            },
                        }
                    ]
                )
        elif command[1] == "rm":
            assert command == ["docker", "rm", "--force", ID]
            code = int(fault == "cleanup-failure")
        else:
            raise AssertionError("Unexpected preflight command")
        return SimpleNamespace(returncode=code, stdout=stdout)

    with pytest.raises(ValueError):
        native.probe_image(
            IMAGE, PROJECT, plan=PLAN if fault == "labels-null" else None, runner=runner
        )
    removals = [command for command in calls if command[1] == "rm"]
    assert removals == (
        [["docker", "rm", "--force", ID]]
        if fault
        in {
            "returned-id",
            "create-timeout",
            "cleanup-failure",
        }
        else []
    )
    if fault == "labels-null":
        assert not any(command[1] == "create" for command in calls)


def test_timed_out_creation_and_failed_inspection_report_cleanup_unverified():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command[1:3] == ["image", "inspect"]:
            return SimpleNamespace(returncode=0, stdout=json.dumps([{"Os": "linux"}]))
        if command[1] == "create":
            raise subprocess.TimeoutExpired(command, 60)
        if command[1:3] == ["container", "inspect"]:
            return SimpleNamespace(returncode=1, stdout="")
        raise AssertionError("Unverified resource must not be started or deleted")

    with pytest.raises(ValueError, match="cleanup could not verify whether creation"):
        native.probe_image(IMAGE, PROJECT, plan=None, runner=runner)
    assert len(calls) == 3


def test_shared_compose_file_is_in_checkout_packaging_boundary():
    import yaml

    common = "docker-compose.service.issuance-native.yml"
    for path in (
        "docker-compose.beta.yml",
        "docker-compose.profile.conformance-native.yml",
    ):
        document = yaml.safe_load((native.ROOT / path).read_text(encoding="utf-8"))
        reference = document["services"]["issuance-native"]["extends"]["file"]
        assert (
            reference == common
            and (native.ROOT / path).parent.joinpath(reference).is_file()
        )
    # Beta uses full, source-verified checkouts. The durable runtime-config
    # bundle contains mounted assets, not relocated Compose service definitions.
    deployment = (native.ROOT / "scripts/deploy-local-beta-release.ps1").read_text(
        encoding="utf-8"
    )
    assert '(Join-Path $script:RepoRoot "docker-compose.beta.yml")' in deployment
    assert "git -C $script:RepoRoot rev-parse HEAD" in deployment
    common_model = yaml.safe_load((native.ROOT / common).read_text(encoding="utf-8"))
    assert not common_model["services"]["issuance-native"].get("volumes")
    runtime_path = "docker-compose.service.issuance-native-runtime.yml"
    assert common_model["services"]["issuance-native"]["extends"] == {
        "file": runtime_path,
        "service": "issuance-native",
    }
    runtime = yaml.safe_load((native.ROOT / runtime_path).read_text(encoding="utf-8"))
    assert runtime["services"]["issuance-native"]["build"]["context"] == "."
    assert set(runtime["services"]["issuance-native"]) == {
        "build",
        "depends_on",
        "healthcheck",
        "restart",
    }


def assert_required_compose_gate(workflow):
    name = "Verify explicit native conformance selection"
    job = workflow["jobs"]["test-rust-service-images"]
    assert not job.get("continue-on-error", False)
    steps = job["steps"]
    matches = [index for index, step in enumerate(steps) if step.get("name") == name]
    assert len(matches) == 1
    index = matches[0]
    assert steps[index] == {
        "name": name,
        "run": 'python3 scripts/test_conformance_native_compose.py --compose-command "$RUNNER_TEMP/compose-render-v5.4.0"',
    }
    assert index > next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Verify native DIDComm configuration ownership"
    )
    assert index < next(
        i
        for i, step in enumerate(steps)
        if "docker/build-push-action@" in step.get("uses", "")
    )


@pytest.mark.parametrize(
    "fault", [None, "removed", "optional", "conditional", "command", "duplicate"]
)
def test_render_gate_is_mandatory_and_cannot_be_disconnected(fault):
    import yaml

    workflow = yaml.safe_load(
        (native.ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    assert_required_compose_gate(workflow)
    steps = workflow["jobs"]["test-rust-service-images"]["steps"]
    step = next(
        step
        for step in steps
        if step.get("name") == "Verify explicit native conformance selection"
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
            assert_required_compose_gate(workflow)


@pytest.mark.parametrize("phase", ["verify", "pull", "probe", "up", "success"])
def test_released_up_preserves_preflight_order_and_up_exit(monkeypatch, phase):
    events = []
    monkeypatch.setattr(
        stack.sys,
        "argv",
        [
            "conformance_stack.py",
            "--project",
            PROJECT,
            "--issuance-owner",
            "native",
            "--stack-manifest",
            "synthetic.json",
            "--stack-checksums",
            "SHA256SUMS",
            "--release-ui-revision",
            REVISION,
            "up",
        ],
    )
    monkeypatch.setattr(stack, "configure_project_environment", lambda *_: None)
    monkeypatch.setattr(stack, "configure_oidf_internal_tls_port", lambda: None)
    monkeypatch.setattr(stack, "rendered_config", lambda *_, **__: model())
    monkeypatch.setattr(stack, "validate_isolation", lambda *_: [])
    monkeypatch.setattr(stack, "assert_ports_available", lambda *_, **__: None)
    monkeypatch.setattr(stack, "wait_for_one_shots", lambda *_: events.append("wait"))

    def verify(*_):
        events.append("verify")
        if phase == "verify":
            raise ValueError("synthetic")
        return PLAN

    def probe(*_, **__):
        events.append("probe")
        if phase == "probe":
            raise ValueError("synthetic")

    monkeypatch.setattr(
        stack.runpy,
        "run_path",
        lambda *_: {
            "validate_model": native.validate_model,
            "verify_release": verify,
            "probe_image": probe,
        },
    )

    def runner(command, **_):
        event = "pull" if command[1] == "pull" else "up"
        events.append(event)
        if event == "up":
            assert command[-3:] == ["up", "--detach", "--no-build"]
        return SimpleNamespace(returncode=23 if phase == event else 0)

    monkeypatch.setattr(stack.subprocess, "run", runner)
    if phase in {"verify", "probe"}:
        with pytest.raises(ValueError):
            stack.main()
    else:
        assert stack.main() == (0 if phase == "success" else 23)
    assert (
        events
        == {
            "verify": ["verify"],
            "pull": ["verify", "pull"],
            "probe": ["verify", "pull", "probe"],
            "up": ["verify", "pull", "probe", "up"],
            "success": ["verify", "pull", "probe", "up", "wait"],
        }[phase]
    )


@pytest.mark.parametrize("phase", ["capability", "build", "probe", "up", "success"])
def test_source_up_is_explicit_and_stops_after_failed_phase(
    monkeypatch, tmp_path, phase
):
    events = []
    source = tmp_path / "contracts"
    source.mkdir()
    document = coverage()
    if phase == "capability":
        document["native_http"].pop()
    (source / "issuance-native-coverage.json").write_text(
        json.dumps(document), encoding="utf-8"
    )
    monkeypatch.setattr(stack, "ROOT", tmp_path)
    monkeypatch.setattr(
        stack.sys,
        "argv",
        [
            "conformance_stack.py",
            "--project",
            PROJECT,
            "--issuance-owner",
            "native",
            "--local-build",
            "up",
        ],
    )
    monkeypatch.setattr(stack, "configure_project_environment", lambda *_: None)
    monkeypatch.setattr(stack, "configure_oidf_internal_tls_port", lambda: None)
    monkeypatch.setattr(stack, "rendered_config", lambda *_, **__: model(local=True))
    monkeypatch.setattr(stack, "validate_isolation", lambda *_: [])
    monkeypatch.setattr(stack, "assert_ports_available", lambda *_, **__: None)
    monkeypatch.setattr(stack, "local_build_arguments", lambda: [])
    monkeypatch.setattr(stack, "wait_for_one_shots", lambda *_: events.append("wait"))

    def capabilities(document):
        events.append("capability")
        native.validate_capabilities(document)

    def probe(image, project, *, plan):
        events.append("probe")
        assert (
            plan is None
            and project == PROJECT
            and image == f"{PROJECT}-issuance-native"
        )
        if phase == "probe":
            raise ValueError("Synthetic binary failure")

    monkeypatch.setattr(
        stack.runpy,
        "run_path",
        lambda *_: {
            "validate_model": native.validate_model,
            "validate_capabilities": capabilities,
            "CAPABILITY_PATH": native.CAPABILITY_PATH,
            "probe_image": probe,
            # No release verifier is available in explicit source evidence mode.
        },
    )

    def runner(command, **kwargs):
        event = "build" if command[-1] == "build" else "up"
        if event == "up":
            assert command[-3:] == ["up", "--detach", "--no-build"]
        events.append(event)
        return SimpleNamespace(returncode=23 if phase == event else 0)

    monkeypatch.setattr(stack.subprocess, "run", runner)
    if phase in {"capability", "probe"}:
        with pytest.raises(ValueError):
            stack.main()
    else:
        assert stack.main() == (0 if phase == "success" else 23)
    assert (
        events
        == {
            "capability": ["capability"],
            "build": ["capability", "build"],
            "probe": ["capability", "build", "probe"],
            "up": ["capability", "build", "probe", "up"],
            "success": ["capability", "build", "probe", "up", "wait"],
        }[phase]
    )
