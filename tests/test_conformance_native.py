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
            *[
                {
                    "method": method,
                    "path": path,
                    "operation": operation,
                    "oid4vci_authorization_behavior_contract": True,
                }
                for method, path, operation in [
                    ("GET", "/v1/issuance/authorize", "authorize"),
                    ("POST", "/v1/issuance/par", "pushed_authorization_request"),
                    (
                        "POST",
                        "/v1/issuance/deferred-credential",
                        "deferred_credential",
                    ),
                    ("POST", "/v1/issuance/notification", "notification_endpoint"),
                    (
                        "PUT",
                        "/v1/issuance/oid4vci-clients",
                        "put_oid4vci_registered_client",
                    ),
                    (
                        "POST",
                        "/v1/issuance/transactions/{tx_id}/revoke",
                        "revoke_transaction",
                    ),
                    ("GET", "/v1/issuance/credentials", "list_credentials"),
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
    "fault",
    [
        None,
        "rate",
        "authorization",
        "mirror-setting",
        "missing-mirror",
        "other-field",
        "rewritten-before",
    ],
)
def test_beta_shared_setting_guard_accepts_only_source_derived_deltas(fault):
    import runpy
    import yaml

    gate = runpy.run_path(
        str(native.ROOT / "scripts/test_conformance_native_compose.py")
    )

    def source(path):
        return yaml.safe_load((native.ROOT / path).read_text(encoding="utf-8"))

    common = gate["complete_common"](source(gate["COMMON"]), source(gate["RUNTIME"]))
    approved = source(gate["APPROVED_COMMON"])
    base = source("docker-compose.base.yml")

    def check():
        gate["assert_native_inputs"](common, base)
        assert common == approved, (
            "Shared native service changed outside the KMS-only model"
        )

    check()
    current = common["services"]["issuance-native"]["environment"]
    if fault == "rate":
        current["TOKEN_RATE_LIMIT"] = "${TOKEN_RATE_LIMIT:-1200}"
    elif fault == "authorization":
        current["ISSUANCE_AUTH_SESSION_TTL_MINUTES"] = "different"
    elif fault == "mirror-setting":
        current["CANVAS_MIRROR_WORKER_BATCH_LIMIT"] = "different"
    elif fault == "missing-mirror":
        current.pop("CANVAS_MIRROR_WORKER_BATCH_LIMIT")
    elif fault == "other-field":
        current["UNREVIEWED_SETTING"] = "synthetic"
    elif fault == "rewritten-before":
        base["services"]["issuance"]["environment"]["ALLOWED_REDIRECT_URIS"] = (
            "different"
        )
    if fault:
        with pytest.raises(AssertionError):
            check()


@pytest.mark.parametrize("owner", ["issuance", "issuance-native"])
@pytest.mark.parametrize(
    "secret_source",
    ["INTEGRATION_SECRET_MASTER_KEY", "INTEGRATION_SECRET_MASTER_KEY_FILE"],
)
def test_native_conformance_rejects_local_master_key_sources(owner, secret_source):
    value = model()
    value["services"][owner]["environment"][secret_source] = "synthetic-forbidden"
    with pytest.raises(ValueError, match="Local integration-secret master-key custody"):
        native.validate_model(
            value, project=PROJECT, authcrypt=False, local_build=False
        )


@pytest.mark.parametrize(
    "fault",
    [
        "missing-url",
        "downgraded-url",
        "missing-ca",
        "missing-mount",
        "reused-key",
        "missing-issuer-key",
        "reused-issuer-key",
    ],
)
def test_native_conformance_requires_remote_envelope_custody(fault):
    value = model()
    service = value["services"]["issuance-native"]
    environment = service["environment"]
    if fault == "missing-url":
        environment.pop("INTEGRATION_SECRET_KMS_URL")
    elif fault == "downgraded-url":
        environment["INTEGRATION_SECRET_KMS_URL"] = "http://signing-keys:8017/internal"
    elif fault == "missing-ca":
        environment.pop("INTEGRATION_SECRET_KMS_CA_FILE")
    elif fault == "missing-mount":
        service["secrets"] = []
    elif fault == "reused-key":
        environment["SIGNING_KEYS_INTEGRATION_SECRET_KEY"] = environment[
            "ISSUANCE_API_KEY"
        ]
    elif fault == "missing-issuer-key":
        environment.pop("SIGNING_KEYS_ISSUER_SIGN_KEY")
    elif fault == "reused-issuer-key":
        environment["SIGNING_KEYS_ISSUER_SIGN_KEY"] = environment[
            "SIGNING_KEYS_INTEGRATION_SECRET_KEY"
        ]
    with pytest.raises(ValueError, match="Native remote"):
        native.validate_model(
            value, project=PROJECT, authcrypt=False, local_build=False
        )


def model(*, local=False, authcrypt=False):
    env = {
        key: "synthetic"
        for key in (
            "DATABASE_URL",
            "TOKEN_HMAC_KEY",
            "ISSUANCE_API_KEY",
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
    legacy["environment"].update(
        DIDCOMM_DELIVERY_OWNER="native",
        ISSUANCE_NATIVE_SERVICE_URL=native.NATIVE_URL,
    )
    legacy["depends_on"] = {
        "issuance-native": {"condition": "service_healthy", "required": True}
    }
    legacy["healthcheck"] = {
        "test": ["CMD", "curl", "--fail", "http://localhost:8005/ready"]
    }
    candidate = {
        "environment": {
            **env,
            "SERVICE_NAME": "issuance_native",
            "SIGNING_KEYS_INTEGRATION_SECRET_KEY": "synthetic-dedicated-integration-secret-key-00000001",
            "SIGNING_KEYS_ISSUER_SIGN_KEY": "synthetic-dedicated-issuer-sign-key-0000000000001",
            "INTEGRATION_SECRET_KMS_URL": "https://signing-keys:8018/internal",
            "INTEGRATION_SECRET_KMS_CA_FILE": "/run/secrets/dev_integration_secret_ca",
        },
        "secrets": [
            {
                "source": "dev_integration_secret_ca",
                "target": "/run/secrets/dev_integration_secret_ca",
            }
        ],
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
    legacy["environment"]["SIGNING_KEYS_INTERNAL_URL"] = (
        "http://signing-keys:8017/internal"
    )
    candidate["environment"]["SIGNING_KEYS_INTERNAL_URL"] = (
        "http://gateway:8000/internal/signing-keys"
    )
    if local:
        candidate["build"] = {
            "dockerfile": "services/Dockerfile",
            "args": {"SERVICE_NAME": "issuance-native"},
        }
    else:
        candidate["pull_policy"] = "always"
    if authcrypt:
        candidate["environment"].update(
            {
                "DIDCOMM_ENCRYPTION_POLICY_FILE": "/run/secrets/didcomm-authcrypt/didcomm-encryption-policy.json",
                "DIDCOMM_KMS_ADDR": "http://openbao:8200",
                "DIDCOMM_KMS_TOKEN_FILE": "/run/secrets/didcomm-kms/openbao-token",
            }
        )
        candidate["volumes"].extend(
            {
                "type": "bind",
                "source": f"/synthetic/policy/{name}",
                "target": f"/run/secrets/didcomm-authcrypt/{name}",
                "read_only": True,
                "bind": {"create_host_path": False},
            }
            for name in ("didcomm-encryption-policy.json",)
        )
        candidate["volumes"].append(
            {
                "type": "volume",
                "source": "didcomm_issuance_token",
                "target": "/run/secrets/didcomm-kms",
                "read_only": True,
            }
        )
        candidate["depends_on"]["openbao-init"] = {
            "condition": "service_completed_successfully"
        }
    services = {
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
    if authcrypt:
        plugin_image = "synthetic.invalid/openbao-didcomm@sha256:" + "d" * 64
        services["openbao"] = {
            "image": plugin_image,
            "command": ["server", "-dev", "-config", "/bao/config/didcomm-plugin.hcl"],
            "volumes": [
                {
                    "type": "bind",
                    "source": "/synthetic/docker/openbao-didcomm-dev.hcl",
                    "target": "/bao/config/didcomm-plugin.hcl",
                    "read_only": True,
                    "bind": {"create_host_path": False},
                }
            ],
        }
        services["openbao-init"] = {
            "image": plugin_image,
            "environment": {
                "DIDCOMM_KMS_PLUGIN_REQUIRED": "true",
                "DIDCOMM_ISSUANCE_TOKEN_FILE": "/run/didcomm-token/openbao-token",
            },
            "volumes": [
                {
                    "type": "volume",
                    "source": "didcomm_issuance_token",
                    "target": "/run/didcomm-token",
                }
            ],
        }
    return {
        "services": services,
        "volumes": {"didcomm_issuance_token": {}} if authcrypt else {},
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
    assert (
        any(item.endswith(stack.DIDCOMM_AUTHCRYPT_FILE) for item in files) is authcrypt
    )
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
        lambda m: m["services"]["issuance"]["environment"].update(
            DIDCOMM_DELIVERY_OWNER="legacy"
        ),
        lambda m: m["services"]["issuance"]["environment"].update(
            ISSUANCE_NATIVE_SERVICE_URL=native.LEGACY_URL
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


@pytest.mark.parametrize("index", range(len(native.REQUIRED_OPERATIONS)))
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
