"""Closed native conformance selection and release preflight; no legacy fallback."""

from __future__ import annotations

import json
import re
import runpy
import subprocess
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY = runpy.run_path(str(ROOT / "scripts/validate_beta_didcomm_configuration.py"))
RELEASE = runpy.run_path(str(ROOT / "scripts/prepare_official_beta_release.py"))
CA_TARGET = "/run/secrets/didcomm-conformance-root-ca.pem"
NATIVE_URL = "http://issuance-native:8005"
LEGACY_URL = "http://issuance:8005"
CAPABILITY_PATH = "contracts/issuance-native-coverage.json"
REQUIRED_OPERATIONS = {
    ("POST", "/v1/issuance/initiate"): (
        "initiate_issuance",
        "initiation_behavior_contract",
    ),
    ("POST", "/v1/issuance/didcomm/deliver"): (
        "didcomm_deliver",
        "didcomm_behavior_contract",
    ),
    ("POST", "/v1/issued-credentials/{credential_id}/renew"): (
        "renew_issued_credential",
        "renewal_behavior_contract",
    ),
    ("GET", "/v1/issued-credentials"): (
        "list_issued_credentials",
        "issued_credential_adapter_behavior_contract",
    ),
    ("GET", "/v1/issued-credentials/{credential_id}"): (
        "get_issued_credential",
        "issued_credential_adapter_behavior_contract",
    ),
    ("POST", "/v1/issued-credentials/{credential_id}/revoke"): (
        "revoke_issued_credential",
        "issued_credential_adapter_behavior_contract",
    ),
    ("POST", "/v1/issued-credentials/{credential_id}/suspend"): (
        "suspend_issued_credential",
        "issued_credential_adapter_behavior_contract",
    ),
    ("POST", "/v1/issued-credentials/{credential_id}/reinstate"): (
        "reinstate_issued_credential",
        "issued_credential_adapter_behavior_contract",
    ),
}
REQUIRED_ENVIRONMENT = (
    "TOKEN_RATE_LIMIT",
    "DATABASE_URL",
    "ISSUER_BASE_URL",
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
)
TOKEN_CONSUMERS = (
    "gateway",
    "auth",
    "organization",
    "credential-template",
    "trust-profile",
    "compliance-profile",
    "presentation-policy",
    "deployment-profile",
    "flow",
    "issuance",
    "revocation-profile",
    "device-registration",
    "verification",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_capabilities(document: dict[str, Any]) -> None:
    """Source ownership floor only; runtime conformance is still mandatory."""
    try:
        require(
            document["schema"] == "marty.issuance-native-coverage/v1",
            "Unsupported native coverage schema",
        )
        selected = {}
        for row in document["native_http"]:
            key = (row["method"], row["path"])
            require(key not in selected, "Ambiguous native coverage operation")
            selected[key] = row
        for key, (operation, flag) in REQUIRED_OPERATIONS.items():
            row = selected.get(key, {})
            require(
                row.get("operation") == operation and row.get(flag) is True,
                "Required native conformance capability is not selected",
            )
    except (KeyError, TypeError, AttributeError):
        raise ValueError("Invalid native coverage model") from None


def validate_model(
    model: dict[str, Any], *, project: str, authcrypt: bool, local_build: bool
) -> None:
    """Validate actual Compose output, never a service name treated as proof."""
    try:
        services = model["services"]
        native, legacy, gateway = (
            services[name] for name in ("issuance-native", "issuance", "gateway")
        )
        env = POLICY["environment_mapping"](native["environment"])
        previous = POLICY["environment_mapping"](legacy["environment"])
        edge = POLICY["environment_mapping"](gateway["environment"])
        require(
            edge.get("ISSUANCE_NATIVE_SERVICE_URL") == NATIVE_URL,
            "Native gateway selection must be explicit",
        )
        require(
            edge.get("ISSUANCE_SERVICE_URL") == LEGACY_URL,
            "Legacy HTTP owner must be retained",
        )
        require(
            env.get("SERVICE_NAME") == "issuance_native",
            "Native executable selector is missing",
        )
        require(
            native.get("entrypoint") == ["/app/services/entrypoint.sh"]
            and native.get("command") == [],
            "Native entrypoint is incompatible",
        )
        require(
            not native.get("ports") and not native.get("container_name"),
            "Native owner must remain project isolated",
        )
        require(
            native["healthcheck"]["test"]
            == ["CMD", "curl", "--fail", "http://localhost:8005/health"],
            "Native readiness probe is missing",
        )
        for dependency, condition in (
            ("issuance-migrations", "service_completed_successfully"),
            ("postgres", "service_healthy"),
        ):
            require(
                native["depends_on"][dependency]["condition"] == condition,
                "Native database readiness is incomplete",
            )
        require(
            gateway["depends_on"]["issuance-native"]["condition"] == "service_healthy",
            "Gateway must wait for native readiness",
        )
        for key in (
            *REQUIRED_ENVIRONMENT,
            "ISSUANCE_OFFER_TTL_MINUTES",
            "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
            "ALLOWED_REDIRECT_URIS",
            "VCDM_RELATED_RESOURCE_URLS",
            "UNIVERSAL_RESOLVER_URL",
            "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
        ):
            require(
                env.get(key) == previous.get(key),
                "Native and legacy issuance configuration is not paired",
            )
        for key in REQUIRED_ENVIRONMENT:
            require(
                isinstance(env.get(key), str) and bool(env[key].strip()),
                "Mandatory native issuance configuration is missing",
            )
        token = env.get("GRPC_SERVICE_TOKEN")
        require(
            isinstance(token, str) and len(token.strip()) >= 32,
            "Native service authentication is missing or too short",
        )
        for name in ("issuance-native", *TOKEN_CONSUMERS):
            peer = POLICY["environment_mapping"](services[name]["environment"])
            require(
                peer.get("GRPC_SERVICE_TOKEN") == token
                and not peer.get("GRPC_SERVICE_TOKEN_FILE"),
                "Native service authentication is not paired",
            )
        require(
            env["ISSUANCE_API_KEY"] == edge.get("ISSUANCE_API_KEY"),
            "Gateway native management key is not paired",
        )
        require(
            env["SIGNING_KEYS_INTERNAL_API_KEY"]
            == edge.get("SIGNING_KEYS_INTERNAL_API_KEY"),
            "Native signing key is not paired",
        )
        require(
            env.get("DIDCOMM_ALLOW_PRIVATE_IPS")
            == previous.get("DIDCOMM_ALLOW_PRIVATE_IPS")
            == "true",
            "Conformance endpoint policy is not paired",
        )
        require(
            env.get("DIDCOMM_TLS_CA_FILE")
            == previous.get("DIDCOMM_TLS_CA_FILE")
            == CA_TARGET,
            "Conformance trust is not paired",
        )
        mounts = []
        for service in (legacy, native):
            items = [
                item
                for item in service.get("volumes", [])
                if item.get("target") == CA_TARGET
            ]
            require(len(items) == 1, "Conformance CA mount is missing or ambiguous")
            item = items[0]
            require(
                item.get("type") == "bind" and item.get("read_only") is True,
                "Conformance CA mount must be read-only",
            )
            mounts.append(item)
        require(
            mounts[0]["source"] == mounts[1]["source"]
            and mounts[1]["bind"]["create_host_path"] is False,
            "Native CA mount is not paired",
        )
        POLICY["validate_model"](model, authcrypt_enabled=authcrypt)
        image = native.get("image", "")
        if local_build:
            require(
                image == f"{project}-issuance-native",
                "Local native image must be project scoped",
            )
            require(
                native["build"]["dockerfile"] == "services/Dockerfile",
                "Local native build is missing",
            )
            require(
                native["build"]["args"]["SERVICE_NAME"] == "issuance-native",
                "Local native build selector is incompatible",
            )
        else:
            require(
                not native.get("build") and native.get("pull_policy") == "always",
                "Released native mode must not build or reuse mutable images",
            )
            uri, digest = image.rsplit("@", 1)
            require(
                RELEASE["image_reference"]({"uri": uri, "digest": digest}, "services")[
                    "reference"
                ]
                == image,
                "Native image must use its exact services digest",
            )
            require(
                image == gateway.get("image"),
                "Gateway/native services artifacts must be paired",
            )
    except (
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        RELEASE["OfficialReleaseError"],
    ):
        raise ValueError("Invalid native conformance model") from None


def _run(command: list[str], *, runner, capture: bool = False, timeout: int = 60):
    result = runner(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=timeout,
        check=False,
    )
    require(result.returncode == 0, "Native conformance preflight command failed")
    return result.stdout if capture else None


def verify_release(
    manifest: Path, checksums: Path, revision: str, image: str, *, runner=subprocess.run
) -> dict[str, Any]:
    """Reuse authoritative release inputs plus the existing GitHub attestation trust."""
    try:
        plan = RELEASE["validate_release_inputs"](
            manifest, checksums, expected_ui_revision=revision
        )
        require(
            plan["images"]["services"]["reference"] == image,
            "Native image differs from the authenticated release",
        )
        _run(
            [
                "gh",
                "attestation",
                "verify",
                str(manifest.resolve()),
                "--repo",
                "ElevenID/marty-ui",
            ],
            runner=runner,
        )
        require(
            RELEASE["validate_release_inputs"](
                manifest, checksums, expected_ui_revision=revision
            )
            == plan,
            "Release inputs changed during attestation verification",
        )
        source = _run(
            ["git", "show", f"{revision}:{CAPABILITY_PATH}"],
            runner=runner,
            capture=True,
        )
        require(
            len(source) <= 2 * 1024 * 1024, "Native coverage source exceeds its bound"
        )
        validate_capabilities(json.loads(source))
        return plan
    except (
        OSError,
        subprocess.SubprocessError,
        RELEASE["OfficialReleaseError"],
        json.JSONDecodeError,
    ):
        raise ValueError("Native release qualification failed") from None


def probe_image(
    image: str, project: str, *, plan: dict[str, Any] | None, runner=subprocess.run
) -> None:
    """Executable/linker preflight, NOT route/feature acceptance. No app launch."""
    owner = uuid.uuid4().hex
    name = f"{project}-native-probe-{owner}"
    created = None
    creation_attempted = False
    try:
        records = json.loads(
            _run(["docker", "image", "inspect", image], runner=runner, capture=True)
        )
        require(
            isinstance(records, list) and len(records) == 1,
            "Native artifact inspection is ambiguous",
        )
        record = records[0]
        require(record.get("Os") == "linux", "Native artifact platform is incompatible")
        if plan is not None:
            labels = record["Config"]["Labels"]
            require(
                image in record["RepoDigests"],
                "Native artifact digest is not the configured digest",
            )
            require(
                labels.get("org.opencontainers.image.source")
                == "https://github.com/ElevenID/marty-ui",
                "Native artifact source label is incompatible",
            )
            require(
                labels.get("org.opencontainers.image.revision") == plan["marty_ui_sha"]
                and labels.get("org.opencontainers.image.version")
                == plan["release_version"],
                "Native artifact labels differ from the authenticated release",
            )
        creation_attempted = True
        returned_id = _run(
            [
                "docker",
                "create",
                "--name",
                name,
                "--label",
                f"marty.conformance.native-probe={owner}",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--entrypoint",
                "/bin/sh",
                image,
                "-ec",
                'test -x /usr/local/bin/marty-issuance-service; test -x /app/services/entrypoint.sh; native_linkage=$(ldd /usr/local/bin/marty-issuance-service); case "$native_linkage" in *"not found"*) exit 1;; esac',
            ],
            runner=runner,
            capture=True,
        ).strip()
        require(
            re.fullmatch(r"[0-9a-f]{64}", returned_id) is not None,
            "Native probe ownership is ambiguous",
        )
        created = returned_id
        _run(["docker", "start", "--attach", created], runner=runner)
    except (
        OSError,
        subprocess.SubprocessError,
        KeyError,
        TypeError,
        AttributeError,
        json.JSONDecodeError,
    ):
        raise ValueError("Native executable preflight failed") from None
    finally:
        # Resolve the unique label even if create timed out before returning its
        # ID. Never remove a name, an image, a project or an unverified ID.
        inspection = runner(
            ["docker", "container", "inspect", name],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
            check=False,
        )
        if inspection.returncode == 0:
            try:
                rows = json.loads(inspection.stdout)
                require(
                    isinstance(rows, list)
                    and len(rows) == 1
                    and rows[0]["Config"]["Labels"].get(
                        "marty.conformance.native-probe"
                    )
                    == owner,
                    "Native probe ownership verification failed",
                )
                exact_id = rows[0]["Id"]
                require(
                    re.fullmatch(r"[0-9a-f]{64}", exact_id) is not None
                    and (created is None or created == exact_id),
                    "Native probe ID verification failed",
                )
                _run(["docker", "rm", "--force", exact_id], runner=runner)
            except (
                KeyError,
                TypeError,
                AttributeError,
                IndexError,
                json.JSONDecodeError,
            ):
                raise ValueError(
                    "Native probe cleanup could not verify its owner"
                ) from None
        elif creation_attempted:
            raise ValueError(
                "Native probe cleanup could not verify whether creation left an owned container"
            )
