#!/usr/bin/env python3
"""Set up a synthetic certificate chain inside an attested disposable project.

This is a private fixture setup step after the protected plan, release, model,
empty-project and OpenBao gates. It uses the released migrations image on the
project-only network. Direct Signing Keys setup does not prove the public
Gateway's human operator ceremony; beta acceptance must prove that separately.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.passport_disposable_identity import ORGANIZATION_ID, issuer_did

if __package__:
    from .check_passport_supported_compose_ownership import _inspect, _labels
    from .check_passport_supported_rust_model import PROJECT
    from .probe_passport_beta_chain import exercise_with_authorities
    from .verify_passport_beta_issuer_profiles import (
        resolve_in_container, sign_in_container, verify_live_signatures,
    )
else:
    from check_passport_supported_compose_ownership import _inspect, _labels
    from check_passport_supported_rust_model import PROJECT
    from probe_passport_beta_chain import exercise_with_authorities
    from verify_passport_beta_issuer_profiles import (
        resolve_in_container, sign_in_container, verify_live_signatures,
    )


IDENTITY_ROUTE = "/v1/signing-keys/issuer-identities"
ROUTES = frozenset({
    IDENTITY_ROUTE,
    "/v1/signing-keys/issuer-identities/csca-self-signed-certificate",
    "/v1/signing-keys/issuer-identities/dsc-certificate",
})
KEY = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[0-9a-f]{64}\Z")
MIGRATIONS_IMAGE = re.compile(
    r"ghcr\.io/elevenid/marty-ui-oss/migrations@sha256:[0-9a-f]{64}\Z"
)
SERVICES_IMAGE = re.compile(
    r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\Z"
)
_POST_SCRIPT = r'''
import json, sys
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None

payload = json.load(sys.stdin)
headers = {"content-type": "application/json", "accept": "application/json"}
if payload["authority"]:
    headers["x-api-key"] = payload["authority"]
    headers["x-user-id"] = payload["actor"]
request = Request(
    "http://127.0.0.1:8017" + payload["path"] +
    "?organization_id=" + payload["organization_id"],
    data=json.dumps(payload["body"], separators=(",", ":")).encode(),
    headers=headers,
    method="POST",
)
try:
    with build_opener(ProxyHandler({}), NoRedirect).open(request, timeout=20) as response:
        status, body = response.status, response.read(131073)
except HTTPError as error:
    status, body = error.code, error.read(131073)
if len(body) > 131072:
    sys.exit(2)
result = json.loads(body)
if not isinstance(result, dict):
    sys.exit(2)
sys.stdout.write(json.dumps({"status": status, "body": result}))
'''


class DisposableCeremonyError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DisposableCeremonyError(message)


def _operator_key(secret_dir: Path, name: str) -> str:
    path = secret_dir / name
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
             and (os.name != "posix" or info.st_uid == os.getuid()),
             "Disposable operator authority file is invalid")
    value = path.read_text(encoding="ascii")
    _require(KEY.fullmatch(value) is not None,
             "Disposable operator authority is invalid")
    return value


def _local_docker_env() -> dict[str, str]:
    environment = os.environ.copy()
    environment["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        environment.pop(name, None)
    return environment


def _local_inspect(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["docker", *args], env=_local_docker_env(), capture_output=True,
            text=True, timeout=25, check=True,
        )
        _require(len(result.stdout) <= 1024 * 1024,
                 "Disposable Docker inspection is oversized")
        return result.stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise DisposableCeremonyError("Disposable Docker inspection failed") from error


def verified_signer_id(
    plan: dict[str, Any], inspect: Callable[[list[str]], str] = _local_inspect,
) -> str:
    """Bind the helper to one running, owned signer container and private network."""
    project = plan["project"]
    match = PROJECT.fullmatch(project)
    _require(match is not None
             and match.group(1) == plan.get("surface")
             and plan.get("surface") in {"base", "selfhost"},
             "Disposable certificate project is invalid")
    ids = inspect(["ps", "-q", "--no-trunc", "--filter",
                   f"label=com.docker.compose.project={project}", "--filter",
                   "label=com.docker.compose.service=signing-keys"]).split()
    _require(len(ids) == 1 and IDENTIFIER.fullmatch(ids[0]) is not None,
             "Disposable Signing Keys container is ambiguous")
    signer = _inspect("container", ids[0], inspect)
    config = signer.get("Config")
    state = signer.get("State")
    _require(signer.get("Id") == ids[0] and isinstance(config, dict)
             and isinstance(state, dict) and state.get("Running") is True
             and isinstance(state.get("Health"), dict)
             and state["Health"].get("Status") == "healthy",
             "Disposable Signing Keys container is not healthy")
    _labels(config.get("Labels"), plan, project)
    _require(config["Labels"].get("com.docker.compose.service") == "signing-keys"
             and config.get("Image") == plan.get("services_reference"),
             "Disposable Signing Keys release identity changed")
    environment = config.get("Env")
    _require(isinstance(environment, list) and all(isinstance(item, str)
             for item in environment)
             and "ENVIRONMENT=beta" in environment
             and "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED=true" in environment
             and "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE=/run/secrets/dsc_issue_gateway_key"
             in environment
             and "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE=/run/secrets/csca_issue_gateway_key"
             in environment,
             "Disposable Signing Keys ceremony phase is absent")
    network_settings = signer.get("NetworkSettings")
    networks = (network_settings.get("Networks")
                if isinstance(network_settings, dict) else None)
    name = f"{project}_private"
    _require(isinstance(networks, dict) and set(networks) == {name}
             and isinstance(networks[name], dict),
             "Disposable signer network is not isolated")
    network_id = networks[name].get("NetworkID")
    _require(isinstance(network_id, str)
             and IDENTIFIER.fullmatch(network_id) is not None,
             "Disposable signer network identity is invalid")
    network = _inspect("network", network_id, inspect)
    _labels(network.get("Labels"), plan, project)
    _require(network.get("Id") == network_id and network.get("Name") == name
             and network.get("Internal") is True and network.get("Driver") == "bridge",
             "Disposable signer network ownership changed")
    return ids[0]


def ceremony_plan(plan: dict[str, Any], root: Path, gateway_port: int,
                  *, now: datetime | None = None) -> tuple[dict[str, Any], str, str]:
    """Bind test certificate inputs to the exact selfhost plan and staged root."""
    project = plan.get("project")
    match = PROJECT.fullmatch(project) if isinstance(project, str) else None
    _require(match is not None and match.group(1) == plan.get("surface")
             and plan.get("surface") in {"base", "selfhost"}
             and plan.get("schema") == "marty.passport-supported-provisioning-plan/v1"
             and plan.get("status") == "blocked", "Disposable ceremony plan is invalid")
    run_id = plan.get("run_id")
    _require(isinstance(run_id, str) and re.fullmatch(r"[1-9][0-9]{0,19}", run_id)
             is not None and type(gateway_port) is int
             and 1024 <= gateway_port <= 65535,
             "Disposable ceremony run or Gateway port is invalid")
    _require(MIGRATIONS_IMAGE.fullmatch(str(plan.get("migrations_reference"))) is not None,
             "Disposable ceremony image is not the released migrations image")
    _require(re.fullmatch(r"[0-9a-f]{40}", str(plan.get("source_commit"))) is not None
             and SERVICES_IMAGE.fullmatch(str(plan.get("services_reference"))) is not None,
             "Disposable ceremony source or services image is invalid")
    labels = plan.get("owner_labels")
    _require(isinstance(labels, dict) and labels == {
        "com.marty.passport.acceptance.owner": "supported-consumer",
        "com.marty.passport.acceptance.run-id": run_id,
        "com.marty.passport.acceptance.source-commit": plan.get("source_commit"),
        "com.marty.passport.acceptance.services-image": plan.get("services_reference"),
    }, "Disposable ceremony ownership differs from the plan")
    try:
        expires = datetime.fromisoformat(plan["expires_at"])
    except (KeyError, TypeError, ValueError) as error:
        raise DisposableCeremonyError("Disposable ceremony lease is invalid") from error
    current = now or datetime.now(timezone.utc)
    _require(current.tzinfo is not None and expires.tzinfo is not None
             and current < expires, "Disposable ceremony lease expired")
    expected_root = Path(tempfile.gettempdir()) / project
    _require(root == expected_root and root.is_absolute()
             and not root.is_symlink() and root.resolve() == root,
             "Disposable ceremony root is not project-owned")
    root_info = root.lstat()
    _require(stat.S_ISDIR(root_info.st_mode)
             and (os.name != "posix" or
                  (root_info.st_uid == os.getuid()
                   and stat.S_IMODE(root_info.st_mode) == 0o700)),
             "Disposable ceremony root is not private")
    env_file = root / "acceptance.env"
    _require(env_file.is_file() and not env_file.is_symlink()
             and env_file.read_text(encoding="ascii").splitlines().count(
                 f"PASSPORT_ACCEPTANCE_GATEWAY_PORT={gateway_port}") == 1,
             "Disposable ceremony port differs from staged Compose")
    secrets = root / "secrets"
    info = secrets.lstat()
    _require(stat.S_ISDIR(info.st_mode) and not secrets.is_symlink()
             and secrets.resolve() == secrets
             and (os.name != "posix" or
                  (info.st_uid == os.getuid()
                   and stat.S_IMODE(info.st_mode) == 0o700)),
             "Disposable ceremony secret root is invalid")
    csca_key = _operator_key(secrets, "csca_issue_gateway_key")
    dsc_key = _operator_key(secrets, "dsc_issue_gateway_key")
    internal_key = _operator_key(secrets, "signing_keys_internal_api_key")
    _require(len({csca_key, dsc_key, internal_key}) == 3,
             "Disposable certificate authorities are not distinct")
    did = issuer_did(gateway_port)
    certificate_id = f"csca-disposable-{run_id}"
    result = {
        "organization_id": ORGANIZATION_ID,
        "csca": {"issuer_did": did, "certificate_id": certificate_id,
                 "credential_format": "ICAO_EMRTD", "country": "US",
                 "organization": "Marty Disposable", "common_name": "Marty Disposable CSCA",
                 "validity_days": 365},
        "dsc": {"dsc_issuer_did": did, "csca_issuer_did": did,
                "csca_certificate_id": certificate_id,
                "credential_format": "ICAO_EMRTD", "country": "US",
                "organization": "Marty Disposable", "common_name": "Marty Disposable DSC",
                "validity_days": 30, "idempotency_key": f"dsc-disposable-{run_id}"},
    }
    return result, csca_key, dsc_key


def _private_post(
    plan: dict[str, Any], path: str, body: dict[str, Any], authority: str,
    signer_id: str,
    *, run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[int, dict[str, Any]]:
    _require(path in ROUTES
             and (authority == "" if path == IDENTITY_ROUTE
                  else KEY.fullmatch(authority) is not None)
             and body.get("organization_id") == ORGANIZATION_ID,
             "Disposable certificate request escaped its project scope")
    project = plan["project"]
    _require(PROJECT.fullmatch(project) is not None
             and MIGRATIONS_IMAGE.fullmatch(plan["migrations_reference"]) is not None
             and IDENTIFIER.fullmatch(signer_id) is not None,
             "Disposable certificate project or image is invalid")
    labels = {"com.docker.compose.project": project,
              "com.docker.compose.service": "passport-certificate-bootstrap",
              **plan["owner_labels"]}
    command = ["docker", "run", "--rm", "--name",
               f"{project}-passport-certificate-bootstrap-1",
               "--pull", "never", "--interactive",
               "--read-only", "--cap-drop", "ALL", "--security-opt",
               "no-new-privileges", "--network", f"container:{signer_id}",
               *(argument for key, value in sorted(labels.items())
                 for argument in ("--label", f"{key}={value}")),
               "--entrypoint", "python3", plan["migrations_reference"],
               "-c", _POST_SCRIPT]
    payload = json.dumps({"path": path, "body": body, "authority": authority,
                          "organization_id": ORGANIZATION_ID,
                          "actor": f"disposable-ceremony-{plan['run_id']}"})
    try:
        result = run(command, input=payload, env=_local_docker_env(),
                     text=True, capture_output=True,
                     timeout=45, check=False)
        _require(result.returncode == 0 and len(result.stdout) <= 131072,
                 "Disposable certificate request failed")
        response = json.loads(result.stdout)
        _require(isinstance(response, dict) and set(response) == {"status", "body"}
                 and type(response["status"]) is int
                 and isinstance(response["body"], dict),
                 "Disposable certificate response is invalid")
        return response["status"], response["body"]
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise DisposableCeremonyError("Disposable certificate request failed") from error


def bootstrap_certificate_chain(
    plan: dict[str, Any], root: Path, gateway_port: int, *,
    now: datetime | None = None,
    inspect: Callable[[list[str]], str] = _local_inspect,
    request: Callable[[dict[str, Any], str, dict[str, Any], str, str],
                      tuple[int, dict[str, Any]]] = _private_post,
    profile_resolver: Callable[[str, str, str, str], dict[str, Any]] = resolve_in_container,
    profile_signer: Callable[[str, str, str, str, bytes], dict[str, Any]] = sign_in_container,
    profile_verifier: Callable[..., dict[str, Any]] = verify_live_signatures,
    on_csca_material: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Issue the chain and prove both selected managed keys without exporting refs."""
    chain, csca_key, dsc_key = ceremony_plan(plan, root, gateway_port, now=now)
    signer_id = verified_signer_id(plan, inspect)
    did = chain["csca"]["issuer_did"]
    for purpose in ("csca", "x509_doc_signer"):
        identity = {"organization_id": ORGANIZATION_ID, "issuer_did": did,
                    "key_purpose": purpose, "credential_format": "ICAO_EMRTD",
                    "algorithm": "ES256"}
        status, response = request(plan, IDENTITY_ROUTE, identity, "", signer_id)
        projected = response.get("identity") if isinstance(response, dict) else None
        _require(status == 200 and isinstance(projected, dict)
                 and all(projected.get(field) == identity[field]
                         for field in ("issuer_did", "key_purpose",
                                       "credential_format", "algorithm"))
                 and projected.get("status") == "active",
                 "Disposable managed passport profile was not provisioned")
    csca_material: list[str] = []
    def capture_csca(pem: str) -> None:
        csca_material.append(pem)
        if on_csca_material is not None:
            on_csca_material(pem)

    result = exercise_with_authorities(
        chain, csca_key, dsc_key,
        request=lambda path, body, authority: request(
            plan, path, body, authority, signer_id),
        on_csca_material=capture_csca,
    )
    _require(len(csca_material) == 1 and "BEGIN CERTIFICATE" in csca_material[0],
             "Disposable managed CSCA material is unavailable")
    csca_resolution = profile_resolver(signer_id, ORGANIZATION_ID, did, "csca")
    dsc_resolution = profile_resolver(signer_id, ORGANIZATION_ID, did, "x509_doc_signer")
    internal_key = _operator_key(root / "secrets", "signing_keys_internal_api_key")
    profile_proof = profile_verifier(
        ORGANIZATION_ID, did, did, csca_resolution, dsc_resolution,
        result["evidence"], csca_material[0], internal_key,
        signer=lambda org, issuer, purpose, challenge: profile_signer(
            signer_id, org, issuer, purpose, challenge),
    )
    _require(isinstance(profile_proof, dict)
             and profile_proof.get("managed_kms_custody_verified") is True
             and profile_proof.get("chain_verified") is True
             and all(isinstance(profile_proof.get(field), str)
                     and KEY.fullmatch(profile_proof[field]) is not None
                     for field in ("csca_issuer_profile_commitment",
                                   "dsc_issuer_profile_commitment"))
             and profile_proof["csca_issuer_profile_commitment"]
             != profile_proof["dsc_issuer_profile_commitment"],
             "Disposable managed issuer proof is incomplete")
    return {"schema": "marty.passport-supported-disposable-certificate-setup/v1",
            "status": "setup_only", "gateway_operator_authorization_verified": False,
            "project": plan["project"], "source_commit": plan["source_commit"],
            "evidence": result["evidence"] | profile_proof}


def recheck_current_managed_signer(
    container_id: str, root: Path, gateway_port: int, certificate: dict[str, Any],
    csca_pem: str, *,
    profile_resolver: Callable[[str, str, str, str], dict[str, Any]] = resolve_in_container,
    profile_signer: Callable[[str, str, str, str, bytes], dict[str, Any]] = sign_in_container,
    profile_verifier: Callable[..., dict[str, Any]] = verify_live_signatures,
) -> dict[str, Any]:
    """Bind ceremony proof to the final Signing Keys container after recreation."""
    evidence = certificate.get("evidence") if isinstance(certificate, dict) else None
    _require(isinstance(container_id, str) and IDENTIFIER.fullmatch(container_id) is not None
             and isinstance(evidence, dict)
             and isinstance(csca_pem, str) and "BEGIN CERTIFICATE" in csca_pem,
             "Current disposable managed signer input is invalid")
    did = issuer_did(gateway_port)
    csca_resolution = profile_resolver(container_id, ORGANIZATION_ID, did, "csca")
    dsc_resolution = profile_resolver(container_id, ORGANIZATION_ID, did, "x509_doc_signer")
    key = _operator_key(root / "secrets", "signing_keys_internal_api_key")
    proof = profile_verifier(
        ORGANIZATION_ID, did, did, csca_resolution, dsc_resolution,
        evidence, csca_pem, key,
        signer=lambda org, issuer, purpose, challenge: profile_signer(
            container_id, org, issuer, purpose, challenge),
    )
    _require(isinstance(proof, dict)
             and proof.get("managed_kms_custody_verified") is True
             and proof.get("chain_verified") is True
             and all(proof.get(field) == evidence.get(field)
                     and isinstance(proof.get(field), str)
                     and KEY.fullmatch(proof[field]) is not None
                     for field in ("csca_issuer_profile_commitment",
                                   "dsc_issuer_profile_commitment")),
             "Current managed signer differs from the issued certificate chain")
    return {"signing_keys_container_id": container_id, **proof}
