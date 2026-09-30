#!/usr/bin/env python3
"""Bounded HTTPS requests to the owned disposable Gateway Flow surface."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import tempfile
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.passport_disposable_identity import ORGANIZATION_ID, issuer_did

if __package__:
    from .check_passport_supported_compose_ownership import (
        _inspect, _status_origin, docker, verify as verify_ownership,
    )
    from .passport_supported_flow_references import provision_physical_passport_references
    from .passport_supported_flow_start import start_physical_passport_flow
    from .passport_supported_flow_advance import advance_physical_passport_flow
    from .passport_supported_flow_history import read_owned_flow_history
    from .passport_supported_private_bureau_poll import poll_owned_bureau
else:
    from check_passport_supported_compose_ownership import (
        _inspect, _status_origin, docker, verify as verify_ownership,
    )
    from passport_supported_flow_references import provision_physical_passport_references
    from passport_supported_flow_start import start_physical_passport_flow
    from passport_supported_flow_advance import advance_physical_passport_flow
    from passport_supported_flow_history import read_owned_flow_history
    from passport_supported_private_bureau_poll import poll_owned_bureau


TEST_KEY = re.compile(r"mk_test_[A-Za-z0-9]{43}\n\Z")
OPERATOR_ROUTES = re.compile(
    r"\A/v1/(?:credential-templates|application-templates|delivery-destinations|"
    r"flows/(?:definitions|instances))(?:/[0-9a-f-]{36}(?:/(?:activate|validate|advance))?)?\Z"
)
NATIVE_STATUS_ROUTE = re.compile(
    r"\A/v1/passport/applications/[0-9a-f-]{36}/production-status\Z"
)
NATIVE_BATCH_ROUTE = re.compile(
    r"\A/v1/passport/applications(?:/[0-9a-f-]{36}/"
    r"(?:generate-data-groups|generate-sod|submit-personalization|"
    r"production-status|quality-verify|activate))?\Z"
)


class FlowGatewayError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise FlowGatewayError(message)


def _private_key(record: dict[str, Any], operator: bool) -> tuple[Path, str]:
    project = record.get("project")
    _require(isinstance(project, str)
             and project.startswith("marty-passport-acceptance-"),
             "Disposable Gateway project is invalid")
    root = Path(tempfile.gettempdir()) / project
    _require(record.get("disposable_root") == str(root) and root.resolve() == root,
             "Disposable Gateway root is invalid")
    secret_dir = root / "secrets"
    info = secret_dir.lstat()
    _require(stat.S_ISDIR(info.st_mode) and not secret_dir.is_symlink(),
             "Disposable Gateway secrets are invalid")
    if os.name == "posix":
        _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                 "Disposable Gateway secrets are not private")
    key_name = ("passport_acceptance_operator_api_key" if operator
                else "passport_acceptance_api_key")
    key_file = secret_dir / key_name
    ca_file = secret_dir / "workload_identity_ca_cert"
    for path in (key_file, ca_file):
        item = path.lstat()
        _require(stat.S_ISREG(item.st_mode) and not path.is_symlink(),
                 "Disposable Gateway credential file is invalid")
        if os.name == "posix":
            _require(item.st_uid == os.getuid()
                     and stat.S_IMODE(item.st_mode) == (
                         0o600 if path == key_file else 0o644),
                     "Disposable Gateway credential file is not private")
    key = key_file.read_text(encoding="ascii")
    _require(TEST_KEY.fullmatch(key) is not None,
             "Disposable Gateway API key is invalid")
    return ca_file, key.removesuffix("\n")


def owned_gateway_request(
    record: dict[str, Any], surface: str, *, operator: bool,
    expected_port: int,
    passport_write: bool = False,
    inspector: Callable[[list[str]], str] = docker,
    ownership: Callable[..., dict] = verify_ownership,
    opener_factory: Callable[..., Any] = build_opener,
) -> Callable[[str, str, dict[str, Any] | None, dict[str, str]],
              tuple[int, dict[str, Any]]]:
    """Create one scoped client; recheck project ownership before every request."""
    proof = ownership(record, surface, datetime.now(timezone.utc), inspector)
    _require(not (operator and passport_write),
             "Disposable Gateway client mixed operator and passport authority")
    _require(proof.get("live_ownership_verified") is True,
             "Disposable Gateway ownership is unverified")
    try:
        expires = datetime.fromisoformat(record["expires_at"])
    except (KeyError, TypeError, ValueError) as error:
        raise FlowGatewayError("Disposable Gateway lease is invalid") from error
    _require(expires.tzinfo is not None,
             "Disposable Gateway lease is invalid")
    edge_id = record.get("containers", {}).get("edge")
    _require(isinstance(edge_id, str), "Disposable Gateway edge is missing")
    origin = _status_origin(_inspect("container", edge_id, inspector))
    _require(type(expected_port) is int and 1024 <= expected_port <= 65535
             and origin == f"https://localhost:{expected_port}",
             "Disposable Gateway origin is invalid")
    ca_file, key = _private_key(record, operator)
    context = ssl.create_default_context(cafile=str(ca_file))
    opener = opener_factory(ProxyHandler({}), NoRedirect, HTTPSHandler(context=context))

    def request(method: str, path: str, body: dict[str, Any] | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
        allowed = (OPERATOR_ROUTES if operator else
                   NATIVE_BATCH_ROUTE if passport_write else NATIVE_STATUS_ROUTE)
        batch_method = (
            (method == "POST" and path == "/v1/passport/applications")
            or (method == "GET" and path.endswith("/production-status"))
            or (method == "POST" and path.endswith((
                "/generate-data-groups", "/generate-sod", "/submit-personalization",
                "/quality-verify", "/activate")))
        )
        _require(method in ("GET", "POST") and allowed.fullmatch(path) is not None
                 and (not operator or method == "GET" or path.startswith((
                     "/v1/credential-templates", "/v1/application-templates",
                     "/v1/delivery-destinations", "/v1/flows/")))
                 and (batch_method if passport_write else operator or method == "GET"),
                 "Disposable Gateway route escaped scope")
        now = datetime.now(timezone.utc)
        _require(now < expires - timedelta(minutes=10),
                 "Disposable Gateway teardown budget is exhausted")
        proof = ownership(record, surface, now, inspector)
        _require(proof.get("live_ownership_verified") is True,
                 "Disposable Gateway ownership changed")
        extra = headers or {}
        _require(set(extra).issubset({"idempotency-key"})
                 and all(isinstance(value, str) and value for value in extra.values()),
                 "Disposable Gateway header escaped scope")
        request_headers = {"Accept": "application/json", "Cache-Control": "no-cache",
                           "x-api-key": key, **extra}
        encoded = None
        if body is not None:
            request_headers["Content-Type"] = "application/json"
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        url = origin + path
        try:
            with opener.open(Request(url, data=encoded, headers=request_headers,
                                     method=method), timeout=30) as response:
                _require(response.geturl() == url,
                         "Disposable Gateway request redirected")
                raw = response.read(65537)
                _require(len(raw) <= 65536,
                         "Disposable Gateway response is oversized")
                payload = json.loads(raw)
                _require(isinstance(payload, dict),
                         "Disposable Gateway response is invalid")
                return response.status, payload
        except HTTPError as error:
            return error.code, {}
        except (OSError, URLError, ValueError, ssl.SSLError) as error:
            raise FlowGatewayError("Disposable Gateway request failed") from error

    return request


def exercise_owned_flow(
    record: dict[str, Any], surface: str, gateway_port: int, run_id: str, *,
    restart: Callable[[], bool],
    dsc_der_sha256: str, dsc_pem_wire_sha256: str,
    batch_state_path: Path, batch_deadline: datetime,
    inspector: Callable[[list[str]], str] = docker,
    request_factory: Callable[..., Any] = owned_gateway_request,
    bureau_poll: Callable[..., tuple[int, dict[str, Any]]] = poll_owned_bureau,
    history_reader: Callable[..., dict[str, Any]] = read_owned_flow_history,
    advance: Callable[..., dict[str, Any]] = advance_physical_passport_flow,
    batch_probe: Callable[..., tuple[str, dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Prove one complete same-job Rust Flow, then return public digests only."""
    _require(isinstance(run_id, str) and run_id.isascii() and run_id.isdigit()
             and 1 <= len(run_id) <= 20,
             "Disposable Flow run ID is invalid")
    operator = request_factory(record, surface, operator=True,
                               expected_port=gateway_port, inspector=inspector)
    native = request_factory(record, surface, operator=False,
                             expected_port=gateway_port, inspector=inspector)
    name = f"Disposable passport {run_id}"
    references = provision_physical_passport_references(
        operator, ORGANIZATION_ID, name, issuer_did(gateway_port),
        f"passport-{run_id}-application-template",
    )
    physical = {
        "country_code": "USA", "document_type": "TD3",
        "applicant": {"name": "Synthetic Passport Applicant"},
        "mrz": {"line_1": "P<USASYNTHETIC<<APPLICANT", "line_2": "1234567890USA"},
        "data_groups": {"DG1": "YQ==", "DG2": "Yg=="},
    }
    started = start_physical_passport_flow(
        lambda method, path, body: operator(method, path, body, {}),
        ORGANIZATION_ID, name + " flow", references, physical,
        lambda method, path, body: native(method, path, body, {}),
    )
    if batch_probe is None:
        if __package__:
            from .passport_supported_native_batch import exercise_owned_native_batch
        else:
            from passport_supported_native_batch import exercise_owned_native_batch
        batch_probe = exercise_owned_native_batch
    batch_receipt: dict[str, Any] | None = None

    def before_submit(selected: dict[str, str], sod_sha256: str) -> str:
        nonlocal batch_receipt
        _require(selected == started and batch_receipt is None,
                 "Disposable selected Flow job changed before native batch")
        application = {
            "organization_id": ORGANIZATION_ID,
            "issuer_did": issuer_did(gateway_port),
            "application_template_id": references["application_template_id"],
            "credential_template_id": references["credential_template_id"],
            "delivery_destination_profile_id": references["delivery_destination_profile_id"],
        }
        selected_bureau, proof = batch_probe(
            record, surface, gateway_port, application, physical,
            started["flow_instance_id"], started["application_id"],
            started["native_job_id"], sod_sha256,
            dsc_der_sha256, dsc_pem_wire_sha256,
            batch_state_path, batch_deadline, inspector=inspector)
        _require(isinstance(selected_bureau, str),
                 "Disposable selected Flow batch job is invalid")
        batch_proof = proof.get("batch") if isinstance(proof, dict) else None
        evidence = batch_proof.get("evidence") if isinstance(batch_proof, dict) else None
        final_preflight = proof.get("final_native_preflight") if isinstance(proof, dict) else None
        _require(isinstance(evidence, dict)
                 and batch_proof.get("verified") is True
                 and evidence.get("selected_flow_in_two_job_batch") is True
                 and evidence.get("first_accepted_material_verified") is True
                 and evidence.get("companion_native_completed") is True
                 and final_preflight == {
                     "native_container_id": record["containers"]["issuance-native"],
                     "native_batch_preflight_verified": True,
                 }, "Disposable selected Flow batch proof is incomplete")
        batch_receipt = {
            **proof,
            "selected_source_job_sha256": hashlib.sha256(
                started["native_job_id"].encode()).hexdigest(),
            "selected_bureau_job_sha256": hashlib.sha256(
                selected_bureau.encode()).hexdigest(),
            "dsc_der_sha256": dsc_der_sha256,
        }
        return selected_bureau
    execution = advance(
        lambda method, path, body: operator(method, path, body, {}),
        lambda method, path, body: native(method, path, body, {}),
        lambda bureau_job_id: bureau_poll(
            record, surface, bureau_job_id, inspector=inspector),
        lambda instance_id, definition_id: history_reader(
            record, surface, instance_id, definition_id, inspector=inspector),
        ORGANIZATION_ID, references, started, issuer_did(gateway_port),
        restart=restart, before_submit=before_submit,
    )
    _require(isinstance(execution, dict)
             and execution.get("flow_step_count") == 9
             and execution.get("native_effect_count") == 6
             and execution.get("durable_history_verified") is True
             and execution.get("restart_resume_verified") is True
             and isinstance(execution.get("bureau_job_id"), str)
             and isinstance(batch_receipt, dict)
             and batch_receipt["selected_bureau_job_sha256"]
             == hashlib.sha256(execution["bureau_job_id"].encode()).hexdigest(),
             "Disposable Flow execution proof is incomplete")
    bureau_job_id = execution.pop("bureau_job_id")
    return {
        "references": {f"{name}_sha256": hashlib.sha256(value.encode()).hexdigest()
                       for name, value in references.items()},
        "flow": {f"{name}_sha256": hashlib.sha256(value.encode()).hexdigest()
                 for name, value in started.items()},
        "batch": batch_receipt,
        "execution": {
            "nine_steps_verified": True,
            "six_native_effects_verified": True,
            "durable_history_verified": True,
            "restart_resume_verified": True,
            "signed_callback_receipt_sha256": execution["signed_callback_receipt_sha256"],
            "sod_sha256": execution["sod_sha256"],
            "bureau_job_id_sha256": hashlib.sha256(bureau_job_id.encode()).hexdigest(),
        },
    }
