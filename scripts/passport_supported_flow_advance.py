#!/usr/bin/env python3
"""Prove nine durable physical-passport Flow advances on one native job."""

from __future__ import annotations

import re
import time
from typing import Any, Callable
from uuid import UUID

if __package__:
    from .passport_supported_flow_start import STEPS, _job
else:
    from passport_supported_flow_start import STEPS, _job


Request = Callable[[str, str, dict[str, Any] | None], tuple[int, dict[str, Any]]]
PrivatePoll = Callable[[str], tuple[int, dict[str, Any]]]
HistoryRead = Callable[[str, str], dict[str, Any]]
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SIDE_EFFECTS = {
    "generate_data_groups": "DATA_GENERATED",
    "sign_sod": "SOD_SIGNED",
    "quality_verify": "READY_FOR_ACTIVATION",
    "activate_credential": "ACTIVE",
}


class FlowAdvanceError(ValueError):
    pass


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise FlowAdvanceError(message)


def _uuid(value: Any) -> str:
    _require(isinstance(value, str), "Flow job ID is missing")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as error:
        raise FlowAdvanceError("Flow job ID is invalid") from error
    _require(str(parsed) == value, "Flow job ID is not canonical")
    return value


def _read(request: Request, path: str) -> dict[str, Any]:
    status, value = request("GET", path, None)
    _require(status == 200 and isinstance(value, dict),
             "Flow or native job read failed")
    return value


def _bound_job(
    value: dict[str, Any], organization_id: str, started: dict[str, str],
    references: dict[str, str], issuer_did: str,
) -> dict[str, Any]:
    _job(value, organization_id, started["flow_instance_id"], references,
         {"country_code": "USA", "document_type": "TD3"},
         started["application_id"], started["native_job_id"])
    _require(value.get("issuer_did") == issuer_did,
             "Flow job changed managed issuer")
    return value


def _instance(
    value: dict[str, Any], organization_id: str, started: dict[str, str],
    references: dict[str, str], issuer_did: str, completed: int,
) -> dict[str, Any]:
    expected_status = "COMPLETED" if completed == len(STEPS) else "IN_PROGRESS"
    expected_step = STEPS[completed] if completed < len(STEPS) else STEPS[-1]
    expected_index = min(completed, len(STEPS) - 1)
    _require(value.get("id") == started["flow_instance_id"]
             and value.get("organization_id") == organization_id
             and value.get("flow_id") == started["flow_definition_id"]
             and value.get("flow_type") == "physical_document_issuance"
             and value.get("status") == expected_status
             and value.get("current_step") == expected_step
             and value.get("current_step_index") == expected_index,
             "Flow transition or identity drifted")
    context = value.get("context_data")
    results = value.get("step_results")
    _require(isinstance(context, dict) and isinstance(results, dict)
             and set(results) == set(STEPS[:completed])
             and all(isinstance(results[step], dict)
                     and results[step].get("result") == "success"
                     and isinstance(results[step].get("completed_at"), str)
                     for step in STEPS[:completed]),
             "Flow step results drifted")
    job = context.get("physical_document_job")
    _require(isinstance(job, dict)
             and context.get("application_id") == started["application_id"],
             "Flow native job context is missing")
    return _bound_job(job, organization_id, started, references, issuer_did)


def _history(
    value: dict[str, Any], organization_id: str, started: dict[str, str],
) -> None:
    _require(value.get("organization_id") == organization_id
             and value.get("flow_definition_id") == started["flow_definition_id"]
             and value.get("status") == "completed",
             "Durable Flow row changed identity")
    steps = value.get("steps")
    entries = value.get("step_history")
    _require(isinstance(steps, list) and isinstance(entries, list)
             and len(steps) == len(STEPS) and len(entries) == len(STEPS),
             "Durable Flow history is incomplete")
    expected_ids = []
    for index, step in enumerate(steps):
        _require(isinstance(step, dict)
                 and step.get("config", {}).get("protocol_step") == STEPS[index],
                 "Durable Flow definition step drifted")
        expected_ids.append(_uuid(step.get("id")))
    _require(len(set(expected_ids)) == len(STEPS),
             "Durable Flow definition duplicated a step")
    for index, entry in enumerate(entries):
        _require(isinstance(entry, dict)
                 and entry.get("step_id") == expected_ids[index]
                 and entry.get("status") == "entered"
                 and entry.get("result") == "success"
                 and isinstance(entry.get("entered_at"), str)
                 and isinstance(entry.get("completed_at"), str),
                 "Durable Flow step history is out of order")


def advance_physical_passport_flow(
    request: Request, native_request: Request, private_poll: PrivatePoll,
    history_read: HistoryRead, organization_id: str,
    references: dict[str, str], started: dict[str, str], issuer_did: str, *,
    max_polls: int = 36, poll_interval_seconds: float = 5,
    sleep: Callable[[float], None] = time.sleep,
    restart: Callable[[], bool] | None = None,
    before_submit: Callable[[dict[str, str], str], str] | None = None,
) -> dict[str, Any]:
    """Require nine transitions, six native effects, one callback, and DB history."""
    _require(1 <= max_polls <= 90 and 0 <= poll_interval_seconds <= 30,
             "Flow callback polling policy is invalid")
    instance_path = f"/v1/flows/instances/{_uuid(started['flow_instance_id'])}"
    application_path = (
        f"/v1/passport/applications/{_uuid(started['application_id'])}/production-status"
    )
    _instance(_read(request, instance_path), organization_id, started,
              references, issuer_did, 0)
    _bound_job(_read(native_request, application_path), organization_id,
               started, references, issuer_did)
    bureau_job_id = None
    callback_receipt = None
    sod_sha256 = None
    restart_verified = False
    batch_bureau_job_id = None
    for index, step in enumerate(STEPS):
        if step == "submit_to_personalization" and before_submit is not None:
            _require(sod_sha256 is not None
                     and (restart is None or restart_verified),
                     "Flow batch ran before signed material or restart proof")
            batch_bureau_job_id = _uuid(before_submit(started, sod_sha256))
        if step == "track_production":
            _require(bureau_job_id is not None,
                     "Flow bureau job is missing before tracking")
            for poll_number in range(max_polls):
                status, private = private_poll(bureau_job_id)
                public = _bound_job(_read(native_request, application_path),
                                    organization_id, started, references, issuer_did)
                receipt = private.get("callback_receipt_sha256") if isinstance(private, dict) else None
                if (status == 200 and isinstance(private, dict)
                    and private.get("status") in ("QUALITY_CHECK", "SHIPPED")
                    and isinstance(receipt, str) and HEX64.fullmatch(receipt)
                    and public.get("bureau_job_id") == bureau_job_id
                    and public.get("status") in ("QUALITY_CHECK", "READY_FOR_ACTIVATION")):
                    callback_receipt = receipt
                    break
                _require(public.get("status") not in ("FAILED", "CANCELLED", "ACTIVE"),
                         "Flow native job failed before signed callback")
                if poll_number + 1 < max_polls:
                    sleep(poll_interval_seconds)
            else:
                raise FlowAdvanceError("Flow same-job signed callback was not observed")
        data = {"passed": True, "failure_codes": []} if step == "quality_verify" else {}
        status, advanced = request("POST", instance_path + "/advance", {
            "step_result": "success", "data": data,
        })
        _require(status == 200 and isinstance(advanced, dict),
                 "Flow advance request failed")
        job = _instance(advanced, organization_id, started, references, issuer_did,
                        index + 1)
        persisted = _read(request, instance_path)
        _instance(persisted, organization_id, started, references, issuer_did,
                  index + 1)
        _require(persisted.get("step_results") == advanced.get("step_results"),
                 "Flow advance did not persist step results")
        native = _bound_job(_read(native_request, application_path), organization_id,
                            started, references, issuer_did)
        expected = SIDE_EFFECTS.get(step)
        if expected:
            _require(job.get("status") == expected and native.get("status") == expected,
                     "Flow native side effect did not persist")
        if step == "sign_sod":
            sod_sha256 = job.get("sod_sha256")
            _require(isinstance(sod_sha256, str) and HEX64.fullmatch(sod_sha256)
                     and job.get("sod_signature_verified") is True,
                     "Flow SOD signature evidence is missing")
            if restart is not None:
                _require(restart() is True, "Owned Rust service restart failed")
                resumed = _read(request, instance_path)
                resumed_job = _instance(resumed, organization_id, started,
                                        references, issuer_did, index + 1)
                resumed_native = _bound_job(
                    _read(native_request, application_path), organization_id,
                    started, references, issuer_did)
                _require(resumed.get("step_results") == persisted.get("step_results")
                         and resumed_job.get("status") == "SOD_SIGNED"
                         and resumed_native.get("status") == "SOD_SIGNED"
                         and resumed_job.get("sod_sha256") == sod_sha256
                         and resumed_job.get("sod_signature_verified") is True,
                         "Flow checkpoint did not survive Rust restart")
                restart_verified = True
        if step == "submit_to_personalization":
            bureau_job_id = _uuid(job.get("bureau_job_id"))
            _require(native.get("bureau_job_id") == bureau_job_id
                     and (batch_bureau_job_id is None
                          or batch_bureau_job_id == bureau_job_id)
                     and job.get("sod_sha256") == sod_sha256
                     and native.get("sod_sha256") == sod_sha256
                     and job.get("sod_signature_verified") is True
                     and native.get("sod_signature_verified") is True
                     and job.get("status") in ("SUBMITTED", "IN_PRODUCTION",
                                               "QUALITY_CHECK", "READY_FOR_ACTIVATION"),
                     "Flow bureau submission changed job")
        if bureau_job_id is not None:
            _require(job.get("bureau_job_id") == bureau_job_id
                     and native.get("bureau_job_id") == bureau_job_id,
                     "Flow bureau job identity drifted")
        if step == "track_production":
            _require(job.get("status") in ("QUALITY_CHECK", "READY_FOR_ACTIVATION")
                     and native.get("status") in ("QUALITY_CHECK", "READY_FOR_ACTIVATION"),
                     "Flow production tracking did not observe callback")
        if step == "quality_verify":
            _require(isinstance(job.get("quality_result"), dict)
                     and job["quality_result"].get("passed") is True,
                     "Flow quality result did not persist")
        if step == "activate_credential":
            _require(isinstance(job.get("completed_at"), str)
                     and bool(job["completed_at"]),
                     "Flow native activation did not persist")
    _require(bureau_job_id is not None and callback_receipt is not None
             and sod_sha256 is not None,
             "Flow native proof is incomplete")
    _history(history_read(started["flow_instance_id"], started["flow_definition_id"]),
             organization_id, started)
    return {"flow_step_count": len(STEPS), "native_effect_count": 6,
            "durable_history_verified": True,
            "restart_resume_verified": restart_verified,
            "signed_callback_receipt_sha256": callback_receipt,
            "bureau_job_id": bureau_job_id, "sod_sha256": sod_sha256}
