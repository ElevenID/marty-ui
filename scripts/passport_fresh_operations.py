"""Compose fresh passport producers without recording or importing prior results.

This is an operation component, not a demo qualification entrypoint. Its caller
must bind protected runtime/fixture custody and observe actual HTTP operations
through the recorder before calling it. Signed release acceptance remains in
run_passport_beta_acceptance; locally built inputs do not assert that gate.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any, Callable

if __package__:
    from . import probe_passport_beta_chain as chain
    from . import probe_passport_beta_selected_flow as flow
    from . import probe_passport_beta_native_batch as batch
    from . import probe_passport_beta_negative_callbacks as negatives
    from .probe_passport_beta_host import beta_material_receipt
else:
    import probe_passport_beta_chain as chain
    import probe_passport_beta_selected_flow as flow
    import probe_passport_beta_native_batch as batch
    import probe_passport_beta_negative_callbacks as negatives
    from probe_passport_beta_host import beta_material_receipt


class FreshOperationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FreshOperationError(message)


def exercise(
    plan: dict[str, Any], *, source_commit: str, stack_manifest_sha256: str,
    csca_session: str, dsc_session: str, flow_session: str, api_key: str,
    service_token: str, operator_token: str, native_container_id: str,
    simulator_container_id: str, private_state_path: Path,
    private_handoff_path: Path, verify_runtime: Callable[[], None],
    chain_probe: Callable[..., dict[str, Any]] = chain.exercise,
    flow_probe: Callable[..., dict[str, Any]] = flow.exercise,
    batch_probe: Callable[..., tuple[str, dict[str, Any]]] = batch.exercise,
    material_receipt: Callable[..., dict[str, Any]] = beta_material_receipt,
    negative_probe: Callable[..., dict[str, Any]] = negatives.exercise,
    on_owned_job: Callable[[str, dict[str, Any]], None] | None = None,
    prepare_selected_flow: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Produce a new Flow/batch and attack that returned job, preserving recovery.

    Injected ports support observed transports and focused contract tests; their
    results are never accepted as imported report inputs. No CLI or qualification
    flag is provided until protected runtime and live-evidence binding exist.
    """
    require(isinstance(plan, dict) and set(plan) == {
        "certificate_plan", "application", "selected_flow"},
        "Fresh passport plan fields are invalid")
    application = plan["application"]
    selected = plan["selected_flow"]
    require(isinstance(application, dict)
            and set(application) == {"organization_id", "issuer_did"}
            and isinstance(selected, dict) and set(selected) == {
                "flow_definition_id", "references", "physical_document"},
            "Fresh passport plan cannot adopt prior jobs or results")
    chain.validate_plan(plan["certificate_plan"])
    chain.validate_sessions(csca_session, dsc_session)
    require(plan["certificate_plan"]["organization_id"] == application["organization_id"]
            and plan["certificate_plan"]["dsc"]["dsc_issuer_did"] == application["issuer_did"],
            "Certificate and Flow issuer identities differ")
    flow.validate_inputs(selected["flow_definition_id"], application["organization_id"],
                         application["issuer_did"], selected["references"],
                         selected["physical_document"], flow_session, api_key,
                         simulator_container_id)
    require(isinstance(source_commit, str) and re.fullmatch(r"[0-9a-f]{40}", source_commit)
            and isinstance(stack_manifest_sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", stack_manifest_sha256)
            and isinstance(native_container_id, str)
            and re.fullmatch(r"[0-9a-f]{64}", native_container_id)
            and all(isinstance(token, str) and len(token) >= 32
                    and not any(c in token for c in "\r\n\0")
                    for token in (service_token, operator_token))
            and service_token != operator_token,
            "Protected passport runtime or separate native authorities are unavailable")
    require(private_state_path.resolve() != private_handoff_path.resolve(),
            "Private passport recovery paths overlap")
    batch.ensure_private_state_available(private_state_path)
    batch.ensure_private_state_available(private_handoff_path)
    fingerprint = flow.selected_plan_commitment(plan, api_key)
    # The caller checks actual images, source, role ownership and custody here,
    # immediately before any production ceremony or Flow mutation.
    verify_runtime()
    require(flow.selected_plan_commitment(plan, api_key) == fingerprint,
            "Passport plan changed during runtime verification")
    dsc: dict[str, str] = {}
    binding: dict[str, Any] = {}
    receipt: dict[str, Any] = {}

    def capture_dsc(der: str, pem: str) -> None:
        require(not dsc and all(isinstance(value, str)
                                and re.fullmatch(r"[0-9a-f]{64}", value)
                                for value in (der, pem)),
                "Fresh certificate material is invalid or repeated")
        dsc.update(der=der, pem=pem)

    chain_result = chain_probe(plan["certificate_plan"], csca_session, dsc_session,
                               on_dsc_material=capture_dsc)
    require(chain_result.get("verified") is True and len(dsc) == 2
            and chain_result.get("evidence", {}).get("dsc_certificate_sha256") == dsc["der"],
            "Fresh governed certificate chain did not verify")
    require(flow.selected_plan_commitment(plan, api_key) == fingerprint,
            "Passport plan changed during certificate operations")
    if prepare_selected_flow:
        prepared = prepare_selected_flow(plan)
        require(flow.selected_plan_commitment(plan, api_key) == fingerprint
                and isinstance(prepared, dict) and set(prepared) == {
                    "flow_definition_id", "references", "physical_document"}
                and prepared["physical_document"] == selected["physical_document"],
                "Owned Flow preparation changed the governed passport plan")
        selected = prepared
        plan = {**plan, "selected_flow": selected}
        flow.validate_inputs(selected["flow_definition_id"], application["organization_id"],
                             application["issuer_did"], selected["references"],
                             selected["physical_document"], flow_session, api_key,
                             simulator_container_id)
        fingerprint = flow.selected_plan_commitment(plan, api_key)

    def bind_batch(instance: str, application_id: str, job: str, sod: str) -> str:
        require(not binding, "Fresh Flow requested more than one native batch")
        bureau, proof = batch_probe(
            {**application, **selected["references"]}, selected["physical_document"], api_key, service_token,
            operator_token, native_container_id, simulator_container_id, instance,
            application_id, job, sod, dsc["der"], dsc["pem"], material_receipt,
            private_state_path, **({"on_owned_job": on_owned_job} if on_owned_job else {}))
        require(proof.get("verified") is True, "Fresh native batch did not verify")
        binding.update(instance=instance, application=application_id, job=job,
                       sod=sod, bureau=bureau, proof=proof)
        return bureau

    def compare(org: str, job: str, bureau: str, sod: str) -> dict[str, Any]:
        require(bool(binding) and not receipt
                and (org, job, bureau, sod) == (application["organization_id"],
                    binding["job"], binding["bureau"], binding["sod"]),
                "Fresh material receipt differs from returned native job")
        result = material_receipt(org, job, bureau, sod, dsc["der"], dsc["pem"],
                                  api_key.encode("utf-8"))
        require(result.get("verified") is True, "Fresh material receipt did not verify")
        receipt.update(result)
        return result

    result = flow_probe(selected["flow_definition_id"], application["organization_id"],
                        application["issuer_did"], selected["references"],
                        selected["physical_document"], flow_session, api_key,
                        simulator_container_id=simulator_container_id,
                        on_signed_sod=bind_batch, on_submission=compare)
    evidence = result.get("evidence", {})
    require(result.get("verified") is True and bool(binding) and bool(receipt)
            and all(evidence.get(field) == value for field, value in {
                "organization_id": application["organization_id"],
                "flow_id": selected["flow_definition_id"],
                "flow_instance_id": binding["instance"], "application_id": binding["application"],
                "job_id": binding["job"], "bureau_job_id": binding["bureau"],
                "sod_sha256": binding["sod"], "terminal_native_status": "ACTIVE",
                "signed_simulator_callback_verified": True,
                "physical_claim": "not_claimed",
            }.items()), "Fresh selected Flow did not bind the returned active job")
    material = receipt.get("evidence", {})
    native = binding["proof"].get("evidence", {})
    require(all(evidence.get(field) == material.get(material_field)
                == native.get(native_field)
                and isinstance(evidence.get(field), str)
                and re.fullmatch(r"[0-9a-f]{64}", evidence[field])
                for field, material_field, native_field in (
                    ("source_job_commitment", "source_job_id_commitment",
                     "selected_source_job_commitment"),
                    ("bureau_job_commitment", "bureau_job_id_commitment",
                     "selected_bureau_job_commitment"))),
            "Fresh Flow, native batch and material receipt commitments differ")
    require(flow.selected_plan_commitment(plan, api_key) == fingerprint,
            "Passport plan changed during fresh operations")
    private = {
        "schema": "marty.passport-beta-demo-private/v1", "source_commit": source_commit,
        "stack_manifest_sha256": stack_manifest_sha256,
        "organization_id": evidence["organization_id"],
        "flow_definition_id": evidence["flow_id"],
        "flow_instance_id": evidence["flow_instance_id"],
        "application_id": evidence["application_id"],
        "source_job_id": evidence["job_id"], "bureau_job_id": evidence["bureau_job_id"],
    }
    batch.write_private_demo_handoff(private_handoff_path, private)
    negative = negative_probe(private, api_key, simulator_container_id, case="both")
    require(negative.get("verified") is True
            and set(negative) == {"schema", "verified", "physical_claim", "unsigned", "foreign"}
            and negative["unsigned"].get("http_status") == 422
            and negative["foreign"].get("http_status") == 404
            and all(negative[lane].get(field) == evidence[field]
                    for lane in ("unsigned", "foreign")
                    for field in ("source_job_commitment", "bureau_job_commitment")),
            "Fresh selected job negative operations did not verify")
    # Keep the private handoff for declared job ownership. Wire-key state may be
    # cleared only after both real denial operations succeeded; failures retain it.
    batch.clear_private_state(private_state_path)
    commitment = hmac.new(api_key.encode(), json.dumps(private, sort_keys=True,
                          separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    return {"schema": "marty.passport-fresh-operations/v1", "operations_verified": True,
            "physical_claim": "not_claimed", "selected_job_commitment": commitment,
            "negative_http_statuses": [422, 404], "private_handoff_retained": True,
            "cleanup_scope": "native_batch_wire_state_only",
            "demo_qualified": False,
            "behaviorAssertions": {
                "managed_csca_dsc_issuer_profiles": True,
                "nine_step_passport_issuance_flow": True,
                "simulator_bureau_job_correlated": True,
                "signed_simulator_callback_verified": True,
                "physical_claim": "not_claimed", "booklet_verified": False,
                "unsigned_or_foreign_callback_denied": True}}
