"""Versioned signed rootless startup and functional/recovery evidence.

These are closed evidence contracts, never a substitute for the installed
assertion owners. A producer cannot turn an incomplete checkpoint into this
report, and startup evidence is never release admission or load qualification.
"""
from __future__ import annotations

import json
import re

import installer_acceptance as legacy

SCHEMA = "elevenid.installer-acceptance/v2"
STARTUP_PROFILE = "rootless-startup-8gib"
FUNCTIONAL_PROFILE = "rootless-functional-recovery-8gib"
MIN_MEMORY_BYTES = 7 * 1024**3
MAX_REPORT_BYTES = 256 * 1024
STARTUP_CASES = ("artifact-verification", "isolated-install", "startup-runtime",
                 "ip-entry-browser", "canonical-origin-routing")
RECOVERY_CASES = ("openbao-static-seal-reboot", "openbao-expired-tls-recovery",
                  "http01-independent-recovery", "long-downtime-credentials",
                  "successive-generation-recovery", "crash-publication-recovery",
                  "paused-reboot-stays-stopped", "security-sealed-reboot-stays-stopped",
                  "raft-backup-restore", "root-retirement-independent-authority",
                  "neighboring-state-preserved")
FUNCTIONAL_CASES = tuple(dict.fromkeys((*legacy.CASES, *STARTUP_CASES, *RECOVERY_CASES)))
require, exact = legacy.require, legacy.exact

# The exact installed owners have not been connected to this signed report
# producer yet. This set is deliberately empty: passing caller-supplied JSON,
# even when it has a plausible schema and a self-consistent digest, cannot add
# an owner or turn a component proof into installed qualification.
IMPLEMENTED_INSTALLED_WRITERS = frozenset()
CASE_CHECKS = {
    "anonymous-download": ("public_release_downloaded_without_credentials", "exact_download_receipts"),
    "artifact-verification": ("all_signatures_verified", "exact_workflow_provenance", "all_payload_digests_verified"),
    "isolated-install": ("new_installation_uuid", "rootless_storage_canary_completed", "no_foreign_resource_adoption"),
    "browser-tls-login": ("public_tls_verified", "browser_authenticated_login", "canonical_cookie_origin"),
    "issue": ("authenticated_issuance", "issued_credential_signature_verified"),
    "present": ("credential_presentation_generated", "challenge_and_audience_bound"),
    "verify": ("presented_credential_verified", "issuer_and_holder_bound"),
    "revoke": ("credential_revocation_recorded", "revocation_observed"),
    "deny": ("revoked_credential_denied", "wrong_audience_denied"),
    "kms-custody": ("openbao_signing_observed", "private_keys_not_exported", "scoped_authentication"),
    "restart-recovery": ("owned_runtime_restarted", "same_cluster", "authenticated_journey_after_restart"),
    "existing-stack-isolation": ("neighbor_baseline_captured", "owned_labels_and_volumes_exact", "neighbor_workload_unchanged"),
    "uninstall-retains-recovery": ("default_uninstall_observed", "recovery_material_retained", "retained_state_recovered"),
    "owned-cleanup": ("exact_owned_resources_removed", "zero_owned_resources_observed", "no_neighbor_deletion"),
    "tampered-artifact-rejected": ("payload_mutation_applied", "verification_refused_before_mutation"),
    "wrong-provenance-rejected": ("wrong_invocation_proof_applied", "verification_refused_before_mutation"),
    "interrupted-download-recovery": ("download_interrupted", "partial_bytes_not_executed", "exact_original_artifact_recovered"),
    "uncertain-provisioning-refused": ("response_lost_after_owned_mutation", "no_blind_replay", "owned_identity_retained"),
    "concurrent-install-refused": ("concurrent_attempt_observed", "exclusive_lock_refused_second_mutator"),
    "partial-cleanup-preserves-recovery": ("cleanup_interrupted", "recovery_files_retained", "resume_preserved_ownership"),
    "failed-public-replay-blocks-channel": ("public_replay_failed", "channel_publish_refused", "prior_channel_unchanged"),
    "stale-promotion-refused": ("stale_admission_observed", "compare_and_swap_refused", "prior_channel_unchanged"),
    "existing-stack-survives-cleanup": ("neighbor_after_cleanup_observed", "neighbor_data_and_workload_unchanged"),
    "startup-runtime": ("exact_selected_runtime_healthy", "verified_local_https", "configured_page_assets_loaded"),
    "ip-entry-browser": ("configured_ip_url_visited", "browser_public_tls_verified", "real_landing_assets_rendered",
                         "raw_ip_url_retained", "no_ip_session_request_or_cookie"),
    "canonical-origin-routing": ("sign_in_uses_canonical_origin", "registration_uses_canonical_origin", "console_uses_canonical_origin"),
    "openbao-static-seal-reboot": ("guest_boot_id_changed", "same_cluster_auto_unsealed", "exact_static_key_retained", "no_init_or_unseal_replay"),
    "openbao-expired-tls-recovery": ("old_network_tls_expired", "scoped_unix_login", "same_key_certificate_replaced", "owned_hup", "verified_network_tls_recovered"),
    "http01-independent-recovery": ("https_unavailable", "exact_http01_response_available", "unknown_host_and_path_refused", "challenge_withdrawn_after_completion"),
    "long-downtime-credentials": ("selected_credentials_expired", "scoped_authorities_recovered", "fresh_generation_selected", "authenticated_journey_recovered"),
    "successive-generation-recovery": ("multiple_successors_selected", "selected_and_rollback_independent", "exact_ancestry_and_native_ids"),
    "crash-publication-recovery": ("publication_interrupted", "same_authorized_attempt_reconciled", "no_duplicate_public_order", "final_selected_runtime_verified"),
    "paused-reboot-stays-stopped": ("paused_intent_durable", "guest_boot_id_changed", "all_owned_runtime_stayed_stopped"),
    "security-sealed-reboot-stays-stopped": ("security_sealed_intent_durable", "bao_memory_stopped", "guest_boot_id_changed", "no_scheduled_restart"),
    "raft-backup-restore": ("source_offline", "ordinary_snapshot_restore", "original_static_key", "same_cluster_keys_and_identities",
                            "selected_and_rollback_credentials", "customer_backup_transport", "installed_image_restore"),
    "root-retirement-independent-authority": ("fresh_application_proof", "fresh_scoped_authorities_proof", "installed_restart_proof",
                                               "installed_restore_proof", "exact_initial_root_rejected", "root_copy_removed", "recovery_key_preserved"),
    "neighboring-state-preserved": ("preexisting_resources_reobserved", "neighbor_configuration_and_data_unchanged", "owned_resources_excluded"),
}

# Each reference is an installed owner output, never a detached Go/Bao fixture.
# Unconnected adapters remain explicit blockers along with their case writers.
CASE_OWNERS = {
    "artifact-verification": ("signed-artifact-verifier",),
    "isolated-install": ("rootless-storage-canary", "native-compose"),
    "startup-runtime": ("deployment-validation", "native-compose", "page-observation"),
    "ip-entry-browser": ("installed-browser",),
    "canonical-origin-routing": ("installed-browser",),
    "browser-tls-login": ("installed-browser", "authenticated-journey"),
    "openbao-static-seal-reboot": ("guest-reboot", "static-seal", "native-compose"),
    "openbao-expired-tls-recovery": ("local-tls-recovery", "native-compose"),
    "http01-independent-recovery": ("http01-observation", "acme-order"),
    "long-downtime-credentials": ("generation-selection", "scoped-authorities", "authenticated-journey"),
    "successive-generation-recovery": ("generation-selection", "scoped-authorities"),
    "crash-publication-recovery": ("generation-selection", "acme-order", "crash-observation"),
    "paused-reboot-stays-stopped": ("lifecycle-intent", "guest-reboot", "native-compose"),
    "security-sealed-reboot-stays-stopped": ("lifecycle-intent", "guest-reboot", "native-compose"),
    "raft-backup-restore": ("installed-restore", "scoped-authorities"),
    "root-retirement-independent-authority": ("root-retirement-application", "root-retirement-scoped-authorities",
                                               "root-retirement-restart", "root-retirement-restore", "root-retirement-completion"),
}
for _case in FUNCTIONAL_CASES:
    CASE_OWNERS.setdefault(_case, ("installed-" + _case,))


def missing_writers(profile):
    return tuple(case for case in cases_for(profile) if case not in IMPLEMENTED_INSTALLED_WRITERS)


def cases_for(profile):
    require(profile in (STARTUP_PROFILE, FUNCTIONAL_PROFILE), "versioned rootless profile differs")
    return STARTUP_CASES if profile == STARTUP_PROFILE else FUNCTIONAL_CASES


def _sha(value):
    require(legacy.matches(value, r"[0-9a-f]{64}"), "qualification evidence digest differs")


def _selection(value, *, required):
    if value is None:
        require(not required, "functional recovery needs selected and rollback generations")
        return
    exact(value, {"current_binding_sha256", "rollback_binding_sha256", "selected_evidence_sha256"}, "qualification selection")
    _sha(value["current_binding_sha256"])
    _sha(value["rollback_binding_sha256"])
    require(value["current_binding_sha256"] != value["rollback_binding_sha256"], "rollback is not independent")
    # Reuse the exact public trust-export grammar; this validates references,
    # not native resource admission or a fresh workload credential proof.
    from installer_acceptance_runner import selected_generation_evidence
    selected_generation_evidence(value["selected_evidence_sha256"])


def validate_case_proof(proof, *, case, scope, selection, observed_at):
    require(case in CASE_CHECKS, "unsupported installed assertion")
    exact(proof, {"schema", "case", "scope", "selection", "started_at", "completed_at", "status", "checks", "native_evidence"}, "installed case proof")
    require(proof["schema"] == f"elevenid.installer-installed-{case}/v1" and proof["case"] == case
            and proof["scope"] == scope and proof["selection"] == selection
            and type(proof["started_at"]) is int and type(proof["completed_at"]) is int
            and scope['authorized_at'] <= proof["started_at"] <= proof["completed_at"] <= observed_at
            and proof["status"] == "passed", "installed case proof scope or result differs")
    checks = proof["checks"]
    exact(checks, set(CASE_CHECKS[case]), "case-specific installed checks")
    require(all(value is True for value in checks.values()), "installed assertion is incomplete")
    exact(proof['native_evidence'], set(CASE_OWNERS[case]), 'installed proof-owner references')
    for owner, reference in proof['native_evidence'].items():
        exact(reference, {'name', 'sha256', 'owner_schema', 'installation_id', 'engine_id', 'operator_sha256',
                          'context_sha256', 'selection', 'started_at', 'completed_at'}, 'typed installed owner reference')
        require(reference['owner_schema'] == f'elevenid.installer-qualification-{owner}/v1'
                and legacy.matches(reference['name'], re.escape(owner)+r'-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json')
                and all(reference[key] == scope[key] for key in ('installation_id','engine_id','operator_sha256','context_sha256'))
                and reference['selection'] == selection
                and type(reference['started_at']) is int and type(reference['completed_at']) is int
                and proof['started_at'] <= reference['started_at'] <= reference['completed_at'] <= proof['completed_at'],
                'native installed owner scope differs')
        _sha(reference['sha256'])
    # A typed reference is still not a proof reader. Opening a new writer here
    # requires its real protected-file adapter, native output schema validation
    # and installed exercise. Until then no caller record can graduate the case.
    require(case in IMPLEMENTED_INSTALLED_WRITERS,
            f'installed assertion owner and native proof adapter unavailable: {case}')


def validate(report: dict, *, inventory_bytes: bytes, source_sha: str,
             release_tag: str, phase: str, run: dict, require_functional=True):
    import installer_release as release
    from installer_host_admission import host_admission, resource_snapshot
    exact(report, {"schema", "repository", "source_sha", "source_ref", "harness_source_sha", "release_tag",
                   "phase", "platform", "inventory_sha256", "workflow", "run_id", "run_attempt",
                   "profile", "authority", "host_observation", "scope", "selection", "cases", "proofs",
                   "neighbor_preservation", "cleanup", "observed_at", "load_characterized"}, "versioned acceptance")
    require(report["schema"] == SCHEMA and report["repository"] == legacy.REPOSITORY
            and report["source_sha"] == source_sha and report["release_tag"] == release_tag
            and report["source_ref"] == "refs/heads/main" and report["phase"] == phase
            and phase in ("staged", "published", "channel") and report["platform"] == "linux/amd64"
            and report["inventory_sha256"] == "sha256:" + release.digest(inventory_bytes)
            and report["workflow"] == legacy.WORKFLOW and report["load_characterized"] is False,
            "versioned acceptance identity or scope differs")
    release.identity(source_sha, release_tag, report["run_id"], report["run_attempt"])
    release.sha(report["harness_source_sha"])
    require(type(run) is dict and type(run.get("repository")) is dict
            and run.get("repository", {}).get("full_name") == legacy.REPOSITORY
            and run.get("path") == legacy.WORKFLOW and run.get("event") == "workflow_dispatch"
            and run.get("head_branch") == "main" and run.get("head_sha") == report["harness_source_sha"]
            and run.get("id") == report["run_id"] and run.get("run_attempt") == report["run_attempt"]
            and run.get("status") == "completed" and run.get("conclusion") == "success",
            "qualification run is not the exact successful main invocation")
    cases = cases_for(report["profile"])
    functional = report["profile"] == FUNCTIONAL_PROFILE
    require(not require_functional or functional, "startup evidence cannot promote a release")
    release.positive(report["observed_at"])
    authority = exact(report["authority"], {"authorization", "controller_consumption",
                       "authenticated_evidence_sha256"}, "qualification authority")
    require(type(authority["authorization"]) is str and type(authority["controller_consumption"]) is str,
            "qualification authority bytes missing")
    auth_raw, receipt_raw = authority["authorization"].encode(), authority["controller_consumption"].encode()
    auth, receipt = release.decode(auth_raw), release.decode(receipt_raw)
    require(auth.get("schema") == release.CANDIDATE_SCHEMA_V2, "rootless qualification needs explicit v2 hosting authority")
    release.validate_controller_consumption(receipt, now=report["observed_at"])
    context = release.candidate_context(auth)
    require(context['phase'] == ('published' if phase == 'channel' else phase)
            and all(context[name] == report[name] for name in ("source_sha", "release_tag", "harness_source_sha", "run_id", "run_attempt")),
            "qualification grant invocation differs")
    require(auth['hosting']['public_entry_origin'] is not None, "IP entry qualification needs an explicitly bound IP alias")
    if functional:
        require(auth['hosting']['certificate_source'] == 'acme' and auth['hosting']['acme_environment'] == 'production'
                and auth['hosting']['staging_trust'] is None,
                "public functional recovery qualification requires production trust")
    release.bind_controller_consumption(receipt_raw, auth_raw, inventory_bytes, expected=context,
        expected_engine=receipt["engine_id"], now=receipt["consumed_at"])
    pins = authority["authenticated_evidence_sha256"]
    release.validate_candidate_evidence(pins)
    require(pins["installer-candidate-authorization.json"] == release.digest(auth_raw)
            and pins["installer-controller-consumption.json"] == release.digest(receipt_raw)
            and pins["installer-inventory.json"] == release.digest(inventory_bytes), "qualification proof sources changed")
    require(type(report["host_observation"]) is str, "qualification host bytes missing")
    host_raw = report["host_observation"].encode()
    host = host_admission(host_raw, receipt["engine_id"], profile=report["profile"])
    scope = dict(installation_id=receipt["installation_id"], engine_id=receipt["engine_id"],
                 operator_sha256=auth['operator_sha256'], authorized_at=receipt['consumed_at'],
                 context_sha256=release.candidate_context_sha256(context), authorization_sha256=release.digest(auth_raw),
                 controller_consumption_sha256=release.digest(receipt_raw),
                 host_observation_sha256=release.digest(host_raw), hosting=auth["hosting"], runtime=host["runtime"])
    require(report["scope"] == scope, "qualification installed scope differs")
    _selection(report["selection"], required=functional)
    exact(report["cases"], set(cases), "versioned installed assertions")
    exact(report["proofs"], set(cases), "versioned installed proof closure")
    require(all(value == "passed" for value in report["cases"].values()), "installed assertions incomplete")
    for case in cases:
        item = exact(report["proofs"][case], {"name", "sha256", "record"}, "installed proof reference")
        require(item["name"] == f"installed-{case}.json" and type(item["record"]) is str, "installed proof filename differs")
        _sha(item["sha256"])
        proof_raw = item["record"].encode()
        require(release.digest(proof_raw) == item["sha256"], "installed proof bytes changed")
        validate_case_proof(release.decode(proof_raw), case=case, scope=scope,
                            selection=report["selection"], observed_at=report["observed_at"])
    neighbors = exact(report["neighbor_preservation"], {"before_sha256", "after_sha256", "preserved"}, "neighbor preservation")
    before = resource_snapshot(host)
    require(neighbors["before_sha256"] == release.digest(release.encode(before))
            and neighbors["after_sha256"] == neighbors["before_sha256"] and neighbors["preserved"] is True,
            "neighboring state preservation is incomplete")
    cleanup = exact(report["cleanup"], {"owned_containers_remaining", "owned_networks_remaining", "owned_volumes_remaining",
                                       "recovery_retention_verified", "performed"}, "versioned cleanup")
    require(cleanup["performed"] is functional and cleanup["recovery_retention_verified"] is functional,
            "cleanup scope differs")
    if functional:
        require(all(type(cleanup[name]) is int and cleanup[name] == 0 for name in (
            "owned_containers_remaining", "owned_networks_remaining", "owned_volumes_remaining")),
            "owned cleanup is incomplete")
    else:
        require(all(cleanup[name] is None for name in (
            "owned_containers_remaining", "owned_networks_remaining", "owned_volumes_remaining")),
            "startup cannot claim cleanup qualification")


def produce(*, completed_case_bytes: dict[str, bytes], report: dict, inventory_bytes: bytes,
            source_sha: str, release_tag: str, phase: str, run: dict) -> dict:
    """Assemble only already-performed installed proofs; no case runner here.

    The signer must authenticate these inputs and preserve their protected-file
    custody. Missing installed browser/recovery/root-retirement writers remain
    blockers; no checkpoint or component-only proof is accepted as a case.
    """
    import installer_release as release
    expected = set(cases_for(report.get("profile")))
    missing = missing_writers(report.get('profile'))
    require(not missing, 'installed qualification writers unavailable: ' + ', '.join(missing))
    require(type(completed_case_bytes) is dict and set(completed_case_bytes) == expected,
            "installed qualification proof writers are incomplete")
    result = dict(report)
    result["cases"], result["proofs"] = {}, {}
    for case, raw in completed_case_bytes.items():
        require(type(raw) is bytes and 0 < len(raw) <= 65536, "installed proof bound differs")
        proof = release.decode(raw)
        require(proof.get("status") == "passed", "installed proof did not pass")
        result["cases"][case] = proof["status"]
        result["proofs"][case] = dict(name=f"installed-{case}.json", sha256=release.digest(raw), record=raw.decode("utf-8"))
    require(len(release.encode(result)) <= MAX_REPORT_BYTES, "qualification report exceeds bound")
    validate(result, inventory_bytes=inventory_bytes, source_sha=source_sha, release_tag=release_tag,
             phase=phase, run=run, require_functional=False)
    return result
