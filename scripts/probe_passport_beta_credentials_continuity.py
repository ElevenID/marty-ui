#!/usr/bin/env python3
"""Prove signed beta Rust issuance serves passport and persists unrelated writes.

The private OID4VCI nonce request is a bounded, unrelated issuance database
write. It does not issue a credential or claim broader issuance parity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable

try:
    from .probe_passport_beta_host import BETA_PROJECT, HostProbeError, beta_psql, ids, inspect, run
    from .prepare_passport_beta_aggregate_compose import verify_render_plan
    from .prepare_passport_beta_aggregate_handoff import verify_fence
    from .verify_passport_beta_rust_owner import verify as verify_rust_owner
except ImportError:
    from probe_passport_beta_host import BETA_PROJECT, HostProbeError, beta_psql, ids, inspect, run
    from prepare_passport_beta_aggregate_compose import verify_render_plan
    from prepare_passport_beta_aggregate_handoff import verify_fence
    from verify_passport_beta_rust_owner import verify as verify_rust_owner


CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
NONCE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
IMAGE_PREFIX = "ghcr.io/elevenid/marty-ui-oss/services@sha256:"
PRETRANSITION_FIELDS = frozenset({
    "schema", "verified", "source_commit", "postgres_container_id",
    "postgres_system_identifier", "database_oid", "fence_epoch",
    "migration_set_sha256", "issuance_container_id", "issuance_image",
    "fence_verify_sql_sha256", "rust_passport_capabilities_verified",
    "unrelated_issuance_nonce_write_verified", "nonce_sha256",
    "receipt_sha256",
})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def private_json(container: str, method: str, path: str,
                 runner: Callable[[list[str]], str], *,
                 expected_status: str = "200") -> dict[str, Any]:
    require(CONTAINER.fullmatch(container) is not None
            and method in {"GET", "POST"} and path.startswith("/"),
            "Private Credentials request identity is invalid")
    raw = runner([
        "docker", "exec", container, "curl", "--silent", "--show-error",
        "--max-time", "20", "--request", method,
        "--write-out", "\n%{http_code}",
        "--url", "http://127.0.0.1:8005" + path,
    ])
    require(len(raw) <= 2_000_000, "Private Credentials response is oversized")
    try:
        body, status = raw.rsplit("\n", 1)
        value = json.loads(body)
    except (ValueError, TypeError) as exc:
        raise HostProbeError("Private Credentials response is invalid") from exc
    require(status == expected_status and isinstance(value, dict),
            "Private Credentials request did not succeed")
    return value


def replacement(plan: dict[str, Any], runner: Callable[[list[str]], str], *,
                allow_running_ingress: bool = False,
                service: str = "issuance") -> str:
    require(service in {"issuance", "issuance-native"},
            "Rust issuance service selection is invalid")
    require(plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and isinstance(plan.get("old_container_ids_by_service"), dict)
            and isinstance(plan.get("service_config_hashes"), dict),
            "Private Credentials plan is invalid")
    expected_image = plan.get("services_image")
    require(isinstance(expected_image, str)
            and expected_image.startswith(IMAGE_PREFIX)
            and DIGEST.fullmatch(expected_image[len(IMAGE_PREFIX):]) is not None,
            "Private Credentials image is not digest pinned")
    old_id = plan["old_container_ids_by_service"].get(service)
    expected_hash = plan["service_config_hashes"].get(service)
    require(isinstance(old_id, str) and CONTAINER.fullmatch(old_id) is not None
            and isinstance(expected_hash, str)
            and DIGEST.fullmatch(expected_hash) is not None,
            "Private Credentials generation is invalid")
    for name in (plan.get("recreate_ingress_last") or []) + (
            plan.get("restart_ingress_last") or []):
        require(isinstance(name, str), "Private Credentials ingress plan is invalid")
    ingress = set(plan.get("recreate_ingress_last") or []) | set(
        plan.get("restart_ingress_last") or [])
    if not allow_running_ingress:
        for ui_id in ids("elevenid-beta-ui", runner):
            ui = inspect(ui_id, runner)
            ui_config = ui.get("Config")
            ui_labels = ui_config.get("Labels") if isinstance(ui_config, dict) else None
            ui_state = ui.get("State")
            require(isinstance(ui_labels, dict) and isinstance(ui_state, dict)
                    and ui_labels.get("com.docker.compose.project") == "elevenid-beta-ui"
                    and ui_labels.get("com.docker.compose.service") == "ui-prod"
                    and ui_state.get("Running") is False,
                    "Public beta UI is running during private Credentials proof")
    current = []
    for candidate in ids(BETA_PROJECT, runner):
        record = inspect(candidate, runner)
        config = record.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        state = record.get("State")
        require(isinstance(labels, dict) and isinstance(state, dict)
                and labels.get("com.docker.compose.project") == BETA_PROJECT,
                "Private Credentials Compose inventory changed")
        name = labels.get("com.docker.compose.service")
        if name in ingress and not allow_running_ingress:
            require(state.get("Running") is False,
                    "Public beta ingress is running during private Credentials proof")
        if name != service:
            continue
        container = record.get("Id")
        require(isinstance(container, str) and CONTAINER.fullmatch(container) is not None,
                "Private Credentials container identity is invalid")
        if container == old_id:
            require(state.get("Running") is False,
                    "Old issuance writer is still running")
            continue
        require(state.get("Running") is True and state.get("Status") == "running"
                and config.get("Image") == expected_image
                and labels.get("com.docker.compose.config-hash") == expected_hash,
                "Replacement Credentials service differs from signed Compose plan")
        health = state.get("Health")
        require(health is None or (isinstance(health, dict)
                                   and health.get("Status") == "healthy"),
                "Replacement Credentials service is unhealthy")
        current.append(record)
    require(len(current) == 1,
            "Private Credentials generation is ambiguous")
    record = current[0]
    local_image = record.get("Image")
    require(isinstance(local_image, str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", local_image) is not None,
            "Replacement Credentials image identity is invalid")
    try:
        images = json.loads(runner(["docker", "image", "inspect", expected_image]))
    except ValueError as exc:
        raise HostProbeError("Signed Credentials image inspection is invalid") from exc
    require(isinstance(images, list) and len(images) == 1
            and isinstance(images[0], dict)
            and images[0].get("Id") == local_image
            and expected_image in (images[0].get("RepoDigests") or []),
            "Running Credentials image does not match signed digest")
    return record["Id"]


def live_route_and_nonce_checks(plan: dict[str, Any], container: str,
                                runner: Callable[[list[str]], str], *,
                                allow_running_ingress: bool = False) -> str:
    """Exercise the signed Rust container through its real HTTP listener."""
    native = replacement(plan, runner, service="issuance-native",
                         allow_running_ingress=allow_running_ingress)
    capabilities = private_json(native, "GET", "/v1/passport/capabilities", runner)
    require(capabilities.get("supported") is True
            and capabilities.get("encrypted_artifact_store") is True
            and capabilities.get("bureau_configured") is True
            and isinstance(capabilities.get("signer"), dict)
            and capabilities["signer"].get("configured") is True
            and capabilities["signer"].get("mode") == "MANAGED_ISSUER_PROFILE"
            and capabilities.get("blockers") == [],
            "Rust passport capabilities are unavailable")
    ready = private_json(container, "GET", "/ready", runner)
    require(ready.get("status") == "ready"
            and ready.get("service") == "issuance-service",
            "Replacement Rust issuance readiness differs")
    written = private_json(container, "POST", "/v1/issuance/nonce", runner)
    nonce = written.get("c_nonce")
    require(isinstance(nonce, str) and NONCE.fullmatch(nonce) is not None,
            "Unrelated issuance nonce response is invalid")
    nonce_digest = hashlib.sha256(nonce.encode()).hexdigest()
    row = beta_psql(
        "SELECT count(*) FROM issuance_service.oid4vci_ephemeral_capabilities "
        "WHERE purpose='proof_nonce' "
        f"AND key_digest='{nonce_digest}' AND payload IS NULL "
        "AND expires_at > clock_timestamp()",
        runner, plan["postgres_container_id"],
    )
    require(row == "1", "Unrelated issuance nonce was not persisted")
    return nonce_digest


def verify_pretransition(
    plan: dict[str, Any], *, runner: Callable[[list[str]], str] = run,
    render_verifier: Callable[[dict[str, Any]], dict[str, Any]] = verify_render_plan,
    fence_verifier: Callable[[dict[str, Any], Callable[[list[str]], str]], None] = verify_fence,
) -> dict[str, Any]:
    require(plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and re.fullmatch(r"[0-9a-f]{40}", str(plan.get("source_commit"))) is not None
            and render_verifier(plan).get("verified") is True,
            "Pretransition signed aggregate plan is invalid")
    container = str(plan.get("postgres_container_id"))
    system_id = str(plan.get("postgres_system_identifier"))
    database_oid = str(plan.get("database_oid"))
    epoch = str(plan.get("fence_epoch"))
    migration_digest = str(plan.get("migration_set_sha256"))
    require(CONTAINER.fullmatch(container) is not None
            and all(re.fullmatch(r"[0-9]+", item) is not None
                    for item in (system_id, database_oid, epoch))
            and DIGEST.fullmatch(migration_digest) is not None,
            "Pretransition beta database target is invalid")
    marker = beta_psql(
        "SELECT (SELECT system_identifier::text FROM pg_control_system()) || '|' || "
        "(SELECT oid::text FROM pg_database WHERE datname=current_database()) || '|' || "
        "(SELECT phase || '|' || epoch::text FROM passport_cutover.state "
        "WHERE singleton=true) || '|' || "
        "(SELECT fence_epoch::text || '|' || source_commit || '|' || "
        "migration_set_sha256 FROM passport_cutover.native_migration_receipt "
        "WHERE singleton=true) || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles WHERE rolname='marty') || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles "
        "WHERE rolname='marty_beta_migrator')",
        runner, container,
    )
    require(marker == "|".join((system_id, database_oid, "fully_fenced", epoch,
                                epoch, plan["source_commit"], migration_digest,
                                "true", "false")),
            "Pretransition database marker differs from signed fenced source")
    fence_verifier({
        "verify_sql_sha256": plan.get("fence_verify_sql_sha256"),
        "postgres_container_id": container,
        "postgres_system_identifier": system_id,
        "database_oid": database_oid,
        "fence_epoch": epoch,
    }, runner)
    return {
        "verified": True,
        "source_commit": plan["source_commit"],
        "postgres_container_id": container,
        "postgres_system_identifier": system_id,
        "database_oid": database_oid,
        "fence_epoch": epoch,
        "migration_set_sha256": migration_digest,
    }


def probe_pretransition(
    plan: dict[str, Any], *, runner: Callable[[list[str]], str] = run,
    pretransition_verifier: Callable[..., dict[str, Any]] = verify_pretransition,
) -> dict[str, Any]:
    before = pretransition_verifier(plan, runner=runner)
    require(before.get("verified") is True
            and before.get("source_commit") == plan.get("source_commit")
            and before.get("postgres_container_id") == plan.get("postgres_container_id")
            and str(before.get("fence_epoch")) == str(plan.get("fence_epoch")),
            "Pretransition fully fenced owner changed")
    container = replacement(plan, runner)
    nonce_digest = live_route_and_nonce_checks(plan, container, runner)
    require(pretransition_verifier(plan, runner=runner) == before,
            "Pretransition fence changed during Credentials continuity proof")
    result = {
        "schema": "marty.passport-beta-credentials-pretransition/v1",
        "verified": True,
        **before,
        "issuance_container_id": container,
        "issuance_image": plan["services_image"],
        "fence_verify_sql_sha256": plan["fence_verify_sql_sha256"],
        "rust_passport_capabilities_verified": True,
        "unrelated_issuance_nonce_write_verified": True,
        "nonce_sha256": nonce_digest,
    }
    result["receipt_sha256"] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return result


def verify_pretransition_receipt(
    plan: dict[str, Any], receipt_bytes: bytes, *,
    render_verifier: Callable[[dict[str, Any]], dict[str, Any]] = verify_render_plan,
) -> dict[str, Any]:
    """Check durable receipt bytes against the plan after the DB phase changes.

    This checks consistency of a previously captured receipt. It does not
    recreate the historical live observation once rust_owner has committed.
    """
    require(isinstance(receipt_bytes, bytes)
            and 0 < len(receipt_bytes) <= 128 * 1024,
            "Pretransition Credentials receipt bytes are invalid")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value = dict(pairs)
        require(len(value) == len(pairs),
                "Pretransition Credentials receipt has duplicate fields")
        return value

    try:
        receipt = json.loads(
            receipt_bytes, object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (ValueError, UnicodeError) as exc:
        raise HostProbeError("Pretransition Credentials receipt is invalid") from exc
    require(isinstance(receipt, dict) and set(receipt) == PRETRANSITION_FIELDS
            and receipt.get("schema")
                == "marty.passport-beta-credentials-pretransition/v1"
            and receipt.get("verified") is True
            and receipt.get("rust_passport_capabilities_verified") is True
            and receipt.get("unrelated_issuance_nonce_write_verified") is True
            and CONTAINER.fullmatch(str(receipt.get("issuance_container_id")))
                is not None
            and DIGEST.fullmatch(str(receipt.get("nonce_sha256"))) is not None
            and DIGEST.fullmatch(str(receipt.get("receipt_sha256"))) is not None,
            "Pretransition Credentials receipt shape is invalid")
    payload = {key: value for key, value in receipt.items()
               if key != "receipt_sha256"}
    canonical_digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    require(receipt["receipt_sha256"] == canonical_digest,
            "Pretransition Credentials receipt canonical hash differs")
    require(plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and render_verifier(plan).get("verified") is True
            and receipt["source_commit"] == plan.get("source_commit")
            and receipt["postgres_container_id"] == plan.get("postgres_container_id")
            and str(receipt["postgres_system_identifier"])
                == str(plan.get("postgres_system_identifier"))
            and str(receipt["database_oid"]) == str(plan.get("database_oid"))
            and str(receipt["fence_epoch"]) == str(plan.get("fence_epoch"))
            and receipt["migration_set_sha256"] == plan.get("migration_set_sha256")
            and receipt["issuance_image"] == plan.get("services_image")
            and receipt["fence_verify_sql_sha256"]
                == plan.get("fence_verify_sql_sha256"),
            "Pretransition Credentials receipt differs from signed plan")
    return {
        "schema": "marty.passport-beta-credentials-pretransition-check/v1",
        "verified": True,
        "receipt_file_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "receipt_sha256": canonical_digest,
        "source_commit": receipt["source_commit"],
        "fence_epoch": receipt["fence_epoch"],
        "postgres_container_id": receipt["postgres_container_id"],
        "issuance_container_id": receipt["issuance_container_id"],
        "issuance_image": receipt["issuance_image"],
    }


def probe(plan: dict[str, Any], *, runner: Callable[[list[str]], str] = run,
          owner_verifier: Callable[..., dict[str, Any]] = verify_rust_owner,
          prior_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    owner = owner_verifier(plan, runner=runner)
    require(owner.get("verified") is True
            and owner.get("source_commit") == plan.get("source_commit")
            and owner.get("postgres_container_id") == plan.get("postgres_container_id"),
            "Private Credentials Rust owner changed")
    if prior_receipt is not None:
        require(prior_receipt.get("schema")
                == "marty.passport-beta-credentials-continuity/v1"
                and prior_receipt.get("verified") is True
                and prior_receipt.get("source_commit") == plan.get("source_commit")
                and str(prior_receipt.get("transition_txid"))
                    == str(owner.get("transition_txid"))
                and prior_receipt.get("issuance_image") == plan.get("services_image")
                and prior_receipt.get("rust_passport_capabilities_verified") is True
                and prior_receipt.get("unrelated_issuance_nonce_write_verified") is True
                and DIGEST.fullmatch(str(prior_receipt.get("nonce_sha256"))) is not None
                and CONTAINER.fullmatch(str(prior_receipt.get("issuance_container_id")))
                    is not None,
                "Prior Credentials continuity receipt differs from Rust owner")
    container = replacement(plan, runner,
                            allow_running_ingress=prior_receipt is not None)
    require(prior_receipt is None
            or prior_receipt["issuance_container_id"] == container,
            "Prior Credentials container differs from running replacement")
    nonce_digest = live_route_and_nonce_checks(
        plan, container, runner, allow_running_ingress=prior_receipt is not None)
    refreshed = owner_verifier(plan, runner=runner)
    require(refreshed == owner, "Rust owner changed during Credentials continuity proof")
    return {
        "schema": "marty.passport-beta-credentials-continuity/v1",
        "verified": True,
        "source_commit": plan["source_commit"],
        "transition_txid": owner["transition_txid"],
        "issuance_container_id": container,
        "issuance_image": plan["services_image"],
        "rust_passport_capabilities_verified": True,
        "unrelated_issuance_nonce_write_verified": True,
        "nonce_sha256": nonce_digest,
    }


def verify_resume(plan: dict[str, Any], prior_bytes: bytes, *,
                  runner: Callable[[list[str]], str] = run,
                  owner_verifier: Callable[..., dict[str, Any]] = verify_rust_owner,
) -> dict[str, Any]:
    require(isinstance(prior_bytes, bytes) and 0 < len(prior_bytes) <= 128 * 1024,
            "Prior Credentials receipt is invalid")
    try:
        prior = json.loads(prior_bytes)
    except ValueError as exc:
        raise HostProbeError("Prior Credentials receipt is invalid") from exc
    require(isinstance(prior, dict), "Prior Credentials receipt is invalid")
    current = probe(plan, runner=runner, owner_verifier=owner_verifier,
                    prior_receipt=prior)
    require(current["nonce_sha256"] != prior["nonce_sha256"],
            "Credentials resume did not produce a fresh nonce")
    return {
        "schema": "marty.passport-beta-credentials-continuity-resume/v1",
        "verified": True,
        "prior_receipt_sha256": hashlib.sha256(prior_bytes).hexdigest(),
        "source_commit": current["source_commit"],
        "transition_txid": current["transition_txid"],
        "issuance_container_id": current["issuance_container_id"],
        "issuance_image": current["issuance_image"],
        "rust_passport_capabilities_verified": True,
        "unrelated_issuance_nonce_write_verified": True,
        "fresh_nonce_sha256": current["nonce_sha256"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--verify-resume", type=Path, metavar="PRIOR_RECEIPT")
    parser.add_argument("--pretransition", action="store_true")
    parser.add_argument("--verify-pretransition-receipt", type=Path,
                        metavar="PRETRANSITION_RECEIPT")
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        require(isinstance(plan, dict), "Private Credentials plan is invalid")
        require(sum((args.verify_resume is not None, args.pretransition,
                     args.verify_pretransition_receipt is not None)) <= 1,
                "Credentials proof modes are mutually exclusive")
        if args.verify_pretransition_receipt is not None:
            require(args.verify_pretransition_receipt.is_absolute(),
                    "Pretransition Credentials receipt path is not absolute")
            result = verify_pretransition_receipt(
                plan, args.verify_pretransition_receipt.read_bytes())
        elif args.pretransition:
            result = probe_pretransition(plan)
        elif args.verify_resume is not None:
            require(args.verify_resume.is_absolute(),
                    "Prior Credentials receipt path is not absolute")
            result = verify_resume(plan, args.verify_resume.read_bytes())
        else:
            result = probe(plan)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        raise SystemExit(f"Private beta Credentials continuity is unavailable: {exc}") from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
