"""One-way MIP 0.2 to 0.3 migration for the applicant JSON store."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any


INTERNAL_KEYS = {
    "credential_offer_uri",
    "credential_offer_uris",
    "credential_offer_labels",
    "offer_expires_at",
    "offer_generated_at",
    "issuance_transaction_id",
    "issuance_status",
    "issuance_source",
    "flow_instance_id",
    "flow_definition_id",
    "credential_display_name",
    "credential_type",
    "review_notes",
    "rejection_reason",
    "info_requests",
    "delivery_preferences",
    "auto_approve",
}
INTEGRATION_KEYS = {
    "canvas_lti",
    "canvas_context",
    "learner_identity",
    "delivery_mode",
    "delivery",
}


def _template_map() -> dict[str, str]:
    raw = os.environ.get("APPLICATION_TEMPLATE_MIGRATION_MAP", "{}").strip() or "{}"
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("APPLICATION_TEMPLATE_MIGRATION_MAP must be a JSON object")
    return {str(key): str(value) for key, value in parsed.items() if value}


def migrate(path: Path) -> bool:
    if not path.exists():
        return False
    payload = json.loads(path.read_text(encoding="utf-8"))
    applications = payload.get("applications")
    if not isinstance(applications, list) or not applications:
        return False
    if all("credential_template_id" in row and "metadata" not in row for row in applications):
        return False

    mapping = _template_map()
    migrated: list[dict[str, Any]] = []
    unresolved: list[str] = []
    for row in applications:
        credential_template_id = str(
            row.get("credential_template_id")
            or row.get("credential_configuration_id")
            or ""
        ).strip()
        application_template_id = str(
            row.get("application_template_id")
            or mapping.get(credential_template_id)
            or ""
        ).strip()
        if not credential_template_id or not application_template_id:
            unresolved.append(str(row.get("id") or "unknown"))
            continue
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        system_data = dict(row.get("system_data") or {})
        integration_context = dict(row.get("integration_context") or {})
        form_data = dict(row.get("form_data") or {})
        for key, value in metadata.items():
            if key in INTERNAL_KEYS:
                system_data[key] = value
            elif key in INTEGRATION_KEYS:
                integration_context[key] = value
            else:
                form_data[key] = value
        auto_approve = bool(system_data.pop("auto_approve", False))
        system_data.setdefault("approval_strategy", "AUTO" if auto_approve else "MANUAL")
        status = str(row.get("status") or "DRAFT").upper()
        offer_ready = bool(system_data.get("credential_offer_uri") or system_data.get("credential_offer_uris"))
        claim_state = "CLAIMED" if status in {"CREDENTIALED", "ISSUED"} else "OFFER_READY" if offer_ready else "NOT_READY"
        migrated.append({
            "id": row.get("id"),
            "applicant_id": row.get("applicant_id"),
            "organization_id": row.get("organization_id"),
            "reference_number": row.get("reference_number"),
            "application_template_id": application_template_id,
            "credential_template_id": credential_template_id,
            "status": status,
            "form_data": form_data,
            "integration_context": integration_context,
            "system_data": system_data,
            "required_checks": row.get("required_checks") or [],
            "claim_state": claim_state,
            "claim_blocker": None,
            "created_at": row.get("created_at"),
            "submitted_at": row.get("submitted_at"),
            "reviewed_at": row.get("reviewed_at"),
            "issued_at": row.get("issued_at"),
            "updated_at": row.get("updated_at"),
        })
    if unresolved:
        raise RuntimeError(
            "Applicant migration cannot resolve Application Templates for: "
            + ", ".join(unresolved)
        )

    backup = path.with_suffix(path.suffix + ".mip-0.2.bak")
    if not backup.exists():
        shutil.copy2(path, backup)
    payload["applications"] = migrated
    payload["schema_version"] = "MIP/0.3.0"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    temporary.replace(path)
    return True


def main() -> None:
    path = Path(os.environ.get("APPLICANT_DATA_FILE", "/app/data/applicant_store.json"))
    changed = migrate(path)
    print(f"Applicant store MIP 0.3 migration: {'updated' if changed else 'not required'}")


if __name__ == "__main__":
    main()
