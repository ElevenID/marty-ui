#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "packages"))

from marty_common.demo_seed_data import (  # pylint: disable=import-error
    DEMO_VENDOR_ORG_ID,
    get_demo_vendor_seed_bundle,
)
from marty_common.migration_profile import (  # pylint: disable=import-error
    is_persistent_profile,
    normalize_migration_profile,
)


def _load_dotenv(env_file: Path) -> None:
    if not env_file.exists():
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+asyncpg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return database_url


def _resolve_database_url() -> str:
    database_url = _normalize_database_url((os.environ.get("DATABASE_URL") or "").strip())
    db_user = (os.environ.get("MARTY_DB_USER") or "marty").strip() or "marty"
    db_password = (os.environ.get("MARTY_DB_PASSWORD") or "marty_dev_password").strip() or "marty_dev_password"
    db_host = (
        os.environ.get("DATABASE_HOST")
        or os.environ.get("POSTGRES_HOST")
        or os.environ.get("MARTY_DB_HOST")
        or "localhost"
    ).strip() or "localhost"
    db_port = (
        os.environ.get("DATABASE_PORT")
        or os.environ.get("POSTGRES_PORT")
        or os.environ.get("POSTGRES_HOST_PORT")
        or os.environ.get("MARTY_DB_PORT")
        or "5433"
    ).strip() or "5433"
    db_name = (
        os.environ.get("DATABASE_NAME")
        or os.environ.get("POSTGRES_DB")
        or os.environ.get("MARTY_DB_NAME")
        or "marty"
    ).strip() or "marty"

    if database_url:
        parsed = urlparse(database_url)
        hostname = (parsed.hostname or "").strip().lower()
        use_local_compose_target = hostname in {"", "postgres", "marty-postgres", "localhost", "127.0.0.1"}
        effective_host = db_host if use_local_compose_target else hostname
        effective_port = db_port if use_local_compose_target else str(parsed.port or db_port)
        effective_user = db_user if use_local_compose_target else (parsed.username or db_user)
        effective_password = db_password if use_local_compose_target else (db_password or parsed.password or "")
        effective_name = db_name if use_local_compose_target else (parsed.path.lstrip("/") or db_name)
        return (
            f"postgresql+asyncpg://{quote(effective_user)}:{quote(effective_password)}"
            f"@{effective_host}:{effective_port}/{effective_name}"
        )

    return (
        f"postgresql+asyncpg://{quote(db_user)}:{quote(db_password)}"
        f"@{db_host}:{db_port}/{db_name}"
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed reset-friendly demo vendor org/catalog/template fixtures",
    )
    parser.add_argument(
        "--env-file",
        default=".env.tunnel.beta.local",
        help="Env file to load before reading process environment (default: .env.tunnel.beta.local)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow seeding even when MARTY_MIGRATION_PROFILE resolves to a persistent profile.",
    )
    return parser.parse_args()


async def _table_exists(conn: AsyncConnection, qualified_name: str) -> bool:
    return bool(
        await conn.scalar(
            text("SELECT to_regclass(:qualified_name) IS NOT NULL"),
            {"qualified_name": qualified_name},
        )
    )


async def _column_exists(conn: AsyncConnection, schema: str, table: str, column: str) -> bool:
    return bool(
        await conn.scalar(
            text(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = :schema
                      AND table_name = :table
                      AND column_name = :column
                )
                """
            ),
            {"schema": schema, "table": table, "column": column},
        )
    )


async def _seed_demo_organization(conn: AsyncConnection, organization: dict[str, Any]) -> None:
    params = {
        **organization,
        "settings": json.dumps(organization["settings"], separators=(",", ":")),
        "match_slug": organization["slug"],
        "match_name": organization["name"],
    }

    await conn.execute(
        text(
            """
            UPDATE organization_service.organizations
            SET
                name = :name,
                display_name = :display_name,
                slug = :slug,
                description = :description,
                org_type = :org_type,
                status = :status,
                join_mechanism = :join_mechanism,
                requires_approval = :requires_approval,
                is_discoverable = :is_discoverable,
                settings = CAST(:settings AS jsonb),
                updated_at = NOW()
            WHERE id = CAST(:id AS uuid)
               OR slug = CAST(:match_slug AS varchar)
               OR LOWER(name) = LOWER(CAST(:match_name AS varchar))
            """
        ),
        params,
    )

    await conn.execute(
        text(
            """
            INSERT INTO organization_service.organizations (
                id,
                name,
                display_name,
                slug,
                description,
                org_type,
                status,
                join_mechanism,
                requires_approval,
                is_discoverable,
                settings,
                created_at,
                updated_at
            )
            SELECT
                CAST(:id AS uuid),
                CAST(:name AS varchar),
                CAST(:display_name AS varchar),
                CAST(:slug AS varchar),
                CAST(:description AS varchar),
                CAST(:org_type AS varchar),
                CAST(:status AS varchar),
                CAST(:join_mechanism AS varchar),
                :requires_approval,
                :is_discoverable,
                CAST(:settings AS jsonb),
                NOW(),
                NOW()
            WHERE NOT EXISTS (
                SELECT 1
                FROM organization_service.organizations
                WHERE id = CAST(:id AS uuid)
                   OR slug = CAST(:match_slug AS varchar)
                   OR LOWER(name) = LOWER(CAST(:match_name AS varchar))
            )
            """
        ),
        params,
    )


async def _seed_credential_types(
    conn: AsyncConnection,
    organization_id: str,
    credential_types: list[dict[str, Any]],
) -> None:
    update_sql = text(
        """
        UPDATE credential_service.credential_types
        SET
                        description = CAST(:description AS varchar),
                        format = CAST(:format AS varchar),
            status = 'active',
            schema_definition = CAST(:schema_definition AS jsonb),
            display_config = CAST(:display_config AS jsonb),
            validity_days = 365,
            revocable = true,
            updated_at = NOW()
                WHERE organization_id = CAST(:organization_id AS varchar)
                    AND name = CAST(:name AS varchar)
        """
    )
    insert_sql = text(
        """
        INSERT INTO credential_service.credential_types (
            id,
            organization_id,
            name,
            description,
            format,
            status,
            schema_definition,
            display_config,
            validity_days,
            revocable,
            created_at,
            updated_at
        )
        SELECT
            CAST(:id AS varchar),
            CAST(:organization_id AS varchar),
            CAST(:name AS varchar),
            CAST(:description AS varchar),
            CAST(:format AS varchar),
            'active',
            CAST(:schema_definition AS jsonb),
            CAST(:display_config AS jsonb),
            365,
            true,
            NOW(),
            NOW()
        WHERE NOT EXISTS (
            SELECT 1
            FROM credential_service.credential_types
                        WHERE organization_id = CAST(:organization_id AS varchar)
                            AND name = CAST(:name AS varchar)
        )
        """
    )

    for row in credential_types:
        params = {
            "id": row["id"],
            "organization_id": organization_id,
            "name": row["name"],
            "description": row["description"],
            "format": row["format"],
            "schema_definition": json.dumps(row["schema_definition"], separators=(",", ":")),
            "display_config": json.dumps(row["display_config"], separators=(",", ":")),
        }
        await conn.execute(update_sql, params)
        await conn.execute(insert_sql, params)


async def _seed_credential_templates(
    conn: AsyncConnection,
    organization_id: str,
    credential_templates: list[dict[str, Any]],
) -> None:
    wallet_configs_supported = await _column_exists(
        conn,
        "credential_template_service",
        "credential_templates",
        "wallet_configs",
    )
    payload_format_supported = await _column_exists(
        conn,
        "credential_template_service",
        "credential_templates",
        "credential_payload_format",
    )

    wallet_update_clause = ""
    wallet_insert_columns = ""
    wallet_insert_values = ""
    if wallet_configs_supported:
        wallet_update_clause = ",\n            wallet_configs = CAST(:wallet_configs AS jsonb)"
        wallet_insert_columns = ",\n            wallet_configs"
        wallet_insert_values = ",\n            CAST(:wallet_configs AS jsonb)"

    payload_update_clause = ""
    payload_insert_columns = ""
    payload_insert_values = ""
    if payload_format_supported:
        payload_update_clause = ",\n            credential_payload_format = :credential_payload_format"
        payload_insert_columns = ",\n            credential_payload_format"
        payload_insert_values = ",\n            :credential_payload_format"

    update_sql = text(
        f"""
        UPDATE credential_template_service.credential_templates
        SET
                        name = CAST(:name AS varchar),
                        description = CAST(:description AS varchar),
                        status = CAST(:status AS varchar),
                        vct = CAST(:vct AS varchar),
                        doctype = CAST(:doctype AS varchar),
            claims = CAST(:claims AS jsonb),
                        privacy_posture = CAST(:privacy_posture AS varchar),
            selective_disclosure_fields = CAST(:selective_disclosure_fields AS jsonb),
            derived_attributes = CAST(:derived_attributes AS jsonb),
            display_style = CAST(:display_style AS jsonb),
            validity_rules = CAST(:validity_rules AS jsonb),
            issuer_requirements = CAST(:issuer_requirements AS jsonb),
            supported_formats = CAST(:supported_formats AS jsonb),
                        version = :version{payload_update_clause}{wallet_update_clause},
            updated_at = NOW()
                WHERE organization_id = CAST(:organization_id AS varchar)
                    AND credential_type = CAST(:credential_type AS varchar)
        """
    )
    insert_sql = text(
        f"""
        INSERT INTO credential_template_service.credential_templates (
            id,
            organization_id,
            name,
            description,
            status,
            credential_type,
            vct,
            doctype,
            claims,
            privacy_posture,
            selective_disclosure_fields,
            derived_attributes,
            display_style,
            validity_rules,
            issuer_requirements,
            supported_formats,
            version{payload_insert_columns}{wallet_insert_columns},
            created_at,
            updated_at
        )
        SELECT
                        CAST(:id AS varchar),
                        CAST(:organization_id AS varchar),
                        CAST(:name AS varchar),
                        CAST(:description AS varchar),
                        CAST(:status AS varchar),
                        CAST(:credential_type AS varchar),
                        CAST(:vct AS varchar),
                        CAST(:doctype AS varchar),
            CAST(:claims AS jsonb),
                        CAST(:privacy_posture AS varchar),
            CAST(:selective_disclosure_fields AS jsonb),
            CAST(:derived_attributes AS jsonb),
            CAST(:display_style AS jsonb),
            CAST(:validity_rules AS jsonb),
            CAST(:issuer_requirements AS jsonb),
            CAST(:supported_formats AS jsonb),
            :version{payload_insert_values}{wallet_insert_values},
            NOW(),
            NOW()
        WHERE NOT EXISTS (
            SELECT 1
            FROM credential_template_service.credential_templates
                        WHERE organization_id = CAST(:organization_id AS varchar)
                            AND credential_type = CAST(:credential_type AS varchar)
        )
        """
    )

    for row in credential_templates:
        credential_payload_format = row.get("credential_payload_format")
        if not credential_payload_format:
            supported_formats = row.get("supported_formats") or []
            if "mso_mdoc" in supported_formats:
                credential_payload_format = "mso_mdoc"
            elif "sd_jwt_vc" in supported_formats:
                credential_payload_format = "w3c_vcdm_v2_sd_jwt"
            elif supported_formats:
                credential_payload_format = supported_formats[0]
            else:
                credential_payload_format = "w3c_vcdm_v2_sd_jwt"

        params = {
            "id": row["id"],
            "organization_id": organization_id,
            "name": row["name"],
            "description": row["description"],
            "status": row["status"],
            "credential_type": row["credential_type"],
            "vct": row["vct"],
            "doctype": row["doctype"],
            "claims": json.dumps(row["claims"], separators=(",", ":")),
            "privacy_posture": row["privacy_posture"],
            "selective_disclosure_fields": json.dumps(row["selective_disclosure_fields"], separators=(",", ":")),
            "derived_attributes": json.dumps(row["derived_attributes"], separators=(",", ":")),
            "display_style": json.dumps(row["display_style"], separators=(",", ":")),
            "validity_rules": json.dumps(row["validity_rules"], separators=(",", ":")),
            "issuer_requirements": json.dumps(row["issuer_requirements"], separators=(",", ":")),
            "supported_formats": json.dumps(row["supported_formats"], separators=(",", ":")),
            "credential_payload_format": credential_payload_format,
            "version": row["version"],
            "wallet_configs": json.dumps(row.get("wallet_configs") or [], separators=(",", ":")),
        }
        await conn.execute(update_sql, params)
        await conn.execute(insert_sql, params)


async def _run_seed() -> dict[str, Any]:
    bundle = get_demo_vendor_seed_bundle()
    database_url = _resolve_database_url()
    engine = create_async_engine(database_url, future=True)

    summary: dict[str, Any] = {
        "organization_id": DEMO_VENDOR_ORG_ID,
        "credential_types_seeded": 0,
        "credential_templates_seeded": 0,
        "wallet_configs_applied": False,
    }

    try:
        async with engine.begin() as conn:
            if not await _table_exists(conn, "organization_service.organizations"):
                raise RuntimeError(
                    "organization_service.organizations is missing. Run schema/stable migrations before seeding demo fixtures."
                )

            await _seed_demo_organization(conn, bundle["organization"])

            if await _table_exists(conn, "credential_service.credential_types"):
                await _seed_credential_types(
                    conn,
                    DEMO_VENDOR_ORG_ID,
                    bundle["credential_types"],
                )
                summary["credential_types_seeded"] = len(bundle["credential_types"])

            if await _table_exists(conn, "credential_template_service.credential_templates"):
                await _seed_credential_templates(
                    conn,
                    DEMO_VENDOR_ORG_ID,
                    bundle["credential_templates"],
                )
                summary["credential_templates_seeded"] = len(bundle["credential_templates"])
                summary["wallet_configs_applied"] = await _column_exists(
                    conn,
                    "credential_template_service",
                    "credential_templates",
                    "wallet_configs",
                )
    finally:
        await engine.dispose()

    return summary


def main() -> int:
    args = _parse_args()
    _load_dotenv(Path(args.env_file))

    profile = normalize_migration_profile(os.environ.get("MARTY_MIGRATION_PROFILE"))
    if is_persistent_profile() and not args.force:
        print(
            "ERROR: demo vendor fixtures are intended for reset-friendly profiles only. "
            f"Refusing to run against persistent profile '{profile}'. Use --force to override.",
            file=sys.stderr,
        )
        return 2

    print(f"==> Seeding demo vendor fixtures (profile: {profile})")
    try:
        summary = asyncio.run(_run_seed())
    except Exception as exc:  # pragma: no cover - CLI failure path
        print(f"ERROR: demo vendor seed failed: {exc}", file=sys.stderr)
        return 1

    print(f"  ✓ Organization upserted: {summary['organization_id']}")
    print(f"  ✓ Credential types seeded: {summary['credential_types_seeded']}")
    print(f"  ✓ Credential templates seeded: {summary['credential_templates_seeded']}")
    print(f"  ✓ Wallet configs applied: {summary['wallet_configs_applied']}")
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())