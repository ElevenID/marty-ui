"""Read-only witnesses for three native system-catalog timestamp cohorts.

This complements membership, ledger and catalog witnesses. It never executes
startup, migrations or deployment, and does not grant transition admission.
Only existing built-in wallet/destination rows and the configured tenant's
Marty issuer may change updated_at. Every other physical field and row remains
in the opaque comparison, including customer rows and unknown columns.
"""

import hashlib
import json
import re
import uuid

import selfhost_windows_product_probe as probe
import selfhost_windows_product_schema as membership

SCHEMA = "marty.windows-system-startup-timestamps/v1"
WALLETS = (
    "wr-spruce-001",
    "wr-marty-001",
    "wr-default",
    "wr-lissi-001",
    "wr-waltid-001",
    "wr-sphereon-001",
    "wr-dc4eu-001",
    "wr-google-001",
    "wr-apple-001",
    "wr-didcomm-001",
)
DESTINATIONS = (
    "dd-elevenid-wallet",
    "dd-oid4vci-compatible-wallet",
    "dd-canvas-credentials-institutional",
    "dd-canvas-credentials-backpack",
)
TABLES = {
    "wallets": "credential_template_service.wallet_registry",
    "destinations": "credential_template_service.delivery_destinations",
    "issuer": "trust_profile_service.issuer_entities",
}
COUNTS = {"wallets": len(WALLETS), "destinations": len(DESTINATIONS), "issuer": 1}
ISSUER_ID = "60000000-0000-0000-0000-000000000012"


def require(value):
    if not value:
        raise ValueError("Native startup timestamp witness refused")


def _scope(organization_id, issuer_did):
    require(type(organization_id) is str and type(issuer_did) is str)
    organization_id = str(uuid.UUID(organization_id))
    require(
        0 < len(issuer_did) <= 2048
        and re.fullmatch(r"did:[a-z0-9]+:[^\s\x00-\x1f]+", issuer_did)
    )
    body = json.dumps(
        {"organization_id": organization_id, "issuer_did": issuer_did},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return organization_id, issuer_did, hashlib.sha256(body).hexdigest()


def _literal(value):
    return "'" + value.replace("'", "''") + "'"


def _rows(name, predicate=None):
    fields = (
        "to_jsonb(candidate) AS _cohort_row, candidate.id::text AS _cohort_order_id, "
    )
    fields += "encode(sha256(convert_to(candidate.id::text,'UTF8')),'hex') AS _cohort_id_sha256"
    if predicate is None:
        fields += ", candidate.updated_at"
    else:
        fields += ", coalesce((" + predicate + "),false) AS _cohort_eligible"
    return (
        "SELECT "
        + fields
        + " FROM "
        + TABLES[name]
        + " candidate LIMIT "
        + str(membership.MAX_ROWS + 1)
    )


def before_sql(organization_id, issuer_did):
    organization_id, issuer_did, scope = _scope(organization_id, issuer_did)
    predicates = {
        "wallets": "candidate.id IN (" + ",".join(map(_literal, WALLETS)) + ")",
        "destinations": "candidate.id IN ("
        + ",".join(map(_literal, DESTINATIONS))
        + ")",
        "issuer": "candidate.organization_id::text="
        + _literal(organization_id)
        + " AND candidate.issuer_id="
        + _literal(issuer_did)
        + " AND (candidate.id::text="
        + _literal(ISSUER_ID)
        + " OR NOT EXISTS (SELECT 1 FROM trust_profile_service.issuer_entities WHERE id::text="
        + _literal(ISSUER_ID)
        + "))",
    }
    ctes = [name + " AS (" + _rows(name, predicates[name]) + ")" for name in TABLES]
    parts = [
        "'"
        + name
        + "',(SELECT "
        + membership._before_table(name, "'{}'::jsonb")
        + " FROM "
        + name
        + ")"
        for name in TABLES
    ]
    return (
        "WITH "
        + ",".join(ctes)
        + " SELECT jsonb_build_object('schema','"
        + SCHEMA
        + "','side','before','database_clock',clock_timestamp(),'scope_sha256','"
        + scope
        + "',"
        + ",".join(parts)
        + ");"
    )


def validate_before(value):
    require(
        type(value) is dict
        and set(value) == {"schema", "side", "database_clock", "scope_sha256", *TABLES}
    )
    require(value["schema"] == SCHEMA and value["side"] == "before")
    membership._clock(value["database_clock"])
    require(
        type(value["scope_sha256"]) is str
        and membership.SHA.fullmatch(value["scope_sha256"])
    )
    for name, expected_count in COUNTS.items():
        row = value[name]
        require(
            type(row) is dict
            and set(row)
            == {
                "row_count",
                "eligible_id_sha256",
                "observed_sha256",
                "expected_after_sha256",
            }
        )
        require(
            type(row["row_count"]) is int
            and expected_count <= row["row_count"] <= membership.MAX_ROWS
        )
        keys = row["eligible_id_sha256"]
        require(
            type(keys) is list
            and len(keys) == expected_count
            and keys == sorted(set(keys))
            and all(type(key) is str and membership.SHA.fullmatch(key) for key in keys)
        )
        require(
            all(
                type(row[key]) is str and membership.SHA.fullmatch(row[key])
                for key in ("observed_sha256", "expected_after_sha256")
            )
        )


def after_sql(before):
    validate_before(before)
    floor = membership._clock(before["database_clock"]).isoformat()
    ctes = [name + " AS (" + _rows(name) + ")" for name in TABLES]
    parts = [
        "'"
        + name
        + "',(SELECT "
        + membership._after_table(name, before[name]["eligible_id_sha256"], floor)
        + " FROM "
        + name
        + ")"
        for name in TABLES
    ]
    return (
        "WITH "
        + ",".join(ctes)
        + " SELECT jsonb_build_object('schema','"
        + SCHEMA
        + "','side','after','database_clock',clock_timestamp(),'scope_sha256','"
        + before["scope_sha256"]
        + "',"
        + ",".join(parts)
        + ");"
    )


def validate_delta(before, after):
    validate_before(before)
    require(
        type(after) is dict
        and set(after) == {"schema", "side", "database_clock", "scope_sha256", *TABLES}
    )
    require(
        after["schema"] == SCHEMA
        and after["side"] == "after"
        and after["scope_sha256"] == before["scope_sha256"]
        and membership._clock(after["database_clock"])
        >= membership._clock(before["database_clock"])
    )
    for name in TABLES:
        row, prior = after[name], before[name]
        require(
            type(row) is dict
            and set(row)
            == {"row_count", "masked_rows", "updated_at_in_window", "observed_sha256"}
        )
        require(
            type(row["row_count"]) is int
            and row["row_count"] == prior["row_count"]
            and type(row["masked_rows"]) is int
            and row["masked_rows"] == COUNTS[name]
            and row["updated_at_in_window"] is True
            and type(row["observed_sha256"]) is str
            and membership.SHA.fullmatch(row["observed_sha256"])
            and row["observed_sha256"] == prior["expected_after_sha256"]
        )
    return {
        "schema": "marty.windows-system-startup-timestamp-delta/v1",
        "native_admission": False,
        "product_transition_admission": False,
    }


def capture(
    docker,
    items,
    project,
    *,
    organization_id,
    issuer_did,
    before=None,
    profile=probe.LedgerProfile(),
):
    require(type(profile) is probe.LedgerProfile)
    scope = _scope(organization_id, issuer_did)[2]
    if before is not None:
        validate_before(before)
        require(before["scope_sha256"] == scope)
    statement = (
        before_sql(organization_id, issuer_did) if before is None else after_sql(before)
    )
    base = probe._postgres_base(items, project)
    result = json.loads(
        probe._text(
            docker,
            [
                base[0],
                "--interactive",
                *base[1:],
                "--dbname",
                profile.application,
                "--file=-",
            ],
            stdin_bytes=statement.encode(),
        )
    )
    if before is None:
        validate_before(result)
    else:
        validate_delta(before, result)
    require(result["scope_sha256"] == scope)
    return result
