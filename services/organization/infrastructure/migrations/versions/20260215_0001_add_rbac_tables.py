"""Add RBAC tables: roles, permissions, role_permissions, member_roles

Revision ID: 20260215_0001
Revises: 20260215_0000
Create Date: 2026-02-15 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
import uuid


# revision identifiers, used by Alembic.
revision = '20260215_0001'
down_revision = '20260215_0000'
branch_labels = None
depends_on = None

SCHEMA = "organization_service"

# ─────────────────────────────────────────────────────────────────────────────
# Default permission catalog: every resource × action pair in the platform
# ─────────────────────────────────────────────────────────────────────────────

PERMISSIONS = [
    # Trust profiles
    ("trust-profile", "view", "View trust profiles"),
    ("trust-profile", "create", "Create trust profiles"),
    ("trust-profile", "edit", "Edit trust profiles"),
    ("trust-profile", "delete", "Delete trust profiles"),
    ("trust-profile", "activate", "Activate trust profiles"),
    ("trust-profile", "suspend", "Suspend trust profiles"),
    # Trusted issuers
    ("trusted-issuer", "view", "View trusted issuers"),
    ("trusted-issuer", "create", "Create trusted issuers"),
    ("trusted-issuer", "edit", "Edit trusted issuers"),
    ("trusted-issuer", "delete", "Delete trusted issuers"),
    # Credential templates
    ("credential-template", "view", "View credential templates"),
    ("credential-template", "create", "Create credential templates"),
    ("credential-template", "edit", "Edit credential templates"),
    ("credential-template", "delete", "Delete credential templates"),
    ("credential-template", "activate", "Activate credential templates"),
    ("credential-template", "deprecate", "Deprecate credential templates"),
    ("credential-template", "version", "Create new version of credential templates"),
    # Compliance profiles
    ("compliance-profile", "view", "View compliance profiles"),
    ("compliance-profile", "create", "Create compliance profiles"),
    ("compliance-profile", "edit", "Edit compliance profiles"),
    ("compliance-profile", "delete", "Delete compliance profiles"),
    ("compliance-profile", "activate", "Activate compliance profiles"),
    ("compliance-profile", "suspend", "Suspend compliance profiles"),
    # Presentation policies
    ("presentation-policy", "view", "View presentation policies"),
    ("presentation-policy", "create", "Create presentation policies"),
    ("presentation-policy", "edit", "Edit presentation policies"),
    ("presentation-policy", "delete", "Delete presentation policies"),
    ("presentation-policy", "activate", "Activate presentation policies"),
    ("presentation-policy", "suspend", "Suspend presentation policies"),
    ("presentation-policy", "version", "Create new version of presentation policies"),
    ("presentation-policy", "evaluate", "Evaluate presentation policies"),
    # Revocation profiles
    ("revocation-profile", "view", "View revocation profiles"),
    ("revocation-profile", "create", "Create revocation profiles"),
    ("revocation-profile", "delete", "Delete revocation profiles"),
    ("revocation-profile", "activate", "Activate revocation profiles"),
    # Deployment profiles
    ("deployment-profile", "view", "View deployment profiles"),
    ("deployment-profile", "create", "Create deployment profiles"),
    ("deployment-profile", "edit", "Edit deployment profiles"),
    ("deployment-profile", "delete", "Delete deployment profiles"),
    ("deployment-profile", "activate", "Activate deployment profiles"),
    ("deployment-profile", "suspend", "Suspend deployment profiles"),
    # Flow definitions
    ("flow-definition", "view", "View flow definitions"),
    ("flow-definition", "create", "Create flow definitions"),
    ("flow-definition", "edit", "Edit flow definitions"),
    ("flow-definition", "delete", "Delete flow definitions"),
    ("flow-definition", "activate", "Activate flow definitions"),
    # Flow instances
    ("flow-instance", "view", "View flow instances"),
    ("flow-instance", "start", "Start flow instances"),
    ("flow-instance", "advance", "Advance flow instances"),
    ("flow-instance", "cancel", "Cancel flow instances"),
    # Issuance
    ("issuance", "view", "View issuance transactions"),
    ("issuance", "initiate", "Initiate credential issuance"),
    # Application templates
    ("application-template", "view", "View application templates"),
    ("application-template", "create", "Create application templates"),
    ("application-template", "edit", "Edit application templates"),
    ("application-template", "delete", "Delete application templates"),
    ("application-template", "activate", "Activate application templates"),
    # Applications
    ("application", "view", "View applications"),
    ("application", "review", "Review applications, checks, and reviewer locks"),
    ("application", "approve", "Approve applications"),
    ("application", "reject", "Reject applications"),
    # Organization
    ("organization", "view", "View organization details"),
    ("organization", "edit", "Edit organization settings"),
    # Team / Members
    ("team", "view", "View team members"),
    ("team", "invite", "Invite team members"),
    ("team", "manage", "Change member roles and remove members"),
    # Roles
    ("role", "view", "View roles"),
    ("role", "create", "Create custom roles"),
    ("role", "edit", "Edit roles and their permissions"),
    ("role", "delete", "Delete custom roles"),
    ("role", "assign", "Assign or remove roles from members"),
    # API keys
    ("api-key", "view", "View API keys"),
    ("api-key", "create", "Create API keys"),
    ("api-key", "edit", "Edit API keys"),
    ("api-key", "revoke", "Revoke API keys"),
    ("api-key", "delete", "Delete API keys"),
    # Signing keys
    ("signing-key", "view", "View signing keys"),
    ("signing-key", "create", "Create signing keys"),
    ("signing-key", "delete", "Delete signing keys"),
    # Webhooks
    ("webhook", "view", "View webhooks"),
    ("webhook", "create", "Create webhooks"),
    ("webhook", "edit", "Edit webhooks"),
    ("webhook", "delete", "Delete webhooks"),
    ("webhook", "test", "Test webhooks"),
    # Integration connectors
    ("integration-connector", "view", "View external protocol connectors"),
    ("integration-connector", "create", "Create external protocol connectors"),
    ("integration-connector", "edit", "Edit external protocol connectors"),
    ("integration-connector", "delete", "Delete external protocol connectors"),
    # Notifications
    ("notification", "view", "View notifications"),
    ("notification", "send", "Send notifications"),
    # Audit
    ("audit", "view", "View audit logs"),
    ("audit", "export", "Export audit logs"),
    # Verification
    ("verification", "view", "View verification results"),
    ("verification", "execute", "Execute verification flows"),
]

# ─────────────────────────────────────────────────────────────────────────────
# System role templates  (copied into each organisation on creation)
# ─────────────────────────────────────────────────────────────────────────────
# owner        – everything + ownership transfer
# admin        – everything except ownership transfer
# access_admin – settings, team, roles, API keys, signing keys, webhooks, audit
# catalog_admin – trust, compliance, templates, deployments, flow definitions
# reviewer     – application review plus related read access
# operator     – issuance, verification, and operational flow execution
# viewer       – read-only org console access
# applicant    – catalog/application access without org console access

_ALL_PERMS = [(r, a) for r, a, _d in PERMISSIONS]
_PERMS_BY_RESOURCE: dict[str, list[tuple[str, str]]] = {}
for resource, action, _description in PERMISSIONS:
    _PERMS_BY_RESOURCE.setdefault(resource, []).append((resource, action))


def _perms_for(*resources: str) -> list[tuple[str, str]]:
    perms: list[tuple[str, str]] = []
    for resource in resources:
        perms.extend(_PERMS_BY_RESOURCE.get(resource, []))
    return perms


def _view_perms_for(*resources: str) -> list[tuple[str, str]]:
    return [
        (resource, action)
        for resource, action, _ in PERMISSIONS
        if resource in resources and action == "view"
    ]


_ACCESS_ADMIN_PERMS = _perms_for(
    "organization",
    "team",
    "role",
    "api-key",
    "signing-key",
    "webhook",
    "integration-connector",
    "notification",
    "audit",
)

_CATALOG_ADMIN_PERMS = _perms_for(
    "trust-profile",
    "trusted-issuer",
    "credential-template",
    "compliance-profile",
    "presentation-policy",
    "revocation-profile",
    "deployment-profile",
    "flow-definition",
    "application-template",
    "integration-connector",
)

_REVIEWER_PERMS = sorted(
    set(
        _view_perms_for(
            "organization",
            "trust-profile",
            "trusted-issuer",
            "credential-template",
            "compliance-profile",
            "presentation-policy",
            "revocation-profile",
            "deployment-profile",
            "application-template",
            "application",
        )
        + [("application", "review"), ("application", "approve"), ("application", "reject")]
    )
)

_OPERATOR_PERMS = sorted(
    set(
        _view_perms_for(
            "organization",
            "trust-profile",
            "credential-template",
            "application-template",
            "deployment-profile",
            "flow-definition",
            "flow-instance",
            "issuance",
            "verification",
        )
        + [
            ("flow-instance", "start"),
            ("flow-instance", "advance"),
            ("flow-instance", "cancel"),
            ("issuance", "initiate"),
            ("verification", "execute"),
        ]
    )
)

_VIEWER_PERMS = [(r, a) for r, a, _ in PERMISSIONS if a == "view"]
_APPLICANT_PERMS = [
    ("organization", "view"),
    ("credential-template", "view"),
    ("application-template", "view"),
    ("application", "view"),
    ("issuance", "view"),
]

SYSTEM_ROLES = [
    {
        "name": "owner",
        "display_name": "Owner",
        "description": "Full access. Can transfer ownership.",
        "permissions": _ALL_PERMS,
    },
    {
        "name": "admin",
        "display_name": "Administrator",
        "description": "Full access to all organization resources and settings.",
        "permissions": _ALL_PERMS,
    },
    {
        "name": "access_admin",
        "display_name": "Access Administrator",
        "description": "Manages organization settings, team access, roles, keys, webhooks, notifications, and audit.",
        "permissions": _ACCESS_ADMIN_PERMS,
    },
    {
        "name": "catalog_admin",
        "display_name": "Catalog Administrator",
        "description": "Manages trust, compliance, templates, deployment profiles, flow definitions, and application templates.",
        "permissions": _CATALOG_ADMIN_PERMS,
    },
    {
        "name": "reviewer",
        "display_name": "Reviewer",
        "description": "Reviews applications and related organization artifacts.",
        "permissions": _REVIEWER_PERMS,
    },
    {
        "name": "operator",
        "display_name": "Operator",
        "description": "Runs issuance, verification, and operational flows.",
        "permissions": _OPERATOR_PERMS,
    },
    {
        "name": "viewer",
        "display_name": "Viewer",
        "description": "Read-only access to organization console resources.",
        "permissions": _VIEWER_PERMS,
    },
    {
        "name": "applicant",
        "display_name": "Applicant",
        "description": "Catalog and application access without organization console access.",
        "permissions": _APPLICANT_PERMS,
    },
]


def upgrade() -> None:
    # ── 1. permissions (global catalog) ──────────────────────────────────────
    op.create_table(
        "permissions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("resource", sa.String(100), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.UniqueConstraint("resource", "action", name="uq_permissions_resource_action"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_permissions_resource",
        "permissions",
        ["resource"],
        schema=SCHEMA,
    )

    # ── 2. roles (per-org) ───────────────────────────────────────────────────
    op.create_table(
        "roles",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey(f"{SCHEMA}.organizations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_default_for_new_members", sa.Boolean(), nullable=False,
                  server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "name", name="uq_roles_org_name"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_roles_organization_id",
        "roles",
        ["organization_id"],
        schema=SCHEMA,
    )

    # ── 3. role_permissions (many-to-many) ───────────────────────────────────
    op.create_table(
        "role_permissions",
        sa.Column("role_id", UUID(as_uuid=True),
                  sa.ForeignKey(f"{SCHEMA}.roles.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("permission_id", UUID(as_uuid=True),
                  sa.ForeignKey(f"{SCHEMA}.permissions.id", ondelete="CASCADE"),
                  primary_key=True),
        schema=SCHEMA,
    )

    # ── 4. member_roles (many-to-many) ───────────────────────────────────────
    op.create_table(
        "member_roles",
        sa.Column("member_id", UUID(as_uuid=True),
                  sa.ForeignKey(f"{SCHEMA}.members.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("role_id", UUID(as_uuid=True),
                  sa.ForeignKey(f"{SCHEMA}.roles.id", ondelete="CASCADE"),
                  primary_key=True),
        schema=SCHEMA,
    )

    # ── 5. Seed permission catalog ───────────────────────────────────────────
    permissions_table = sa.table(
        "permissions",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("resource", sa.String),
        sa.column("action", sa.String),
        sa.column("description", sa.Text),
        schema=SCHEMA,
    )

    # Build a (resource, action) → UUID mapping for use in role seeding
    perm_ids: dict[tuple[str, str], str] = {}
    rows = []
    for resource, action, description in PERMISSIONS:
        pid = str(uuid.uuid4())
        perm_ids[(resource, action)] = pid
        rows.append({
            "id": pid,
            "resource": resource,
            "action": action,
            "description": description,
        })

    op.bulk_insert(permissions_table, rows)

    # ── 6. Seed system roles for every existing organization ─────────────────
    conn = op.get_bind()
    org_rows = conn.execute(
        sa.text("SELECT id FROM organization_service.organizations")
    ).fetchall()

    roles_table = sa.table(
        "roles",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("organization_id", UUID(as_uuid=True)),
        sa.column("name", sa.String),
        sa.column("display_name", sa.String),
        sa.column("description", sa.Text),
        sa.column("is_system", sa.Boolean),
        sa.column("is_default_for_new_members", sa.Boolean),
        sa.column("created_at", sa.DateTime),
        sa.column("updated_at", sa.DateTime),
        schema=SCHEMA,
    )

    rp_table = sa.table(
        "role_permissions",
        sa.column("role_id", UUID(as_uuid=True)),
        sa.column("permission_id", UUID(as_uuid=True)),
        schema=SCHEMA,
    )

    member_roles_table = sa.table(
        "member_roles",
        sa.column("member_id", UUID(as_uuid=True)),
        sa.column("role_id", UUID(as_uuid=True)),
        schema=SCHEMA,
    )

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    for (org_id_val,) in org_rows:
        org_id = str(org_id_val)
        role_name_to_id: dict[str, str] = {}

        # Create system roles for this org
        role_rows = []
        rp_rows = []
        for tmpl in SYSTEM_ROLES:
            role_id = str(uuid.uuid4())
            role_name_to_id[tmpl["name"]] = role_id
            role_rows.append({
                "id": role_id,
                "organization_id": org_id,
                "name": tmpl["name"],
                "display_name": tmpl["display_name"],
                "description": tmpl["description"],
                "is_system": True,
                "is_default_for_new_members": tmpl["name"] == "applicant",
                "created_at": now,
                "updated_at": now,
            })
            for resource, action in tmpl["permissions"]:
                rp_rows.append({
                    "role_id": role_id,
                    "permission_id": perm_ids[(resource, action)],
                })

        if role_rows:
            op.bulk_insert(roles_table, role_rows)
        if rp_rows:
            op.bulk_insert(rp_table, rp_rows)

        # Existing fresh-reset environments do not need to migrate a legacy
        # members.role column into member_roles.


def downgrade() -> None:
    op.drop_table("member_roles", schema=SCHEMA)
    op.drop_table("role_permissions", schema=SCHEMA)
    op.drop_table("roles", schema=SCHEMA)
    op.drop_index("ix_permissions_resource", table_name="permissions", schema=SCHEMA)
    op.drop_table("permissions", schema=SCHEMA)
