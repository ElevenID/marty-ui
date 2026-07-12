"""
Canonical permission catalog.

Single source of truth for every resource × action pair in the platform.
Used by:
  • Alembic migration (seed data)
  • RoleUseCase (system-role templates)
  • Frontend permissions.js should mirror this list

Each entry is (resource, action, description).
"""

PERMISSION_CATALOG: list[tuple[str, str, str]] = [
    # Trust profiles
    ("trust-profile", "view", "View trust profiles"),
    ("trust-profile", "create", "Create trust profiles"),
    ("trust-profile", "edit", "Edit trust profiles"),
    ("trust-profile", "delete", "Delete trust profiles"),
    ("trust-profile", "activate", "Activate trust profiles"),
    ("trust-profile", "suspend", "Suspend trust profiles"),
    # Cedar policy sets
    ("policy-set", "view", "View Cedar policy sets"),
    ("policy-set", "create", "Create Cedar policy sets"),
    ("policy-set", "edit", "Edit Cedar policy sets"),
    ("policy-set", "delete", "Delete Cedar policy sets"),
    ("policy-set", "activate", "Activate Cedar policy sets"),
    ("policy-set", "archive", "Archive Cedar policy sets"),
    ("policy-set", "validate", "Validate Cedar policy sets"),
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
