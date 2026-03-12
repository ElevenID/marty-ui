"""Update MemberCredential wallet_config display_names to be wallet-centric.

Previously the display_name in each wallet config described the credential
being issued ("Member Credential", "Member Credential (Marty Authenticator)").
This makes the QR-code tab labels confusing — users should see the wallet name
so they know which app to use, not the credential name.

Updated labels
--------------
  wr-default    "Member Credential"                      → "Any OID4VCI Wallet"
  wr-marty-001  "Member Credential (Marty Authenticator)" → "Marty Authenticator"

Applies to every credential_template row whose wallet_configs contains a
wallet_id of "wr-default" or "wr-marty-001", i.e. all MemberCredential
templates across any organisation.

Revision ID: 20260308_0001
Revises: 20260307_0001
Create Date: 2026-03-08 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# ---------------------------------------------------------------------------
# Alembic revision metadata
# ---------------------------------------------------------------------------
revision = "20260308_0001"
down_revision = "20260307_0001"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"

# wallet_id → new display_name
LABEL_UPDATES = {
    "wr-default":   "Any OID4VCI Wallet",
    "wr-marty-001": "Marty Authenticator",
}


def upgrade() -> None:
    conn = op.get_bind()

    for wallet_id, new_label in LABEL_UPDATES.items():
        conn.execute(
            sa.text(
                """
                UPDATE credential_template_service.credential_templates
                   SET wallet_configs = (
                       SELECT jsonb_agg(
                           CASE
                               WHEN elem->>'wallet_id' = :wallet_id
                               THEN jsonb_set(elem, '{display_name}', to_jsonb(CAST(:new_label AS text)))
                               ELSE elem
                           END
                       )
                       FROM jsonb_array_elements(CAST(wallet_configs AS jsonb)) AS elem
                   )
                 WHERE CAST(wallet_configs AS jsonb) @> jsonb_build_array(
                           jsonb_build_object('wallet_id', :wallet_id)
                       )
                """
            ),
            {"wallet_id": wallet_id, "new_label": new_label},
        )


def downgrade() -> None:
    old_labels = {
        "wr-default":   "Member Credential",
        "wr-marty-001": "Member Credential (Marty Authenticator)",
    }
    conn = op.get_bind()

    for wallet_id, old_label in old_labels.items():
        conn.execute(
            sa.text(
                """
                UPDATE credential_template_service.credential_templates
                   SET wallet_configs = (
                       SELECT jsonb_agg(
                           CASE
                               WHEN elem->>'wallet_id' = :wallet_id
                               THEN jsonb_set(elem, '{display_name}', to_jsonb(CAST(:old_label AS text)))
                               ELSE elem
                           END
                       )
                       FROM jsonb_array_elements(CAST(wallet_configs AS jsonb)) AS elem
                   )
                 WHERE CAST(wallet_configs AS jsonb) @> jsonb_build_array(
                           jsonb_build_object('wallet_id', :wallet_id)
                       )
                """
            ),
            {"wallet_id": wallet_id, "old_label": old_label},
        )
