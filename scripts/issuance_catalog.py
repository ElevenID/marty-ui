# SPDX-License-Identifier: AGPL-3.0-only
"""Compose the issuance catalog query from the same SQL inputs as the service."""
from pathlib import Path

_SCHEMA = Path(__file__).resolve().parents[1] / "rust/services/issuance/schema"


def scoped_catalog_query(scope: str) -> str:
    selector = (_SCHEMA / f"{scope}_catalog_scope.sql").read_text(encoding="utf-8")
    return selector + (_SCHEMA / "scoped_catalog_query.sql").read_text(encoding="utf-8")
