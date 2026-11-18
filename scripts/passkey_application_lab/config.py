"""Explicit inputs supplied by the disposable application probe CLI."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ["MARTY_PASSKEY_APP_LAB_OUTPUT"])
IMAGE = os.environ["MARTY_PASSKEY_APP_LAB_IMAGE"]
NGINX_IMAGE = os.environ["MARTY_PASSKEY_APP_LAB_NGINX_IMAGE"]
KEYCLOAK_IMAGE = os.environ["MARTY_PASSKEY_APP_LAB_KEYCLOAK_IMAGE"]
UI_DIST = Path(os.environ["MARTY_PASSKEY_APP_LAB_UI_DIST"])
