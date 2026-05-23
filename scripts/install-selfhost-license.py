#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def build_parser(repo_root: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate and install the self-host production license files into SELFHOST_SECRET_DIR.")
    parser.add_argument("--env-file", default=str(repo_root / ".env.selfhost.production.local"))
    parser.add_argument("--secret-dir", default="")
    parser.add_argument("--license-token-file", required=True)
    parser.add_argument(
        "--public-key-file",
        default="",
        help="Deprecated dev/test override. Commercial validation uses the embedded Marty public key.",
    )
    return parser


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root / "packages"))

    from marty_common.licensing import validate_runtime_license_from_env  # pylint: disable=import-error

    parser = build_parser(repo_root)
    args = parser.parse_args()

    env_file = Path(args.env_file).expanduser().resolve()
    env_values = load_env_file(env_file)
    secret_dir_value = args.secret_dir or env_values.get("SELFHOST_SECRET_DIR", "")
    if not secret_dir_value:
        raise SystemExit("SELFHOST_SECRET_DIR is required via --secret-dir or the env file.")

    secret_dir = Path(secret_dir_value).expanduser()
    secret_dir = secret_dir.resolve()
    secret_dir.mkdir(parents=True, exist_ok=True)

    license_token = Path(args.license_token_file).expanduser().resolve().read_text(encoding="utf-8").strip()
    validation_env = {
        "MARTY_LICENSE_ENFORCEMENT": env_values.get("MARTY_LICENSE_ENFORCEMENT", "required"),
        "MARTY_LICENSE_REQUIRED_ISSUER": env_values.get("MARTY_LICENSE_REQUIRED_ISSUER", "marty-license-issuer"),
        "MARTY_LICENSE_REQUIRED_PLAN_TIER": env_values.get("MARTY_LICENSE_REQUIRED_PLAN_TIER", "system"),
        "MARTY_LICENSE_REQUIRED_PRODUCTS": env_values.get("MARTY_LICENSE_REQUIRED_PRODUCTS", "ui-app"),
        "LICENSE_KEY": license_token,
    }
    if args.public_key_file:
        public_key = Path(args.public_key_file).expanduser().resolve().read_text(encoding="utf-8").strip()
        validation_env["MARTY_LICENSE_ALLOW_RUNTIME_PUBLIC_KEY"] = "true"
        validation_env["LICENSE_PUBLIC_KEY"] = public_key

    claims = validate_runtime_license_from_env(validation_env)

    (secret_dir / "license_key").write_text(license_token + "\n", encoding="utf-8")

    org_label = claims.org_name or claims.sub if claims else "unknown"
    plan_tier = claims.plan_tier if claims else "unknown"
    expiry = claims.expires_at.isoformat().replace("+00:00", "Z") if claims else "unknown"
    print(f"Installed self-host license for {org_label} (plan_tier={plan_tier}, expires_at={expiry})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())