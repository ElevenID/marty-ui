"""Opt-in real Marty passkey regression on disposable development services.

Requires locally built, source-matched application/UI and qualified Keycloak/KMS
images. Creates synthetic accounts and data; never starts the base Compose stack.
See docs/keycloak-passkeys.md for the qualification limits.
"""

import argparse
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import urllib.parse
from pathlib import Path

import probe_keycloak_remote_rs256 as kms

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "scripts" / "passkey_application_lab"


def image_state(reference):
    return json.loads(
        subprocess.check_output(["docker", "image", "inspect", reference], text=True)
    )[0]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, LAB / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-image", required=True)
    parser.add_argument("--openbao-image", required=True)
    parser.add_argument("--application-image", required=True)
    parser.add_argument("--nginx-image", required=True)
    parser.add_argument("--ui-dist", required=True, type=Path)
    parser.add_argument(
        "--administrator",
        action="store_true",
        help="Exercise the seeded administrator instead of an applicant",
    )
    parser.add_argument(
        "--badge",
        action="store_true",
        help="Also issue a real test Badge, verify its login and enroll through captured native email",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="New private directory outside the source checkout",
    )
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if output.is_relative_to(ROOT) or output.exists():
        parser.error("--output-dir must be a new directory outside the source checkout")
    ui = args.ui_dist.resolve(strict=True)
    manifest = json.loads((ui / "marty-web-routes.json").read_text())
    if manifest.get("surface") != "application":
        parser.error("--ui-dist must contain the built application surface")
    application = image_state(args.application_image)
    revision = (application["Config"].get("Labels") or {}).get("marty.source")
    if not revision or revision != manifest.get("source_sha"):
        parser.error("Application image marty.source and UI source_sha must match")
    # Comparing actual component content permits later test/docs-only commits,
    # while refusing stale runtime binaries or an unbuilt runtime edit.
    subprocess.run(
        [
            "git",
            "diff",
            "--exit-code",
            revision,
            "--",
            "rust",
            "proto",
            "services/Dockerfile",
            "services/entrypoint.sh",
            "ui",
        ],
        cwd=ROOT,
        check=True,
    )
    keycloak = image_state(args.keycloak_image)["Id"]
    bao = image_state(args.openbao_image)["Id"]
    nginx = image_state(args.nginx_image)["Id"]
    output.mkdir(parents=True, mode=0o700)
    for name, value in {
        "OUTPUT": str(output),
        "IMAGE": application["Id"],
        "NGINX_IMAGE": nginx,
        "KEYCLOAK_IMAGE": keycloak,
        "UI_DIST": str(ui),
    }.items():
        os.environ["MARTY_PASSKEY_APP_LAB_" + name] = value
    sys.path.insert(0, str(LAB))
    sys.path.insert(0, str(ROOT))
    model = load("passkey_application_model", "model.py")
    model.prepare()
    login = load("passkey_application_login", "login.py")
    workload = load("passkey_application_workloads", "workloads.py")

    class QualifiedApplication(workload.WorkloadMixin, login.LoginLab):
        profile_path = "/console/applicant/profile"

        def setup_client(self, admin, token, origin):
            applicant = super().setup_client(admin, token, origin)
            if not args.administrator:
                return applicant
            email = self.settings["MARTY_ORG_ADMIN_EMAIL"]
            password = secrets.token_urlsafe(32)
            self.sensitive.append(password)
            login.native.request(
                admin + "/users",
                token=token,
                body={
                    "username": email,
                    "email": email,
                    "emailVerified": True,
                    "enabled": True,
                    "firstName": "Passkey",
                    "lastName": "Administrator",
                    "attributes": {"user_type": ["admin"]},
                    "credentials": [
                        {"type": "password", "value": password, "temporary": False}
                    ],
                },
            )
            subject = login.native.request(
                admin
                + "/users?"
                + urllib.parse.urlencode(
                    {
                        "username": email,
                        "exact": "true",
                    }
                ),
                token=token,
            )[0]["id"]
            return email, password, subject

        def browser_journey(self, *arguments):
            super().browser_journey(*arguments)
            expected = "administrator" if args.administrator else "applicant"
            assert self.application_baseline_user["user_type"] == expected

    application_class = (
        load("passkey_application_badge", "badge.py").BadgeLab
        if args.badge
        else QualifiedApplication
    )

    def qualify(context):
        application_class(context).bootstrap()

    kms.probe(
        keycloak, bao, Path("unused"), require_browser=True, qualify_ready=qualify
    )
    # This marker is emitted only after the parent KMS/custody checks and cleanup
    # have also completed. Earlier per-journey files are partial diagnostics.
    (output / "qualification-complete.json").write_text(
        json.dumps(
            {
                "application_source": revision,
                "application_image": application["Id"],
                "keycloak_image": keycloak,
                "openbao_image": bao,
                "scope": "disposable development stack with Chrome virtual authenticator",
                "application_passkey_journey": True,
                "account_type": "administrator_and_badge_applicant"
                if args.badge
                else ("administrator" if args.administrator else "applicant"),
                "parent_custody_checks": True,
                "badge_login_and_native_email_enrollment": args.badge,
                "physical_device_or_google_login": False,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(
        "Disposable application passkey and parent custody qualification PASSED",
        flush=True,
    )


if __name__ == "__main__":
    main()
