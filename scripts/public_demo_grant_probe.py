"""Dedicated grant policy qualification within the existing disposable controller.

This module has no deployment entry point. Its caller creates and guards the
isolated OpenBao/Redis fixtures; no operator token or endpoint is discovered.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "deploy-config/compose/public-verification/openbao"
ORIGINS = (
    "gateway-service",
    "gateway-issuer-did",
    "flow-wallet",
    "issuance-credential",
    "issuance-canvas",
    "issuance-readiness",
    "issuance-passport",
    "flow-demo-holder",
)
CASE = "verifier::tests::live_grant_verification_is_one_use_before_kms_signing"


def command(*, discovery=False):
    return [
        "cargo",
        "+1.95.0",
        "test",
        "-p",
        "marty-signing-grant",
        "--lib",
        "--locked",
        "--offline",
        "-j1",
        CASE,
        "--",
        "--ignored",
        "--exact",
        *(["--list"] if discovery else ["--nocapture"]),
    ]


def discovered(result):
    return result.returncode == 0 and [
        line for line in result.stdout.splitlines() if line.endswith(": test")
    ] == [f"{CASE}: test"]


def require(condition, operation):
    if not condition:
        raise RuntimeError(
            f"Disposable public demo grant qualification refused: {operation}"
        )


def native_succeeded(result):
    return result.returncode == 0 and bool(
        re.search(
            r"^test result: ok\. 1 passed; 0 failed;", result.stdout, re.MULTILINE
        )
    )


def qualify(call, root, environment, *, runner=subprocess.run):
    """Use real Transit and the native minter/verifier on a guarded fixture."""
    require(
        environment.get("MARTY_TEST_OPENBAO_ROOT_TOKEN") == root,
        "controller authority must match the native guard",
    )
    policy = (INPUTS / "verify-with-demo-holder.hcl").read_text(encoding="utf-8")
    legacy = "\n".join(
        line for line in policy.splitlines() if "flow-demo-holder" not in line
    )
    status, current = call("GET", "sys/policies/acl/sign-grant-verify", root)
    require(
        status == 200
        and current.get("data", {}).get("policy", "").strip()
        in (legacy.strip(), policy.strip()),
        "preserve unexpected verifier policy",
    )
    key = "marty-sign-grant-flow-demo-holder-v1"
    status, _ = call(
        "POST",
        f"transit/keys/{key}",
        root,
        json.loads((INPUTS / "demo-holder-key.json").read_text()),
    )
    require(status in (200, 204), "create dedicated MAC key")
    for name, body in (
        (
            "sign-grant-mint-flow-demo-holder",
            (INPUTS / "mint-flow-demo-holder.hcl").read_text(),
        ),
        ("sign-grant-verify", policy),
    ):
        require(
            call("POST", f"sys/policies/acl/{name}", root, {"policy": body})[0]
            in (200, 204),
            "apply reviewed policy input",
        )
        status, actual = call("GET", f"sys/policies/acl/{name}", root)
        require(
            status == 200
            and actual.get("data", {}).get("policy", "").strip() == body.strip(),
            "exact policy readback",
        )

    def token(policy_name):
        status, result = call(
            "POST",
            "auth/token/create",
            root,
            {
                "policies": [policy_name],
                "no_default_policy": True,
                "ttl": "10m",
                "explicit_max_ttl": "10m",
            },
        )
        require(status == 200, "issue short-lived scoped fixture token")
        value = result.get("auth", {}).get("client_token")
        require(
            isinstance(value, str) and value and value != root, "scoped token identity"
        )
        status, lookup = call("POST", "auth/token/lookup", root, {"token": value})
        require(
            status == 200
            and lookup["data"]["policies"] == [policy_name]
            and not lookup["data"].get("entity_id"),
            "no inherited token authority",
        )
        return value

    minters = {origin: token(f"sign-grant-mint-{origin}") for origin in ORIGINS}
    verifier = token("sign-grant-verify")
    require(
        len(set([root, verifier, *minters.values()])) == len(ORIGINS) + 2,
        "all fixture capabilities must be distinct",
    )
    payload = {"input": base64.b64encode(b"public-demo-grant-scope-probe").decode()}
    for origin in ORIGINS:
        name = f"marty-sign-grant-{origin}-v1"
        status, metadata = call("GET", f"transit/keys/{name}", root)
        data = metadata.get("data", {})
        require(
            status == 200
            and data.get("type") == "hmac"
            and data.get("exportable") is False
            and data.get("allow_plaintext_backup") is False,
            "non-exportable MAC custody",
        )
        status, minted = call(
            "POST", f"transit/hmac/{name}/sha2-256", minters[origin], payload
        )
        require(status == 200, "same-origin mint")
        proof = {**payload, "hmac": minted["data"]["hmac"]}
        status, verified = call(
            "POST", f"transit/verify/{name}/sha2-256", verifier, proof
        )
        require(
            status == 200 and verified.get("data", {}).get("valid") is True,
            "same-origin verify",
        )
        require(
            call("POST", f"transit/hmac/{name}/sha2-256", verifier, payload)[0] == 403,
            "verifier cannot mint",
        )
        require(
            call("POST", f"transit/verify/{name}/sha2-256", minters[origin], proof)[0]
            == 403,
            "minter cannot verify",
        )
        for other in ORIGINS:
            if other == origin:
                continue
            target = f"marty-sign-grant-{other}-v1"
            require(
                call(
                    "POST", f"transit/hmac/{target}/sha2-256", minters[origin], payload
                )[0]
                == 403,
                "cross-origin mint denial",
            )
            status, wrong = call(
                "POST", f"transit/verify/{target}/sha2-256", verifier, proof
            )
            require(
                status == 200 and wrong.get("data", {}).get("valid") is False,
                "distinct origin MAC keys",
            )
    for path, body in (
        ("auth/token/create", {"policies": ["root"]}),
        (
            "sys/policies/acl/unauthorized-demo",
            {"policy": 'path "*" { capabilities = ["sudo"] }'},
        ),
        (f"transit/keys/{key}/config", {"exportable": True}),
        ("transit/keys/unauthorized-demo", {"type": "ecdsa-p256"}),
        ("transit/sign/demo-holder-forbidden", payload),
    ):
        require(
            call("POST", path, minters["flow-demo-holder"], body)[0] == 403,
            "demo minter cannot provision, sign directly or elevate",
        )
    native_env = dict(
        environment,
        MARTY_TEST_GRANT_ORIGIN="flow_demo_holder",
        MARTY_TEST_GRANT_MINT_TOKEN=minters["flow-demo-holder"],
        MARTY_TEST_GRANT_VERIFY_TOKEN=verifier,
    )
    result = runner(
        command(),
        cwd=ROOT / "rust",
        env=native_env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if not native_succeeded(result):
        detail = result.stdout + result.stderr
        for secret in (root, verifier, *minters.values()):
            detail = detail.replace(secret, "[fixture-capability]")
        raise RuntimeError(
            f"Native demo grant/replay qualification failed:\n{detail[-2000:]}"
        )
    return {
        "scope": "ISOLATED_REMOTE_DEMO_GRANT_AND_REPLAY",
        "origins": len(ORIGINS),
        "nativePassed": 1,
        "nativeCase": CASE,
        "asymmetricHolderSigningQualified": False,
        "walletQualified": False,
        "deployedConfigurationChanged": False,
    }
