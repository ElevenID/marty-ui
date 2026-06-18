#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "packages"))

from marty_common.licensing import (  # pylint: disable=import-error
    LicenseValidationError,
    is_placeholder_value,
    validate_runtime_license_from_env,
)
from marty_common.migration_profile import normalize_migration_profile  # pylint: disable=import-error
from marty_common.system_ids import MARTY_OPEN_BADGE_LOGIN_POLICY_ID  # pylint: disable=import-error
from marty_devops import DeploymentCatalog  # pylint: disable=import-error


class CheckError(RuntimeError):
    """Raised when a self-host production check fails."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from following redirects outside our control."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


OPEN_BADGE_LOGIN_POLICY_ID = MARTY_OPEN_BADGE_LOGIN_POLICY_ID
TEXT_BUNDLE_SUFFIXES = {".css", ".html", ".js", ".json", ".map", ".txt"}
ORIGIN_RE = re.compile(r"https?://[A-Za-z0-9.-]+(?::\d+)?")


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


def load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def read_required_secret(path: Path, label: str) -> str:
    if not path.exists():
        raise CheckError(f"{label} file is missing: {path}")
    if not path.is_file():
        raise CheckError(f"{label} must be a regular file, not a directory: {path}")

    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise CheckError(f"{label} file is empty: {path}")
    if is_placeholder_value(value):
        raise CheckError(f"{label} still uses a shipped placeholder value: {path}")
    return value


def run_compose_command(env_file: Path, compose_file: Path, *extra_args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(env_file),
            "-f",
            str(compose_file),
            *extra_args,
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def ensure_compose_config(env_file: Path, compose_file: Path) -> None:
    result = run_compose_command(env_file, compose_file, "config")
    if result.returncode != 0:
        error_output = (result.stderr or result.stdout).strip()
        raise CheckError(f"{compose_file.name} config failed: {error_output}")


def parse_compose_ps_output(raw_output: str) -> list[dict[str, Any]]:
    stripped = raw_output.strip()
    if not stripped:
        return []

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        entries: list[dict[str, Any]] = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
        return entries

    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return parsed
    raise CheckError("docker compose ps returned an unsupported JSON payload.")


def get_compose_services(env_file: Path, compose_file: Path) -> list[dict[str, Any]]:
    result = run_compose_command(env_file, compose_file, "ps", "--format", "json")
    if result.returncode != 0:
        error_output = (result.stderr or result.stdout).strip()
        raise CheckError(f"{compose_file.name} ps failed: {error_output}")
    return parse_compose_ps_output(result.stdout)


def validate_license(env_values: dict[str, str], secret_dir: Path) -> str:
    claims = validate_runtime_license_from_env(
        {
            **env_values,
            "LICENSE_KEY_FILE": str(secret_dir / "license_key"),
        }
    )
    if claims is None:
        raise CheckError("License enforcement is disabled; no runtime license validation occurred.")
    products = ",".join(claims.entitled_products) or "<none>"
    return (
        f"subject={claims.sub} plan_tier={claims.plan_tier or 'none'} "
        f"products={products} expires_at={claims.expires_at.isoformat().replace('+00:00', 'Z')}"
    )


def validate_required_secret_files(secret_dir: Path, catalog: DeploymentCatalog, stack_name: str) -> str:
    checked: list[str] = []
    for secret in catalog.required_secret_specs_for_stack(stack_name):
        secret_id = str(secret["id"])
        file_name = str(secret.get("compose_secret") or secret_id)
        read_required_secret(secret_dir / file_name, secret_id)
        checked.append(secret_id)

    return "files=" + ",".join(checked)


def validate_tunnel_token(secret_dir: Path) -> str:
    token = read_required_secret(secret_dir / "cloudflare_tunnel_token", "Cloudflare tunnel token")
    return f"token_length={len(token)}"


def is_enabled(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on", "enabled"}


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def normalized_origin(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise CheckError(f"Invalid URL origin: {value!r}")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def configured_ui_origins(env_values: dict[str, str]) -> list[str]:
    origins: list[str] = []
    for raw_origin in [env_values.get("UI_BASE_URL", ""), *split_csv(env_values.get("UI_ADDITIONAL_BASE_URLS"))]:
        if not raw_origin.strip():
            continue
        origin = normalized_origin(raw_origin)
        if origin not in origins:
            origins.append(origin)
    return origins


def validate_google_social_login(env_values: dict[str, str], secret_dir: Path) -> str:
    if not is_enabled(env_values.get("KEYCLOAK_SOCIAL_LOGIN_ENABLED")):
        return "disabled"

    read_required_secret(secret_dir / "google_client_id", "Google OAuth client ID")
    read_required_secret(secret_dir / "google_client_secret", "Google OAuth client secret")

    public_domain = env_values.get("PUBLIC_DOMAIN", "").strip()
    if not public_domain:
        raise CheckError("PUBLIC_DOMAIN is required when Google social login is enabled.")
    realm = env_values.get("KEYCLOAK_REALM", "11id").strip() or "11id"
    return f"enabled redirect_uri=https://{public_domain}/realms/{realm}/broker/google/endpoint"


def validate_migration_profile(env_values: dict[str, str]) -> str:
    profile = normalize_migration_profile(env_values.get("MARTY_MIGRATION_PROFILE"))
    if profile != "selfhost-production":
        raise CheckError(
            "MARTY_MIGRATION_PROFILE must resolve to selfhost-production for the self-host stack; "
            f"current={profile}"
        )
    return f"profile={profile}"


def validate_selfhost_catalog_templates(env_file: Path, compose_file: Path) -> str:
    open_badge_template_id = "50000000-0000-0000-0000-000000000040"
    query = """
        SELECT id, name, status
          FROM credential_template_service.credential_templates
         WHERE organization_id = '00000000-0000-0000-0000-000000000001'
           AND status = 'active'
         ORDER BY id;
    """
    result = run_compose_command(
        env_file,
        compose_file,
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "postgres",
        "-d",
        "marty",
        "-t",
        "-A",
        "-F",
        "\t",
        "-c",
        query,
    )
    if result.returncode != 0:
        error_output = (result.stderr or result.stdout).strip()
        raise CheckError(f"Unable to query credential template catalog: {error_output}")

    active_templates: list[tuple[str, str, str]] = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split("\t")
        if len(parts) != 3:
            raise CheckError(f"Unexpected credential template catalog row: {stripped}")
        active_templates.append((parts[0], parts[1], parts[2]))

    active_ids = [template_id for template_id, _, _ in active_templates]
    if active_ids != [open_badge_template_id]:
        details = ",".join(f"{template_id}:{name}" for template_id, name, _ in active_templates) or "<none>"
        raise CheckError(
            "Self-host production catalog must expose only the Open Badge login template; "
            f"active_templates={details}"
        )

    return f"active_template={active_templates[0][0]}:{active_templates[0][1]}"


def validate_managed_openbao_signing(env_file: Path, compose_file: Path) -> str:
    command = r"""
python - <<'PY'
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

api_key_file = os.environ.get("ISSUANCE_API_KEY_FILE") or "/run/secrets/issuance_api_key"
try:
    api_key = pathlib.Path(api_key_file).read_text(encoding="utf-8").strip()
except OSError as exc:
    print(f"Unable to read issuance API key secret at {api_key_file}: {exc}", file=sys.stderr)
    raise SystemExit(20) from exc

payload = {"payload_b64": "dGVzdA", "algorithm": "ES256", "key_reference": "cred-issuer-marty-es256"}
request = urllib.request.Request(
    "http://127.0.0.1:8000/internal/signing-keys/services/managed-openbao-transit/sign?organization_id=00000000-0000-0000-0000-000000000001",
    data=json.dumps(payload).encode("utf-8"),
    headers={"X-API-Key": api_key, "Content-Type": "application/json"},
    method="POST",
)

try:
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - in-container operator health check
        print(response.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8", errors="replace").strip()
    print(f"HTTP {exc.code}: {body}", file=sys.stderr)
    raise SystemExit(exc.code) from exc
except OSError as exc:
    print(f"Managed OpenBao signing endpoint is unreachable: {exc}", file=sys.stderr)
    raise SystemExit(21) from exc
PY
""".strip()
    result = run_compose_command(
        env_file,
        compose_file,
        "exec",
        "-T",
        "gateway",
        "sh",
        "-lc",
        command,
    )
    if result.returncode != 0:
        error_output = (result.stderr or result.stdout).strip()
        raise CheckError(f"Managed OpenBao signing check failed: {error_output}")

    try:
        payload_doc = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CheckError(f"Managed OpenBao signing check returned non-JSON output: {result.stdout.strip()}") from exc

    if payload_doc.get("ok") is not True or not payload_doc.get("signature_b64"):
        raise CheckError(f"Managed OpenBao signing check returned an invalid payload: {payload_doc}")

    return f"service_id={payload_doc.get('service_id')} algorithm={payload_doc.get('algorithm')}"


def validate_credential_login_config(env_values: dict[str, str]) -> str:
    policy_id = env_values.get("CREDENTIAL_LOGIN_POLICY_ID", "").strip()
    if not policy_id:
        raise CheckError(
            "CREDENTIAL_LOGIN_POLICY_ID is missing. Set it to the seeded OpenBadgeLogin "
            f"policy ID {OPEN_BADGE_LOGIN_POLICY_ID}."
        )
    if is_placeholder_value(policy_id):
        raise CheckError("CREDENTIAL_LOGIN_POLICY_ID still uses a placeholder value.")
    return f"policy_id={policy_id}"


def expected_marty_issuer_did(env_values: dict[str, str]) -> str:
    public_domain = env_values.get("PUBLIC_DOMAIN", "").strip()
    if not public_domain:
        raise CheckError("PUBLIC_DOMAIN is required to derive the Marty issuer DID.")
    org_slug = env_values.get("MARTY_ORG_SLUG", "marty").strip() or "marty"
    return f"did:web:{public_domain}:orgs:{org_slug}"


def validate_marty_login_trust_profile(env_file: Path, compose_file: Path, env_values: dict[str, str]) -> str:
    expected_issuer_did = expected_marty_issuer_did(env_values)
    query = """
        SELECT trust_sources
          FROM trust_profile_service.trust_profiles
         WHERE id = '60000000-0000-0000-0000-000000000001'
           AND organization_id = '00000000-0000-0000-0000-000000000001';
    """
    result = run_compose_command(
        env_file,
        compose_file,
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "postgres",
        "-d",
        "marty",
        "-t",
        "-A",
        "-c",
        query,
    )
    if result.returncode != 0:
        error_output = (result.stderr or result.stdout).strip()
        raise CheckError(f"Unable to query the Marty login trust profile: {error_output}")

    raw = result.stdout.strip()
    if not raw:
        raise CheckError("Marty login trust profile is missing from trust_profile_service.trust_profiles.")

    try:
        trust_sources = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CheckError(f"Marty login trust profile returned invalid trust_sources JSON: {raw}") from exc

    managed_source = None
    for source in trust_sources if isinstance(trust_sources, list) else []:
        if not isinstance(source, dict):
            continue
        if source.get("id") == "60000000-0000-0000-0000-000000000021" or source.get("name") == "Marty Managed Issuer":
            managed_source = source
            break

    if managed_source is None:
        raise CheckError("Marty login trust profile is missing the Marty Managed Issuer trust source.")

    issuer_did = str(managed_source.get("issuer_did") or "").strip()
    if issuer_did != expected_issuer_did:
        raise CheckError(
            "Marty login trust profile is pinned to the wrong issuer DID; "
            f"expected {expected_issuer_did}, got {issuer_did or '<missing>'}"
        )
    if not bool(managed_source.get("enabled", False)):
        raise CheckError("Marty Managed Issuer trust source is disabled.")

    return f"issuer_did={issuer_did}"


def validate_ui_origin_config(env_values: dict[str, str]) -> str:
    origins = configured_ui_origins(env_values)
    if not origins:
        raise CheckError("UI_BASE_URL is required for the self-host auth redirect allowlist.")

    cors_origins = {normalized_origin(origin) for origin in split_csv(env_values.get("CORS_ORIGINS"))}
    missing_from_cors = [origin for origin in origins if origin not in cors_origins]
    if missing_from_cors:
        raise CheckError(
            "CORS_ORIGINS must include every UI auth origin; missing "
            + ", ".join(missing_from_cors)
        )

    return "origins=" + ",".join(origins)


def validate_selfhost_ui_bundle_origins(env_values: dict[str, str]) -> str:
    dist_dir = REPO_ROOT / "ui" / "dist-selfhost"
    if not dist_dir.exists():
        return "not-built"

    allowed_origins = set(configured_ui_origins(env_values))
    for key in ("PUBLIC_API_URL", "PUBLIC_URL"):
        value = env_values.get(key, "").strip()
        if value:
            allowed_origins.add(normalized_origin(value))

    forbidden_origins = {
        normalized_origin(origin)
        for origin in split_csv(env_values.get("SELFHOST_FORBIDDEN_UI_ORIGINS"))
    }
    for default_forbidden_origin in ("https://beta.elevenidllc.com", "http://beta.elevenidllc.com"):
        if default_forbidden_origin not in allowed_origins:
            forbidden_origins.add(default_forbidden_origin)

    checked_files = 0
    disallowed_hits: list[str] = []
    for path in dist_dir.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_BUNDLE_SUFFIXES:
            continue

        checked_files += 1
        content = path.read_text(encoding="utf-8", errors="ignore")
        for origin in sorted(set(ORIGIN_RE.findall(content))):
            if normalized_origin(origin) in forbidden_origins:
                disallowed_hits.append(f"{path.relative_to(REPO_ROOT)} -> {origin}")

    if disallowed_hits:
        raise CheckError(
            "Self-host UI bundle contains forbidden origins; rebuild with "
            "`make selfhost-prod-ui-build`. Offending references: "
            + "; ".join(disallowed_hits[:5])
        )

    return (
        f"checked_files={checked_files} allowed_origins={','.join(sorted(allowed_origins))} "
        f"forbidden_origins={','.join(sorted(forbidden_origins))}"
    )


def validate_selfhost_canvas_frame_ancestors() -> str:
    template_path = REPO_ROOT / "docker" / "nginx-selfhost.prod.conf.template"
    content = template_path.read_text(encoding="utf-8")
    forbidden = {
        "http://localhost:8088",
        "http://127.0.0.1:8088",
    }
    hits = sorted(origin for origin in forbidden if origin in content)
    if hits:
        raise CheckError(
            "Self-host production nginx template must not allow local Canvas LMS frame ancestors: "
            + ", ".join(hits)
        )
    if "https://${CANVAS_REAL_PUBLIC_HOST}" not in content:
        raise CheckError("Self-host production nginx template is missing the Canvas LMS HTTPS frame ancestor.")
    return "no-local-canvas-frame-ancestors"


def _public_dns_host(host: str, *, label: str) -> str:
    normalized = host.strip().lower()
    if not normalized:
        return ""
    if normalized in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or normalized.endswith(".local"):
        raise CheckError(f"{label} must not use a local/private host: {host}")
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        if "." not in normalized:
            raise CheckError(f"{label} must be a public DNS host, not an internal service name: {host}")
        return normalized
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise CheckError(f"{label} must not use a local/private address: {host}")
    return normalized


def _validate_public_https_url(value: str, *, label: str) -> str:
    if not value.strip():
        return ""
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise CheckError(f"{label} must be an https URL with a public host.")
    return _public_dns_host(parsed.hostname, label=label)


def validate_selfhost_canvas_public_config(env_values: dict[str, str]) -> str:
    checked: list[str] = []
    for key in (
        "PUBLIC_API_URL",
        "ISSUER_BASE_URL",
        "CANVAS_LTI_EXPERIENCE_BASE_URL",
        "CANVAS_CREDENTIALS_PUBLIC_BASE_URL",
        "CANVAS_API_BASE_URL",
    ):
        value = env_values.get(key, "").strip()
        if value:
            _validate_public_https_url(value, label=key)
            checked.append(key)

    for key in ("CANVAS_REAL_PUBLIC_HOST", "CANVAS_SANDBOX_PUBLIC_HOST"):
        value = env_values.get(key, "").strip()
        if value:
            parsed = urlparse(value if "://" in value else f"https://{value}")
            _public_dns_host(parsed.hostname or value, label=key)
            checked.append(key)

    provider = env_values.get("CANVAS_CREDENTIALS_PROVIDER", "").strip().lower()
    if provider in {"bridge", "sandbox", "proxy", "bridge_api"}:
        raise CheckError(
            "CANVAS_CREDENTIALS_PROVIDER must use the real Canvas Credentials API in self-host production, "
            f"not {provider!r}."
        )
    if provider:
        checked.append("CANVAS_CREDENTIALS_PROVIDER")

    return f"checked={','.join(checked) if checked else 'none-configured'}"


def validate_auth_login_redirect_hosts(env_values: dict[str, str]) -> str:
    origins = configured_ui_origins(env_values)
    if not origins:
        raise CheckError("UI_BASE_URL is required to validate auth login redirects.")

    edge_port = int(env_values.get("SELFHOST_EDGE_HOST_PORT", "19080"))
    opener = urllib.request.build_opener(NoRedirectHandler)
    checked: list[str] = []
    for origin in origins:
        parsed_origin = urlparse(origin)
        host = parsed_origin.netloc
        expected_callback = f"{origin}/v1/auth/callback"
        request = urllib.request.Request(
            f"http://127.0.0.1:{edge_port}/v1/auth/login",
            headers={
                "Accept": "text/html",
                "Host": host,
                "X-Forwarded-Proto": parsed_origin.scheme,
            },
            method="GET",
        )

        try:
            with opener.open(request, timeout=10) as response:  # noqa: S310 - localhost operator health check
                raise CheckError(f"Auth login for {origin} returned HTTP {response.status} instead of redirecting.")
        except urllib.error.HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                body = exc.read().decode("utf-8", errors="replace").strip()
                raise CheckError(f"Auth login for {origin} returned HTTP {exc.code}: {body}") from exc

            location = exc.headers.get("Location")
            if not location:
                raise CheckError(f"Auth login for {origin} returned HTTP {exc.code} without a Location header") from exc
        except OSError as exc:
            raise CheckError(f"Auth login is unreachable for {origin}: {exc}") from exc

        location_query = parse_qs(urlparse(location).query)
        actual_callback = (location_query.get("redirect_uri") or [""])[0]
        if actual_callback != expected_callback:
            raise CheckError(
                f"Auth login for {origin} uses redirect_uri={actual_callback or '<missing>'}; "
                f"expected {expected_callback}. Check UI_ADDITIONAL_BASE_URLS/CORS_ORIGINS and proxy Host headers."
            )
        checked.append(f"{origin}->{actual_callback}")

    return "redirects=" + ",".join(checked)


def validate_keycloak_open_badge_option(env_values: dict[str, str]) -> str:
    public_domain = env_values.get("PUBLIC_DOMAIN", "").strip()
    if not public_domain:
        raise CheckError("PUBLIC_DOMAIN is required to validate the Keycloak Open Badge login option.")

    edge_port = int(env_values.get("SELFHOST_EDGE_HOST_PORT", "19080"))
    url = f"http://127.0.0.1:{edge_port}/v1/auth/login"
    final_url = url
    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        for _ in range(10):
            request = urllib.request.Request(
                url,
                headers={
                    "Accept": "text/html",
                    "Host": public_domain,
                },
                method="GET",
            )
            try:
                with opener.open(request, timeout=10) as response:  # noqa: S310 - localhost operator health check
                    content_type = response.headers.get("Content-Type", "")
                    body = response.read().decode("utf-8", errors="replace")
                    final_url = response.geturl()
                    break
            except urllib.error.HTTPError as exc:
                if exc.code not in {301, 302, 303, 307, 308}:
                    body = exc.read().decode("utf-8", errors="replace").strip()
                    raise CheckError(f"Keycloak login page returned HTTP {exc.code}: {body}") from exc

                location = exc.headers.get("Location")
                if not location:
                    raise CheckError(f"Keycloak login redirect returned HTTP {exc.code} without a Location header") from exc

                resolved = urlparse(urljoin(url, location))
                if resolved.hostname not in {public_domain, "127.0.0.1", "localhost"}:
                    raise CheckError(f"Keycloak login redirected to unexpected host: {location}") from exc

                local_url = resolved._replace(scheme="http", netloc=f"127.0.0.1:{edge_port}")
                url = urlunparse(local_url)
                final_url = urlunparse(resolved)
        else:
            raise CheckError("Keycloak login page exceeded the redirect limit.")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise CheckError(f"Keycloak login page returned HTTP {exc.code}: {body}") from exc
    except OSError as exc:
        raise CheckError(f"Keycloak login page is unreachable at {url}: {exc}") from exc

    if "text/html" not in content_type.lower():
        raise CheckError(f"Keycloak login page has unexpected content type: {content_type or '<missing>'}")
    has_open_badge = "data-testid=\"social-login-credential\"" in body and "/v1/auth/credential-login" in body
    has_google = "data-testid=\"social-login-google\"" in body
    has_password = 'name="password"' in body

    if not has_open_badge:
        raise CheckError(
            "Keycloak login page is missing the Present Open Badge Credential option; "
            f"final_url={final_url}"
        )

    if not is_enabled(env_values.get("KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED"), default=False) and not has_password:
        raise CheckError(
            "Keycloak login page is still rendering the username-first flow instead of the beta-style password form; "
            f"final_url={final_url}"
        )

    if is_enabled(env_values.get("KEYCLOAK_SOCIAL_LOGIN_ENABLED")) and not has_google:
        raise CheckError(
            "KEYCLOAK_SOCIAL_LOGIN_ENABLED=true but the Keycloak login page is missing the Google option; "
            f"final_url={final_url}"
        )

    google_detail = "present" if has_google else "disabled"
    password_detail = "present" if has_password else "identity-first"
    return f"final_url={final_url} badge_option=present google_option={google_detail} password_form={password_detail}"


def validate_credential_login_page(env_values: dict[str, str]) -> str:
    public_domain = env_values.get("PUBLIC_DOMAIN", "").strip()
    if not public_domain:
        raise CheckError("PUBLIC_DOMAIN is required to validate the Open Badge credential-login page.")

    edge_port = int(env_values.get("SELFHOST_EDGE_HOST_PORT", "19080"))
    request = urllib.request.Request(
        f"http://127.0.0.1:{edge_port}/v1/auth/credential-login",
        headers={
            "Accept": "text/html",
            "Host": public_domain,
            "X-Forwarded-Proto": "https",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - localhost operator health check
            content_type = response.headers.get("Content-Type", "")
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise CheckError(f"Credential-login page returned HTTP {exc.code}: {body}") from exc
    except OSError as exc:
        raise CheckError(f"Credential-login page is unreachable: {exc}") from exc

    if "text/html" not in content_type.lower():
        raise CheckError(f"Credential-login page has unexpected content type: {content_type or '<missing>'}")
    if "temporarily unavailable" in body.lower() or "sign-in unavailable" in body.lower():
        raise CheckError(
            "Credential-login page rendered the unavailable banner instead of the wallet sign-in experience."
        )
    if "Sign in with Open Badge Credential" not in body:
        raise CheckError("Credential-login page is missing the expected Open Badge sign-in heading.")
    if "data-nonce=" not in body:
        raise CheckError("Credential-login page did not embed a login nonce; the flow did not bootstrap.")

    return "page=ready flow_bootstrap=ok"


def validate_oid4vp_did_document(env_values: dict[str, str]) -> str:
    public_domain = env_values.get("PUBLIC_DOMAIN", "").strip()
    if not public_domain:
        raise CheckError("PUBLIC_DOMAIN is required to validate the OID4VP verifier DID document.")

    edge_port = int(env_values.get("SELFHOST_EDGE_HOST_PORT", "19080"))
    url = f"http://127.0.0.1:{edge_port}/oid4vp/did.json"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/did+json, application/json",
            "Host": public_domain,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - localhost operator health check
            content_type = response.headers.get("Content-Type", "")
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise CheckError(f"OID4VP DID document endpoint returned HTTP {exc.code}: {body}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError(f"OID4VP DID document endpoint is not returning JSON at {url}: {exc}") from exc

    if not content_type.lower().startswith("application/did+json"):
        raise CheckError(f"OID4VP DID document has unsupported content type: {content_type or '<missing>'}")

    expected_id = f"did:web:{public_domain}:oid4vp"
    actual_id = payload.get("id")
    if actual_id != expected_id:
        raise CheckError(f"OID4VP DID document id mismatch: expected {expected_id}, got {actual_id!r}")

    return f"id={actual_id} content_type={content_type}"


def validate_open_badge_type_metadata(env_values: dict[str, str]) -> str:
    public_domain = env_values.get("PUBLIC_DOMAIN", "").strip()
    if not public_domain:
        raise CheckError("PUBLIC_DOMAIN is required to validate the Open Badge type metadata route.")

    edge_port = int(env_values.get("SELFHOST_EDGE_HOST_PORT", "19080"))
    expected_vct = f"https://{public_domain}/credentials/marty-verified-member-badge"
    request = urllib.request.Request(
        f"http://127.0.0.1:{edge_port}/credentials/marty-verified-member-badge",
        headers={
            "Accept": "application/json",
            "Host": public_domain,
            "X-Forwarded-Proto": "https",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - localhost operator health check
            content_type = response.headers.get("Content-Type", "")
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise CheckError(f"Open Badge type metadata returned HTTP {exc.code}: {body}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError(
            "Open Badge type metadata route is not returning JSON; "
            "ensure /credentials/ is proxied to gateway before the UI fallback: "
            f"{exc}"
        ) from exc

    if not content_type.lower().startswith("application/json"):
        raise CheckError(f"Open Badge type metadata has unsupported content type: {content_type or '<missing>'}")
    if payload.get("vct") != expected_vct:
        raise CheckError(f"Open Badge type metadata vct mismatch: expected {expected_vct}, got {payload.get('vct')!r}")
    if payload.get("name") != "Marty Verified Member Badge":
        raise CheckError(f"Open Badge type metadata name mismatch: {payload.get('name')!r}")

    display = payload.get("display") or []
    display_name = display[0].get("name") if display and isinstance(display[0], dict) else None
    if display_name != "Marty Verified Member Badge":
        raise CheckError(f"Open Badge type metadata display name mismatch: {display_name!r}")

    return f"vct={payload.get('vct')} name={payload.get('name')} content_type={content_type}"


def validate_marty_issuer_did_document(env_values: dict[str, str]) -> str:
    public_domain = env_values.get("PUBLIC_DOMAIN", "").strip()
    org_slug = env_values.get("MARTY_ORG_SLUG", "marty").strip() or "marty"
    if not public_domain:
        raise CheckError("PUBLIC_DOMAIN is required to validate the Marty issuer DID document.")

    edge_port = int(env_values.get("SELFHOST_EDGE_HOST_PORT", "19080"))
    expected_id = f"did:web:{public_domain}:orgs:{org_slug}"
    request = urllib.request.Request(
        f"http://127.0.0.1:{edge_port}/orgs/{org_slug}/did.json",
        headers={
            "Accept": "application/did+json, application/json",
            "Host": public_domain,
            "X-Forwarded-Proto": "https",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - localhost operator health check
            content_type = response.headers.get("Content-Type", "")
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise CheckError(f"Marty issuer DID document returned HTTP {exc.code}: {body}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError(
            "Marty issuer DID document route is not returning JSON; "
            "ensure /orgs/{slug}/did.json is proxied to gateway before the UI fallback: "
            f"{exc}"
        ) from exc

    if not content_type.lower().startswith(("application/did+json", "application/json")):
        raise CheckError(f"Marty issuer DID document has unsupported content type: {content_type or '<missing>'}")
    actual_id = payload.get("id")
    if actual_id != expected_id:
        raise CheckError(f"Marty issuer DID document id mismatch: expected {expected_id}, got {actual_id!r}")
    assertion_methods = payload.get("assertionMethod") or []
    if not assertion_methods:
        raise CheckError("Marty issuer DID document is missing assertionMethod entries")

    return f"id={actual_id} assertion_methods={len(assertion_methods)} content_type={content_type}"


def validate_protocol_routes_do_not_spa_fallback(env_values: dict[str, str]) -> str:
    public_domain = env_values.get("PUBLIC_DOMAIN", "").strip()
    org_slug = env_values.get("MARTY_ORG_SLUG", "marty").strip() or "marty"
    if not public_domain:
        raise CheckError("PUBLIC_DOMAIN is required to validate protocol fallback guards.")

    edge_port = int(env_values.get("SELFHOST_EDGE_HOST_PORT", "19080"))
    paths = [
        f"/orgs/{org_slug}/not-a-did.json",
        "/org/00000000-0000-0000-0000-000000000001/not-well-known",
        "/oid4vp/not-a-did.json",
        "/credentials/__selfhost-fallback-check__",
    ]
    checked: list[str] = []
    for path in paths:
        request = urllib.request.Request(
            f"http://127.0.0.1:{edge_port}{path}",
            headers={
                "Accept": "application/did+json, application/json",
                "Host": public_domain,
                "X-Forwarded-Proto": "https",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - localhost operator health check
                content_type = response.headers.get("Content-Type", "")
                body = response.read(256).decode("utf-8", errors="replace").lower()
        except urllib.error.HTTPError as exc:
            content_type = exc.headers.get("Content-Type", "")
            body = exc.read(256).decode("utf-8", errors="replace").lower()
            if exc.code not in {404, 405}:
                raise CheckError(f"Protocol path {path} returned HTTP {exc.code}; expected 404/405, not UI fallback") from exc
            if "text/html" in content_type.lower() or "<!doctype html" in body or "<html" in body:
                raise CheckError(f"Protocol path {path} returned HTML instead of failing closed as machine-readable 404") from exc
            checked.append(f"{path}->{exc.code}")
            continue
        except OSError as exc:
            raise CheckError(f"Protocol fallback guard check is unreachable at {path}: {exc}") from exc

        if "text/html" in content_type.lower() or "<!doctype html" in body or "<html" in body:
            raise CheckError(f"Protocol path {path} fell through to the UI SPA fallback with HTTP {response.status}")
        raise CheckError(f"Protocol path {path} unexpectedly returned HTTP {response.status}; expected 404/405")

    return "guards=" + ",".join(checked)


def validate_openbao(env_values: dict[str, str], secret_dir: Path, env_file: Path, compose_file: Path) -> str:
    read_required_secret(secret_dir / "openbao_service_token", "OpenBao service token")
    services = get_compose_services(env_file, compose_file)
    openbao_service = next((entry for entry in services if entry.get("Service") == "openbao"), None)
    if openbao_service is None:
        raise CheckError("Standalone OpenBao service is not running in Docker Compose.")
    if openbao_service.get("State") != "running":
        raise CheckError(f"Standalone OpenBao state is {openbao_service.get('State', 'unknown')}.")
    if openbao_service.get("Health") and openbao_service.get("Health") != "healthy":
        raise CheckError(f"Standalone OpenBao health is {openbao_service.get('Health')}.")

    host_port = int(env_values.get("SELFHOST_OPENBAO_HOST_PORT", "18200"))
    health_url = f"http://127.0.0.1:{host_port}/v1/sys/health?standbyok=true&perfstandbyok=true"
    try:
        with urllib.request.urlopen(health_url, timeout=5) as response:  # noqa: S310 - localhost operator health check
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise CheckError(f"OpenBao health endpoint returned HTTP {exc.code}: {body}") from exc
    except OSError as exc:
        raise CheckError(f"OpenBao health endpoint is unreachable at {health_url}: {exc}") from exc

    if not payload.get("initialized"):
        raise CheckError("OpenBao reports initialized=false.")
    if payload.get("sealed"):
        raise CheckError("OpenBao reports sealed=true.")

    return f"state={openbao_service.get('State')} health={openbao_service.get('Health') or 'n/a'} port={host_port}"


def validate_main_stack(env_file: Path, compose_file: Path, catalog: DeploymentCatalog | None = None) -> str:
    services = get_compose_services(env_file, compose_file)
    if not services:
        raise CheckError("Main self-host production stack is not running.")

    service_map = {entry.get("Service"): entry for entry in services}
    required_services = tuple(
        catalog.running_services_for_stack("selfhost-production")
        if catalog is not None
        else (
            "postgres",
            "redis",
            "keycloak",
            "auth",
            "organization",
            "credential-template",
            "trust-profile",
            "applicant",
            "notification",
            "compliance-profile",
            "presentation-policy",
            "deployment-profile",
            "flow",
            "verification",
            "revocation-profile",
            "billing",
            "issuance",
            "event-stream",
            "gateway",
            "ui",
            "edge",
            "cloudflared",
        )
    )
    missing_services = [service for service in required_services if service not in service_map]
    if missing_services:
        raise CheckError("Missing expected running services: " + ", ".join(sorted(missing_services)))

    unhealthy: list[str] = []
    for service_name in required_services:
        service = service_map[service_name]
        state = str(service.get("State", ""))
        health = str(service.get("Health", ""))
        if state != "running":
            unhealthy.append(f"{service_name}=state:{state or 'unknown'}")
            continue
        if health and health != "healthy":
            unhealthy.append(f"{service_name}=health:{health}")

    if unhealthy:
        raise CheckError("Unhealthy services: " + ", ".join(unhealthy))

    return "services=" + ",".join(required_services)


def run_check(name: str, checker) -> CheckResult:
    try:
        detail = checker()
        return CheckResult(name=name, ok=True, detail=detail)
    except (CheckError, LicenseValidationError) as exc:
        return CheckResult(name=name, ok=False, detail=str(exc))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the self-host production deployment state.")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env.selfhost.production.local"))
    parser.add_argument("--prod-compose-file", default=str(REPO_ROOT / "docker-compose.selfhost.prod.yml"))
    parser.add_argument("--openbao-compose-file", default=str(REPO_ROOT / "docker-compose.selfhost.openbao.yml"))
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    env_file = Path(args.env_file).expanduser().resolve()
    prod_compose_file = Path(args.prod_compose_file).expanduser().resolve()
    openbao_compose_file = Path(args.openbao_compose_file).expanduser().resolve()

    if not env_file.exists():
        raise SystemExit(f"Self-host env file does not exist: {env_file}")

    env_values = load_env_file(env_file)
    secret_dir_value = env_values.get("SELFHOST_SECRET_DIR", "").strip()
    if not secret_dir_value:
        raise SystemExit("SELFHOST_SECRET_DIR is missing from the self-host env file.")
    secret_dir = Path(secret_dir_value).expanduser().resolve()
    catalog = DeploymentCatalog.load(REPO_ROOT)

    compose_config_results = [
        run_check("openbao-compose-config", lambda: (ensure_compose_config(env_file, openbao_compose_file) or openbao_compose_file.name)),
        run_check("prod-compose-config", lambda: (ensure_compose_config(env_file, prod_compose_file) or prod_compose_file.name)),
    ]
    validation_results = [
        run_check("selfhost-required-secrets", lambda: validate_required_secret_files(secret_dir, catalog, "selfhost-production")),
        run_check("license", lambda: validate_license(env_values, secret_dir)),
        run_check("cloudflare-tunnel-token", lambda: validate_tunnel_token(secret_dir)),
        run_check("migration-profile", lambda: validate_migration_profile(env_values)),
        run_check("google-social-login", lambda: validate_google_social_login(env_values, secret_dir)),
        run_check("credential-login-config", lambda: validate_credential_login_config(env_values)),
        run_check("marty-login-trust-profile", lambda: validate_marty_login_trust_profile(env_file, prod_compose_file, env_values)),
        run_check("selfhost-catalog-templates", lambda: validate_selfhost_catalog_templates(env_file, prod_compose_file)),
        run_check("managed-openbao-signing", lambda: validate_managed_openbao_signing(env_file, prod_compose_file)),
        run_check("ui-origin-config", lambda: validate_ui_origin_config(env_values)),
        run_check("selfhost-ui-bundle-origins", lambda: validate_selfhost_ui_bundle_origins(env_values)),
        run_check("selfhost-canvas-frame-ancestors", validate_selfhost_canvas_frame_ancestors),
        run_check("selfhost-canvas-public-config", lambda: validate_selfhost_canvas_public_config(env_values)),
        run_check("auth-login-redirects", lambda: validate_auth_login_redirect_hosts(env_values)),
        run_check("keycloak-open-badge-option", lambda: validate_keycloak_open_badge_option(env_values)),
        run_check("credential-login-page", lambda: validate_credential_login_page(env_values)),
        run_check("oid4vp-did-document", lambda: validate_oid4vp_did_document(env_values)),
        run_check("open-badge-type-metadata", lambda: validate_open_badge_type_metadata(env_values)),
        run_check("marty-issuer-did-document", lambda: validate_marty_issuer_did_document(env_values)),
        run_check("protocol-no-spa-fallback", lambda: validate_protocol_routes_do_not_spa_fallback(env_values)),
        run_check("openbao", lambda: validate_openbao(env_values, secret_dir, env_file, openbao_compose_file)),
        run_check("prod-compose-health", lambda: validate_main_stack(env_file, prod_compose_file, catalog)),
    ]

    results = compose_config_results + validation_results
    for result in results:
        status = "[OK]" if result.ok else "[FAIL]"
        print(f"{status} {result.name}: {result.detail}")

    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
