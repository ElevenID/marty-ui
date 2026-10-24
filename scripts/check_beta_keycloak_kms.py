"""Fail closed on beta Keycloak's remote-key image, references, and public files."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlsplit


IMAGE = re.compile(r"ghcr\.io/elevenid/marty-ui-oss/keycloak@sha256:[0-9a-f]{64}\Z")
SECRET_TARGETS = {
    "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
    "keycloak_signing_kms_token": "/run/secrets/keycloak_signing_kms_token",
    "keycloak_master_rs256_cert": "/run/secrets/keycloak-master-rs256.crt",
    "keycloak_11id_rs256_cert": "/run/secrets/keycloak-11id-rs256.crt",
    "keycloak_master_cookie_token": "/run/secrets/master-cookie.token",
    "keycloak_master_ciba_token": "/run/secrets/master-ciba.token",
    "keycloak_11id_cookie_token": "/run/secrets/11id-cookie.token",
    "keycloak_11id_ciba_token": "/run/secrets/11id-ciba.token",
}
PUBLIC_CERTS = frozenset({
    "openbao_tls_ca_cert", "keycloak_master_rs256_cert", "keycloak_11id_rs256_cert",
})


class KeycloakKmsError(ValueError):
    """Rendered beta Keycloak can use local keys or lacks its remote custody."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KeycloakKmsError(message)


def validate_model(model: dict, *, check_files: bool = False) -> None:
    services = model.get("services", {})
    require(isinstance(services, dict), "Beta services model is invalid")
    keycloak = services.get("keycloak")
    configurator = services.get("keycloak-configurator")
    require(isinstance(keycloak, dict) and isinstance(configurator, dict),
            "Beta Keycloak services are missing")
    image = keycloak.get("image")
    require(isinstance(image, str) and IMAGE.fullmatch(image) is not None
            and configurator.get("image") == image,
            "Beta Keycloak services require the same pinned remote-key image")

    env = keycloak.get("environment")
    require(isinstance(env, dict), "Beta Keycloak environment is invalid")
    address = env.get("BAO_ADDR")
    try:
        parsed = urlsplit(address) if isinstance(address, str) else None
        valid_address = (parsed is not None and parsed.scheme == "https"
                         and parsed.hostname is not None and not parsed.username
                         and not parsed.password and parsed.path in ("", "/")
                         and not parsed.query and not parsed.fragment)
    except ValueError:
        valid_address = False
    require(valid_address, "Beta Keycloak requires a trusted HTTPS KMS origin")
    expected = {
        "BAO_CACERT": SECRET_TARGETS["openbao_tls_ca_cert"],
        "BAO_TOKEN_FILE": SECRET_TARGETS["keycloak_signing_kms_token"],
        "MARTY_KEYCLOAK_RS256_CERT_DIR": "/run/secrets",
        "MARTY_KEYCLOAK_JWE_TOKEN_DIR": "/run/secrets",
        "MARTY_KEYCLOAK_JWE_MOUNT": "didcomm",
        "MARTY_KEYCLOAK_KMS_KEY_PREFIX": "keycloak",
    }
    require(all(env.get(name) == value for name, value in expected.items())
            and re.fullmatch(r"[1-9][0-9]*",
                             str(env.get("MARTY_KEYCLOAK_KMS_KEY_VERSION", ""))) is not None
            and not any(name in env for name in ("BAO_TOKEN", "VAULT_TOKEN",
                                                  "BAO_DEV_ROOT_TOKEN_ID")),
            "Beta Keycloak remote-key settings are incomplete")

    references = keycloak.get("secrets", [])
    require(isinstance(references, list), "Beta Keycloak secret bindings are invalid")
    bindings = {}
    for reference in references:
        require(isinstance(reference, dict)
                and isinstance(reference.get("source"), str)
                and isinstance(reference.get("target"), str)
                and reference["source"] not in bindings,
                "Beta Keycloak secret binding is invalid")
        bindings[reference["source"]] = reference["target"]
    require(bindings == SECRET_TARGETS,
            "Beta Keycloak requires exactly the reviewed scoped secret bindings")
    declarations = model.get("secrets")
    require(isinstance(declarations, dict), "Beta Keycloak secret declarations are missing")
    paths = {}
    for name in SECRET_TARGETS:
        declaration = declarations.get(name)
        path = declaration.get("file") if isinstance(declaration, dict) else None
        require(isinstance(path, str) and Path(path).is_absolute(),
                "Beta Keycloak secret source is invalid")
        paths[name] = Path(path)
    require(len(set(paths.values())) == len(paths),
            "Beta Keycloak scoped secret sources must be distinct")
    if not check_files:
        return
    tokens = set()
    for name, path in paths.items():
        require(path.is_file() and not path.is_symlink(),
                "Beta Keycloak KMS input file is missing or linked")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise KeycloakKmsError("Beta Keycloak KMS input file cannot be read") from exc
        require(0 < len(raw) <= 64 * 1024 and b"PRIVATE KEY" not in raw,
                "Beta Keycloak KMS input contains private material or is invalid")
        if name in PUBLIC_CERTS:
            require(b"-----BEGIN CERTIFICATE-----" in raw
                    and b"-----END CERTIFICATE-----" in raw,
                    "Beta Keycloak public certificate is invalid")
        else:
            token = raw.strip()
            require(len(token) >= 16 and not any(byte in token for byte in b" \t\r\n"),
                    "Beta Keycloak scoped token is invalid")
            require(token not in tokens, "Beta Keycloak scoped tokens must be distinct")
            tokens.add(token)
