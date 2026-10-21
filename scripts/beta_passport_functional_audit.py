"""Protected runtime prerequisites for fresh, local-engineering passport actions.

This module does not enable canonical D12 qualification or signed acceptance.
Runtime observation is read-only. The recording adapter must bind these inputs
and actual public HTTP responses through the existing owned Python protocol.
"""

from __future__ import annotations

import json
import re
import subprocess
from http.cookies import SimpleCookie
from typing import Any, Callable
from urllib.parse import quote, urlsplit


ORIGIN = "https://beta.elevenidllc.com"
ROLES = ("gateway", "flow", "signing-keys", "issuance-native",
         "passport-beta-bureau", "passport-callback-signer")
CALLBACK_NETWORK = "elevenid-beta-passport-callback-signing"
FEATURES = {
    "gateway": {"PASSPORT_NATIVE_GATEWAY_ENABLED": "true",
                "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED": "false",
                "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true"},
    "flow": {"PASSPORT_NATIVE_FLOW_ENABLED": "true",
             "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true"},
    "signing-keys": {"ENVIRONMENT": "beta",
                     "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED": "true"},
    "issuance-native": {"ENVIRONMENT": "beta", "PASSPORT_NATIVE_HTTP_ENABLED": "true",
                        "PASSPORT_BETA_RECONCILIATION_ENABLED": "true",
                        "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true",
                        "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED": "true",
                        "PASSPORT_KMS_ARTIFACTS_ENABLED": "true",
                        "PASSPORT_KMS_CALLBACKS_ENABLED": "true"},
    "passport-beta-bureau": {"ENVIRONMENT": "beta", "PASSPORT_BETA_BUREAU_ENABLED": "true",
                             "PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED": "true"},
    "passport-callback-signer": {"ENVIRONMENT": "beta", "PASSPORT_CALLBACK_SIGNER_ENABLED": "true"},
}


class PassportPrerequisiteError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PassportPrerequisiteError(message)


def docker_json(*arguments: str) -> list[dict[str, Any]]:
    try:
        result = subprocess.run(["docker", *arguments], capture_output=True,
                                check=False, timeout=30)
        require(result.returncode == 0 and len(result.stdout) <= 2 * 1024 * 1024,
                "Protected passport runtime observation failed")
        value = json.loads(result.stdout)
        require(isinstance(value, list) and all(isinstance(x, dict) for x in value),
                "Protected passport runtime observation is malformed")
        return value
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise PassportPrerequisiteError("Protected passport runtime observation failed") from error


def verify_runtime(
    receipt: dict[str, Any], deployment: dict[str, Any], *,
    observe: Callable[..., list[dict[str, Any]]] = docker_json,
) -> dict[str, Any]:
    """Bind exact local product images, beta feature selection and KMS network.

    The caller separately verifies sealed receipt/manifest bytes and the existing
    production source-manifest verifier. No release signature flag is invented.
    Returned container IDs are private operation inputs, not public artifacts.
    """
    require(receipt.get("scope") == "LOCAL_DEVELOPER_STACK"
            and receipt.get("betaDeployed") is True
            and receipt.get("exactRuntimeImagesAndMarkersVerified") is True
            and receipt.get("publicUiMarkerVerified") is True
            and re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("sourceRevision", "")))
            and re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("sourceId", ""))),
            "Passport actions require an exact verified local beta receipt")
    require(deployment.get("source_kind") == "local-worktree-snapshot"
            and deployment.get("promotion_eligible") is False
            and deployment.get("release_ready") is False
            and deployment.get("beta_origin") == ORIGIN
            and deployment.get("compose_project") == "elevenid-beta"
            and deployment.get("marty_ui_sha") == receipt["sourceId"]
            and deployment.get("release_version") == receipt.get("release"),
            "Passport deployment differs from the local beta receipt")
    require(deployment.get("passport_provider_mode") == "simulator",
            "Fresh passport operations require the explicit beta native simulator profile")
    rows = deployment.get("images")
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows),
            "Passport deployment image inventory is unavailable")
    bound: dict[str, str] = {}
    for role in ROLES:
        candidates = [row for row in rows if row.get("service") == role]
        require(len(candidates) == 1, "Protected passport role is missing or duplicated: " + role)
        row = candidates[0]
        require(re.fullmatch(r"[0-9a-f]{64}", str(row.get("container_id", "")))
                and re.fullmatch(r"sha256:[0-9a-f]{64}", str(row.get("image_id", "")))
                and row["image_id"] == receipt.get("images", {}).get("services", {}).get("imageId"),
                "Protected passport role differs from the exact services image: " + role)
        current = observe("inspect", row["container_id"])
        require(len(current) == 1, "Protected passport role observation is ambiguous: " + role)
        item = current[0]
        labels = item.get("Config", {}).get("Labels") or {}
        raw_environment = item.get("Config", {}).get("Env", [])
        require(isinstance(raw_environment, list)
                and all(isinstance(value, str) and "=" in value for value in raw_environment),
                "Protected passport runtime environment is malformed: " + role)
        pairs = [value.split("=", 1) for value in raw_environment]
        require(len({name for name, _ in pairs}) == len(pairs),
                "Protected passport runtime environment repeats a name: " + role)
        environment = dict(pairs)
        require(item.get("Id") == row["container_id"] and item.get("Image") == row["image_id"]
                and item.get("State", {}).get("Running") is True
                and item.get("State", {}).get("Health", {}).get("Status") == "healthy"
                and labels.get("com.docker.compose.project") == "elevenid-beta"
                and labels.get("com.docker.compose.service") == role
                and all(environment.get(name) == value for name, value in FEATURES[role].items()),
                "Protected passport runtime role is unhealthy or configured differently: " + role)
        if role in ("gateway", "flow", "issuance-native"):
            require(not environment.get("PASSPORT_TENANT_API_KEYS")
                    and not environment.get("PASSPORT_TENANT_API_KEYS_FILE"),
                    "Protected passport runtime must not use tenant keyring files")
        if role == "passport-callback-signer":
            require(environment.get("BAO_ADDR") == "https://openbao:8200"
                    and environment.get("BAO_CACERT") == "/bao/public-ca/ca.crt"
                    and environment.get("BAO_TOKEN_FILE") == "/bao/passport-callback/token",
                    "Protected passport callback signer must use governed KMS custody")
        bound[role] = item["Id"]
    networks = observe("network", "inspect", CALLBACK_NETWORK)
    require(len(networks) == 1 and networks[0].get("Internal") is True
            and networks[0].get("Name") == CALLBACK_NETWORK
            and re.fullmatch(r"[0-9a-f]{64}", str(networks[0].get("Id", "")))
            and (networks[0].get("Labels") or {}).get("com.docker.compose.project") == "elevenid-beta"
            and (networks[0].get("Labels") or {}).get("com.docker.compose.network") == "passport-callback-signing",
            "Protected passport callback network is not isolated")
    members = networks[0].get("Containers", {})
    require(isinstance(members, dict) and len(members) == 3
            and bound["passport-beta-bureau"] in members
            and bound["passport-callback-signer"] in members,
            "Protected passport callback network has unexpected members")
    remaining = set(members) - {bound["passport-beta-bureau"], bound["passport-callback-signer"]}
    require(len(remaining) == 1, "Protected passport callback KMS identity is unavailable")
    kms_member = remaining.pop()
    kms = observe("inspect", kms_member)
    require(len(kms) == 1 and kms[0].get("Id") == kms_member
            and kms[0].get("State", {}).get("Running") is True
            and (kms[0].get("Config", {}).get("Labels") or {}).get("com.docker.compose.project") == "elevenid-beta"
            and (kms[0].get("Config", {}).get("Labels") or {}).get("com.docker.compose.service") == "openbao",
            "Protected passport callback network has an unexpected KMS member")
    return {"sourceRevision": receipt["sourceRevision"], "sourceId": receipt["sourceId"],
            "containers": bound, "callbackNetworkId": networks[0]["Id"],
            "providerMode": "simulator", "physicalClaim": "not_claimed"}


class ObservedPassportRequests:
    """Actual Page.fetch request ports observed by the owned Python client.

    Separate browser contexts keep governed CSCA/DSC authority distinct. No API
    response body is emitted as evidence, and there is no manual TRACE emitter.
    Construct only after protected runtime and sealed fixture verification.
    """

    def __init__(self, capture, browser, *, csca_session: str, dsc_session: str,
                 flow_session: str, api_key: str):
        require(csca_session != dsc_session, "Separate governed passport sessions are required")
        self.capture = capture
        self.api_key = api_key
        self.sessions = {"csca": csca_session, "dsc": dsc_session, "flow": flow_session}
        self.contexts = []
        self.pages = {}
        try:
            for role in ("csca", "dsc", "flow", "api"):
                context = browser.new_context(ignore_https_errors=False, service_workers="block")
                self.contexts.append(context)
                if role != "api":
                    session = self.sessions[role]
                    require(isinstance(session, str) and not any(c in session for c in "\r\n\0"),
                            "Protected passport session is invalid")
                    cookies = SimpleCookie()
                    cookies.load(session)
                    require(set(cookies) == {"sessionId"} and bool(cookies["sessionId"].value),
                            "Protected passport context requires one exact session cookie")
                    context.add_cookies([{"name": "sessionId", "value": cookies["sessionId"].value,
                                          "url": ORIGIN, "secure": True, "httpOnly": True,
                                          "sameSite": "Lax"}])
                page = context.new_page()
                capture.bind_page(page)
                response = page.goto(ORIGIN + "/ready", wait_until="domcontentloaded", timeout=60000)
                require(response is not None and response.status == 200
                        and page.url == ORIGIN + "/ready",
                        "Protected passport browser readiness redirected or failed")
                self.pages[role] = page
        except Exception:
            self.close()
            raise

    def close(self):
        for context in reversed(self.contexts):
            context.close()
        self.contexts.clear()

    def _fetch(self, role: str, method: str, path: str, encoded_body: str | None,
               headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
        endpoint = urlsplit(path)
        require(role in self.pages and method in ("GET", "POST")
                and path.startswith("/") and not path.startswith("//")
                and not endpoint.scheme and not endpoint.netloc and not endpoint.fragment
                and ".." not in path and "\\" not in path
                and not any(c in path for c in "\r\n\0"),
                "Unexpected protected passport browser request")
        require(not self.capture.failed and not self.capture.completed,
                "Passport live evidence stopped before the next operation")
        result = self.pages[role].evaluate("""async ({method, path, body, headers, credentialed}) => {
          const url = new URL(path, location.origin);
          if (url.origin !== 'https://beta.elevenidllc.com') throw Error('Unexpected passport origin');
          const response = await fetch(url.href, {method, body, headers,
            credentials: credentialed ? 'include' : 'omit', redirect: 'error',
            cache: 'no-store', signal: AbortSignal.timeout(120000)});
          const bytes = new Uint8Array(await response.arrayBuffer());
          if (bytes.length > 131072) throw Error('Passport response exceeds bounds');
          const value = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes));
          if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Passport response is not an object');
          return {status:response.status, value};
        }""", {"method": method, "path": path, "body": encoded_body,
                 "headers": {"Accept": "application/json", "Content-Type": "application/json",
                             **(headers or {})}, "credentialed": role != "api"})
        require(not self.capture.failed, "Passport HTTP observation failed")
        return result["status"], result["value"]

    def chain_request(self, path: str, body: dict[str, Any], session: str):
        require(path in ("/v1/signing-keys/issuer-identities/csca-self-signed-certificate",
                         "/v1/signing-keys/issuer-identities/dsc-certificate"),
                "Unexpected governed passport ceremony route")
        role = "csca" if path.endswith("csca-self-signed-certificate") else "dsc"
        require(session == self.sessions[role] and isinstance(body.get("organization_id"), str)
                and bool(body["organization_id"]), "Governed passport ceremony authority changed")
        route = path + "?organization_id=" + quote(body["organization_id"], safe="")
        payload = {name: value for name, value in body.items() if name != "organization_id"}
        return self._fetch(role, "POST", route, json.dumps(payload, separators=(",", ":")))

    def flow_request(self, method, path, body, session):
        require(path.startswith("/v1/flows/") and session == self.sessions["flow"],
                "Unexpected passport Flow route or authority")
        return self._fetch("flow", method, path,
                           None if body is None else json.dumps(body, separators=(",", ":")))

    def passport_request(self, method, path, body, api_key):
        require(path.startswith("/v1/passport/") and api_key == self.api_key,
                "Unexpected passport API route or authority")
        return self._fetch("api", method, path,
                           None if body is None else json.dumps(body, separators=(",", ":")),
                           {"x-api-key": api_key})

    def negative_post(self, body: bytes, signature: str | None):
        if __package__:
            from .probe_passport_beta_negative_callbacks import denial_projection
        else:
            from probe_passport_beta_negative_callbacks import denial_projection
        require(isinstance(body, bytes) and len(body) <= 8192,
                "Passport callback input exceeds bounds")
        # Preserve exactly the bytes signed by the production KMS helper.
        encoded = body.decode("utf8")
        headers = {"x-personalization-signature": signature} if signature is not None else {}
        status, result = self._fetch("api", "POST", "/v1/passport/webhooks/personalization",
                                     encoded, headers)
        return status, denial_projection(result)
