"""Fail-closed Keycloak OpenID Connect adapter."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from common.native_backend import get_marty_rs_diagnostics, load_marty_rs

from ...application.ports import OIDCProviderPort
from ...domain.entities import OIDCUserInfo, OIDCValidatedIdentity

logger = logging.getLogger(__name__)

_DISCOVERY_MAX_BYTES = 256 * 1024
_JWKS_MAX_BYTES = 1024 * 1024


async def _fetch_json_object(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int,
    document_name: str,
) -> dict[str, Any]:
    """Fetch a bounded JSON object without following provider redirects."""
    async with client.stream("GET", url) as response:
        response.raise_for_status()
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError as error:
                raise ValueError(
                    f"OIDC {document_name} has an invalid Content-Length"
                ) from error
            if declared_size > max_bytes:
                raise ValueError(f"OIDC {document_name} exceeds the size limit")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > max_bytes:
                raise ValueError(f"OIDC {document_name} exceeds the size limit")
            body.extend(chunk)
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"OIDC {document_name} is not valid JSON") from error
    if not isinstance(document, dict):
        raise ValueError(f"OIDC {document_name} must be an object")
    return document


def build_oidc_user_info(
    id_token_claims: dict[str, Any],
    access_token_claims: dict[str, Any] | None = None,
) -> OIDCUserInfo:
    """Map already verified provider claims into the stable domain model."""
    if not isinstance(id_token_claims, dict) or not id_token_claims:
        raise ValueError("Verified ID-token claims are required")
    if access_token_claims is not None and not isinstance(access_token_claims, dict):
        raise ValueError("Verified access-token claims must be an object")
    return OIDCUserInfo.from_claims(id_token_claims, access_token_claims)


@dataclass
class OIDCConfig:
    """OIDC provider and relying-party policy."""

    issuer_url: str
    client_id: str
    client_secret: str | None = None
    redirect_uri: str = "http://localhost:8001/v1/auth/callback"
    scopes: list[str] | None = None
    external_issuer_url: str | None = None
    access_token_audience: str | None = None
    allowed_algorithms: tuple[str, ...] = ("RS256",)
    leeway_seconds: int = 60
    jwks_cache_seconds: int = 300

    def __post_init__(self) -> None:
        self.issuer_url = self.issuer_url.rstrip("/")
        if self.scopes is None:
            self.scopes = ["openid", "email", "profile"]
        if self.external_issuer_url is None:
            self.external_issuer_url = self.issuer_url
        self.external_issuer_url = self.external_issuer_url.rstrip("/")
        if self.access_token_audience is None:
            self.access_token_audience = self.client_id
        if not self.allowed_algorithms:
            raise ValueError("OIDC allowed algorithm list must not be empty")
        if self.leeway_seconds < 0 or self.leeway_seconds > 300:
            raise ValueError("OIDC clock leeway must be between 0 and 300 seconds")
        if self.jwks_cache_seconds < 1 or self.jwks_cache_seconds > 3600:
            raise ValueError("OIDC JWKS cache duration must be between 1 and 3600 seconds")

    @property
    def authorization_endpoint(self) -> str:
        return f"{self.external_issuer_url}/protocol/openid-connect/auth"

    @property
    def registration_endpoint(self) -> str:
        return f"{self.external_issuer_url}/protocol/openid-connect/registrations"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer_url}/protocol/openid-connect/token"

    @property
    def logout_endpoint(self) -> str:
        return f"{self.external_issuer_url}/protocol/openid-connect/logout"

    @property
    def discovery_endpoint(self) -> str:
        return f"{self.issuer_url}/.well-known/openid-configuration"


class OIDCNativeValidator:
    """Fetch provider trust material and delegate every token decision to Rust."""

    def __init__(self, config: OIDCConfig, native_backend: Any | None = None) -> None:
        self.config = config
        self._native = native_backend or load_marty_rs(
            required_capability="oidc_id_token_validation"
        )
        self.native_backend_diagnostics = (
            get_marty_rs_diagnostics(
                self._native,
                required_capability="oidc_id_token_validation",
            )
            if native_backend is None
            else {
                "available": True,
                "backend": "injected-test-backend",
                "version": "test",
                "capabilities": ["oidc_id_token_validation"],
            }
        )
        self._jwks: dict[str, Any] | None = None
        self._cache_expires_at = 0.0
        self._cache_lock = asyncio.Lock()

    async def validate_identity(
        self,
        id_token: str,
        access_token: str | None,
        expected_nonce: str,
    ) -> OIDCValidatedIdentity:
        if not expected_nonce:
            raise ValueError("OIDC nonce is required")
        id_claims = await self._validate_token(
            id_token,
            expected_audience=self.config.client_id,
            expected_nonce=expected_nonce,
            access_token=access_token,
        )
        # OAuth access tokens are opaque to the relying party unless the
        # resource server publishes a separate validation contract. Keycloak
        # lightweight access tokens deliberately omit ID-token claims such as
        # ``sub`` and ``aud``. The canonical Rust ID-token validator receives
        # the opaque value and enforces ``at_hash`` when the provider emits it;
        # the adapter must never reinterpret the bearer token as an ID token.
        access_claims: dict[str, Any] = {}
        return OIDCValidatedIdentity(
            user_info=build_oidc_user_info(id_claims, access_claims),
            id_token_claims=id_claims,
            access_token_claims=access_claims,
        )

    async def validate_exchanged_tokens(
        self,
        tokens: dict[str, Any],
        *,
        expected_audience: str,
    ) -> OIDCValidatedIdentity | None:
        """Validate optional RFC 8693 output without trusting decoded claims."""
        id_token = str(tokens.get("id_token") or "")
        access_token = str(tokens.get("access_token") or "")
        if not id_token and not access_token:
            return None
        if not id_token:
            raise ValueError("OIDC token exchange requires a verifiable ID token")
        id_claims = await self._validate_token(
            id_token,
            expected_audience=expected_audience,
            expected_nonce=None,
            access_token=access_token or None,
        )
        access_claims: dict[str, Any] = {}
        return OIDCValidatedIdentity(
            user_info=build_oidc_user_info(id_claims, access_claims),
            id_token_claims=id_claims,
            access_token_claims=access_claims,
        )

    async def _validate_token(
        self,
        token: str,
        *,
        expected_audience: str,
        expected_nonce: str | None,
        access_token: str | None,
        refreshed: bool = False,
    ) -> dict[str, Any]:
        jwks = await self._provider_jwks(force_refresh=refreshed)
        request = {
            "compact_jwt": token,
            "jwks": jwks,
            "expected_issuer": self.config.external_issuer_url,
            "expected_audience": expected_audience,
            "expected_nonce": expected_nonce,
            "access_token": access_token,
            "allowed_algorithms": list(self.config.allowed_algorithms),
            "leeway_seconds": self.config.leeway_seconds,
        }
        try:
            claims = json.loads(self._native.oidc_validate_id_token(json.dumps(request)))
        except Exception as error:
            if not refreshed and str(error).startswith("OIDC.KEY_NOT_FOUND"):
                return await self._validate_token(
                    token,
                    expected_audience=expected_audience,
                    expected_nonce=expected_nonce,
                    access_token=access_token,
                    refreshed=True,
                )
            raise ValueError(f"OIDC token validation failed: {error}") from error
        if not isinstance(claims, dict) or not claims:
            raise ValueError("OIDC token validation returned invalid claims")
        return claims

    async def _provider_jwks(self, *, force_refresh: bool) -> dict[str, Any]:
        now = time.monotonic()
        if not force_refresh and self._jwks is not None and now < self._cache_expires_at:
            return self._jwks
        async with self._cache_lock:
            now = time.monotonic()
            if not force_refresh and self._jwks is not None and now < self._cache_expires_at:
                return self._jwks
            jwks = await self._fetch_provider_jwks()
            self._jwks = jwks
            self._cache_expires_at = now + self.config.jwks_cache_seconds
            return jwks

    async def _fetch_provider_jwks(self) -> dict[str, Any]:
        timeout = httpx.Timeout(10.0)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            discovery = await _fetch_json_object(
                client,
                self.config.discovery_endpoint,
                max_bytes=_DISCOVERY_MAX_BYTES,
                document_name="discovery document",
            )
            discovered_issuer = str(discovery.get("issuer") or "").rstrip("/")
            if discovered_issuer != self.config.external_issuer_url:
                raise ValueError("OIDC discovery issuer does not match configured issuer")
            jwks_uri = str(discovery.get("jwks_uri") or "")
            internal_jwks_uri = self._trusted_internal_jwks_uri(jwks_uri)
            jwks = await _fetch_json_object(
                client,
                internal_jwks_uri,
                max_bytes=_JWKS_MAX_BYTES,
                document_name="JWKS document",
            )
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise ValueError("OIDC JWKS response is malformed")
        return jwks

    def _trusted_internal_jwks_uri(self, jwks_uri: str) -> str:
        expected = urlparse(self.config.external_issuer_url)
        discovered = urlparse(jwks_uri)
        if discovered.scheme not in {"http", "https"} or not discovered.netloc:
            raise ValueError("OIDC jwks_uri must be an absolute HTTP(S) URL")
        if (discovered.scheme, discovered.netloc) != (expected.scheme, expected.netloc):
            raise ValueError("OIDC jwks_uri origin does not match configured issuer")
        issuer_path = expected.path.rstrip("/")
        if issuer_path and not discovered.path.startswith(f"{issuer_path}/"):
            raise ValueError("OIDC jwks_uri is outside the configured issuer path")
        internal = urlparse(self.config.issuer_url)
        return urlunparse(
            (
                internal.scheme,
                internal.netloc,
                discovered.path,
                discovered.params,
                discovered.query,
                "",
            )
        )


class KeycloakOIDCAdapter(OIDCProviderPort):
    """Keycloak authorization-code adapter backed by native token validation."""

    def __init__(
        self,
        config: OIDCConfig,
        native_backend: Any | None = None,
    ) -> None:
        self.config = config
        self.validator = OIDCNativeValidator(config, native_backend=native_backend)

    def get_authorization_url(
        self,
        state: str,
        code_challenge: str,
        nonce: str,
        redirect_uri: str | None = None,
    ) -> str:
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri or self.config.redirect_uri,
            "scope": " ".join(self.config.scopes or []),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "consent login",
        }
        return f"{self.config.authorization_endpoint}?{urlencode(params)}"

    def get_registration_url(
        self,
        state: str,
        code_challenge: str,
        nonce: str,
        redirect_uri: str | None = None,
    ) -> str:
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri or self.config.redirect_uri,
            "scope": " ".join(self.config.scopes or []),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{self.config.registration_endpoint}?{urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str | None = None,
    ) -> dict[str, Any]:
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri or self.config.redirect_uri,
            "client_id": self.config.client_id,
            "code_verifier": code_verifier,
        }
        if self.config.client_secret:
            token_data["client_secret"] = self.config.client_secret
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            response = await client.post(
                self.config.token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if response.status_code != 200:
            logger.error("Token exchange failed with status %s", response.status_code)
            raise ValueError(f"Token exchange failed: {response.status_code}")
        tokens = response.json()
        if not isinstance(tokens, dict):
            raise ValueError("Token exchange returned an invalid response")
        return tokens

    async def validate_tokens(
        self,
        id_token: str,
        access_token: str | None,
        expected_nonce: str,
    ) -> OIDCValidatedIdentity:
        return await self.validator.validate_identity(
            id_token,
            access_token,
            expected_nonce,
        )

    def get_logout_url(
        self,
        id_token: str | None = None,
        post_logout_redirect_uri: str | None = None,
    ) -> str:
        params = {"client_id": self.config.client_id}
        if id_token:
            params["id_token_hint"] = id_token
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        return f"{self.config.logout_endpoint}?{urlencode(params)}"
