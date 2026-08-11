from datetime import datetime, timedelta, timezone

import pytest

from services.auth.application.ports import HandleCallbackCommand, InitiateLoginCommand
from services.auth.application.use_cases import AuthenticateUseCase
from services.auth.domain.entities import (
    AuthenticatedUser,
    OIDCUserInfo,
    OIDCValidatedIdentity,
    PKCEState,
)


class MemoryPkceRepository:
    def __init__(self) -> None:
        self.state: PKCEState | None = None

    async def save(self, state: PKCEState) -> None:
        self.state = state

    async def get_and_delete(self, state: str) -> PKCEState | None:
        if self.state is None or self.state.state != state:
            return None
        result = self.state
        self.state = None
        return result


class MemorySessionRepository:
    def __init__(self) -> None:
        self.saved = None

    async def save(self, session) -> None:
        self.saved = session


class FakeOidcProvider:
    def __init__(self) -> None:
        self.authorization_nonce: str | None = None
        self.validated_nonce: str | None = None

    def get_authorization_url(self, state, code_challenge, nonce, redirect_uri=None):
        self.authorization_nonce = nonce
        return f"https://login.example/auth?state={state}&nonce={nonce}"

    def get_registration_url(self, state, code_challenge, nonce, redirect_uri=None):
        return f"https://login.example/register?state={state}&nonce={nonce}"

    async def exchange_code(self, code, code_verifier, redirect_uri=None):
        return {
            "id_token": "verified-id-token",
            "access_token": "verified-access-token",
            "refresh_token": "refresh-token",
        }

    async def validate_tokens(self, id_token, access_token, expected_nonce):
        self.validated_nonce = expected_nonce
        claims = {
            "sub": "user-1",
            "email": "alice@example.com",
            "IMPERSONATOR_ID": "admin-1",
        }
        return OIDCValidatedIdentity(
            user_info=OIDCUserInfo.from_claims(claims),
            id_token_claims=claims,
            access_token_claims={"sub": "user-1"},
        )

    def get_logout_url(self, id_token=None, post_logout_redirect_uri=None):
        return "https://login.example/logout"


class FakeUserProvisioner:
    async def provision_user(self, oidc_user: OIDCUserInfo) -> AuthenticatedUser:
        return AuthenticatedUser(user_id=oidc_user.sub, email=oidc_user.email)


class FakeEventPublisher:
    async def publish(self, _event) -> None:
        return None


def _use_case():
    pkce = MemoryPkceRepository()
    sessions = MemorySessionRepository()
    provider = FakeOidcProvider()
    use_case = AuthenticateUseCase(
        session_repository=sessions,
        pkce_repository=pkce,
        oidc_provider=provider,
        user_provisioning=FakeUserProvisioner(),
        event_publisher=FakeEventPublisher(),
    )
    return use_case, pkce, sessions, provider


@pytest.mark.asyncio
async def test_login_request_persists_and_sends_oidc_nonce():
    use_case, pkce, _sessions, provider = _use_case()

    await use_case.initiate_login(InitiateLoginCommand())

    assert pkce.state is not None
    assert pkce.state.nonce
    assert provider.authorization_nonce == pkce.state.nonce


@pytest.mark.asyncio
async def test_callback_persists_only_native_validated_claims():
    use_case, pkce, sessions, provider = _use_case()
    pkce.state = PKCEState(
        state="state-1",
        code_verifier="verifier",
        redirect_uri="/console",
        nonce="nonce-1",
    )

    result = await use_case.handle_callback(
        HandleCallbackCommand(code="code-1", state="state-1")
    )

    assert provider.validated_nonce == "nonce-1"
    assert result.session is sessions.saved
    assert result.session.oidc_claims == {
        "sub": "user-1",
        "email": "alice@example.com",
        "IMPERSONATOR_ID": "admin-1",
    }
    restored = type(result.session).from_dict(result.session.to_dict())
    assert restored.oidc_claims == result.session.oidc_claims


@pytest.mark.asyncio
async def test_callback_rejects_pre_cutover_state_without_nonce():
    use_case, pkce, _sessions, provider = _use_case()
    pkce.state = PKCEState(
        state="state-1",
        code_verifier="verifier",
        redirect_uri="/console",
        nonce=None,
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    with pytest.raises(ValueError, match="nonce is missing"):
        await use_case.handle_callback(
            HandleCallbackCommand(code="code-1", state="state-1")
        )

    assert provider.validated_nonce is None
