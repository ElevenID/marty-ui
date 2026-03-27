"""
Auth Service Use Cases

Application layer use cases that orchestrate domain logic
and coordinate with infrastructure through ports.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass

from ..domain.entities import AuthenticatedUser, PKCEState, Session
from ..domain.events import (
    SessionCreatedEvent,
    SessionRevokedEvent,
    UserAuthenticatedEvent,
    UserLoggedOutEvent,
)
from .ports import (
    EventPublisherPort,
    HandleCallbackCommand,
    HandleCallbackResult,
    InitiateLoginCommand,
    InitiateLoginResult,
    LogoutCommand,
    LogoutResult,
    OIDCProviderPort,
    PKCEStateRepositoryPort,
    SessionRepositoryPort,
    UserProvisioningPort,
    ValidateSessionQuery,
)

logger = logging.getLogger(__name__)


def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code verifier and challenge."""
    # Generate code verifier (43-128 chars)
    code_verifier = secrets.token_urlsafe(64)
    
    # Generate code challenge (S256)
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    
    return code_verifier, code_challenge


@dataclass
class AuthenticateUseCase:
    """
    Use case for user authentication via OIDC.
    
    Handles the complete OIDC authorization code flow with PKCE:
    1. Initiate login - generate PKCE and redirect to provider
    2. Handle callback - exchange code, provision user, create session
    """
    
    session_repository: SessionRepositoryPort
    pkce_repository: PKCEStateRepositoryPort
    oidc_provider: OIDCProviderPort
    user_provisioning: UserProvisioningPort
    event_publisher: EventPublisherPort
    audit_repository: "PostgresAuditRepository | None" = None  # Optional audit logging
    session_ttl_seconds: int = 86400  # 24 hours
    post_logout_redirect_uri: str = "http://localhost:3000/"
    
    async def initiate_login(self, command: InitiateLoginCommand) -> InitiateLoginResult:
        """
        Initiate OIDC login flow.
        
        Generates PKCE pair, stores state, and returns authorization URL.
        """
        # Generate PKCE pair
        code_verifier, code_challenge = generate_pkce_pair()
        
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Store PKCE state
        pkce_state = PKCEState(
            state=state,
            code_verifier=code_verifier,
            redirect_uri=command.redirect_uri or "/",
        )
        await self.pkce_repository.save(pkce_state)
        
        # Build authorization URL (always use configured OIDC callback, not user's final redirect)
        auth_url = self.oidc_provider.get_authorization_url(
            state=state,
            code_challenge=code_challenge,
            redirect_uri=None,  # Use the configured OIDC callback URL
        )
        
        logger.info(f"Initiated OIDC login flow with state: {state[:20]}...")
        
        return InitiateLoginResult(
            authorization_url=auth_url,
            state=state,
        )
    
    async def initiate_registration(self, command: InitiateLoginCommand) -> InitiateLoginResult:
        """
        Initiate OIDC registration flow.
        
        Similar to login but redirects to registration page.
        """
        # Generate PKCE pair
        code_verifier, code_challenge = generate_pkce_pair()
        
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Store PKCE state
        pkce_state = PKCEState(
            state=state,
            code_verifier=code_verifier,
            redirect_uri=command.redirect_uri or "/",
        )
        await self.pkce_repository.save(pkce_state)
        
        # Build registration URL (always use configured OIDC callback, not user's final redirect)
        reg_url = self.oidc_provider.get_registration_url(
            state=state,
            code_challenge=code_challenge,
            redirect_uri=None,  # Use the configured OIDC callback URL
        )
        
        logger.info(f"Initiated OIDC registration flow with state: {state[:20]}...")
        
        return InitiateLoginResult(
            authorization_url=reg_url,
            state=state,
        )
    
    async def handle_callback(self, command: HandleCallbackCommand) -> HandleCallbackResult:
        """
        Handle OIDC callback after successful authentication.
        
        1. Validate and consume PKCE state
        2. Exchange authorization code for tokens
        3. Get user info from provider
        4. Provision user (JIT)
        5. Create session
        6. Publish events
        """
        # Consume PKCE state (single-use)
        pkce_state = await self.pkce_repository.get_and_delete(command.state)
        if not pkce_state:
            raise ValueError("Invalid or expired state")
        
        if not pkce_state.is_valid:
            raise ValueError("PKCE state has expired")
        
        # Exchange code for tokens
        tokens = await self.oidc_provider.exchange_code(
            code=command.code,
            code_verifier=pkce_state.code_verifier,
        )
        
        access_token = tokens["access_token"]
        id_token = tokens.get("id_token")
        refresh_token = tokens.get("refresh_token")
        
        if not id_token:
            raise ValueError("No ID token in response")
        
        # Parse user claims from ID token (already validated via PKCE)
        oidc_user = self.oidc_provider.parse_id_token(id_token)
        
        # JIT provision user
        user = await self.user_provisioning.provision_user(oidc_user)
        
        # Create session
        session = Session.create(
            user=user,
            ttl_seconds=self.session_ttl_seconds,
            ip_address=command.ip_address,
            user_agent=command.user_agent,
            id_token=id_token,
            refresh_token=refresh_token,
        )
        
        await self.session_repository.save(session)
        
        # Publish events
        await self.event_publisher.publish(
            UserAuthenticatedEvent(
                user_id=user.user_id,
                email=user.email,
                organization_id=user.organization_id,
                ip_address=command.ip_address,
            )
        )
        
        await self.event_publisher.publish(
            SessionCreatedEvent(
                session_id=session.session_id,
                user_id=user.user_id,
                expires_at=session.expires_at,
            )
        )
        
        # Log to audit repository if available
        if self.audit_repository:
            try:
                await self.audit_repository.log_authentication(
                    user_id=user.user_id,
                    email=user.email,
                    organization_id=user.organization_id,
                    session_id=session.session_id,
                    authentication_method="oidc",
                    success=True,
                    ip_address=command.ip_address,
                    user_agent=command.user_agent,
                )
                await self.audit_repository.log_session_created(session)
                await self.audit_repository.record_session_history(session)
            except Exception as e:
                logger.warning(f"Failed to log audit event: {e}")
        
        logger.info(
            f"User {user.email} authenticated successfully, "
            f"session {session.session_id[:8]}... created"
        )
        
        return HandleCallbackResult(
            session=session,
            redirect_uri=pkce_state.redirect_uri,
        )
    
    async def logout(self, command: LogoutCommand) -> LogoutResult:
        """
        Logout user and revoke session.
        
        Returns SSO logout URL if available for full logout.
        """
        # Get session
        session = await self.session_repository.get(command.session_id)
        if not session:
            return LogoutResult(success=True)
        
        # Revoke and delete session
        session.revoke()
        await self.session_repository.delete(command.session_id)
        
        # Get SSO logout URL with redirect back to home
        sso_logout_url = self.oidc_provider.get_logout_url(
            session.id_token,
            post_logout_redirect_uri=self.post_logout_redirect_uri
        )
        
        # Publish events
        await self.event_publisher.publish(
            UserLoggedOutEvent(
                user_id=session.user.user_id,
                session_id=session.session_id,
                logout_type="user_initiated",
            )
        )
        
        await self.event_publisher.publish(
            SessionRevokedEvent(
                session_id=session.session_id,
                user_id=session.user.user_id,
                revoked_by=session.user.user_id,
                reason="User initiated logout",
            )
        )
        
        # Log to audit repository if available
        if self.audit_repository:
            try:
                await self.audit_repository.log_logout(
                    user_id=session.user.user_id,
                    session_id=session.session_id,
                    organization_id=session.user.organization_id,
                    logout_type="user_initiated",
                )
                await self.audit_repository.log_session_revoked(
                    user_id=session.user.user_id,
                    session_id=session.session_id,
                    organization_id=session.user.organization_id,
                    revoked_by=session.user.user_id,
                    reason="User initiated logout",
                )
                await self.audit_repository.update_session_history_on_revocation(
                    session_id=session.session_id,
                    reason="User initiated logout",
                )
            except Exception as e:
                logger.warning(f"Failed to log audit event: {e}")
        
        logger.info(
            f"User {session.user.email} logged out, "
            f"session {session.session_id[:8]}... revoked"
        )
        
        return LogoutResult(
            success=True,
            sso_logout_url=sso_logout_url,
        )


@dataclass
class SessionUseCase:
    """
    Use case for session management.
    
    Handles session validation, user retrieval, and refresh.
    """
    
    session_repository: SessionRepositoryPort
    
    async def validate_session(self, query: ValidateSessionQuery) -> Session | None:
        """
        Validate a session and return it if valid.
        
        Updates last activity timestamp on successful validation.
        """
        session = await self.session_repository.get(query.session_id)
        
        if not session:
            return None
        
        if not session.is_valid:
            # Clean up expired session
            await self.session_repository.delete(query.session_id)
            return None
        
        # Update last activity
        session.touch()
        await self.session_repository.save(session)
        
        return session
    
    async def get_user(self, session_id: str) -> AuthenticatedUser | None:
        """Get authenticated user from session."""
        session = await self.validate_session(ValidateSessionQuery(session_id=session_id))
        if session:
            return session.user
        return None
    
    async def refresh_session(self, session_id: str) -> Session | None:
        """Refresh session expiry."""
        session = await self.session_repository.get(session_id)
        
        if not session or not session.is_valid:
            return None
        
        # Touch to update last activity
        session.touch()
        await self.session_repository.save(session)
        
        return session
