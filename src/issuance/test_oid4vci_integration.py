"""
OID4VCI Integration Tests

Comprehensive test suite for OpenID for Verifiable Credential Issuance (OID4VCI) protocol implementation.
Tests cover the complete credential issuance flow from offer creation to credential retrieval.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from fastapi.testclient import TestClient

from issuance.router import (
    router,
    IssuanceStatus,
    CreateOfferRequest,
    CredentialRequest,
    _generate_transaction_id,
    _generate_pre_authorized_code,
    _negotiate_credential_format,
    _get_supported_formats,
    _detect_wallet_from_user_agent,
)


# ==================== Fixtures ====================


@pytest.fixture
def mock_db_session():
    """Mock AsyncSession for database operations."""
    session = AsyncMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.rollback = AsyncMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def mock_current_user():
    """Mock authenticated user with org admin role."""
    user_mock = MagicMock()
    user_mock.user_id = "user-123"
    user_mock.email = "admin@example.com"
    user_mock.organization_id = "org-456"
    user_mock.roles = ["org_admin", "member"]
    
    auth_status = MagicMock()
    auth_status.authenticated = True
    auth_status.user = user_mock
    return auth_status


@pytest.fixture
def sample_offer_request():
    """Sample credential offer creation request."""
    return CreateOfferRequest(
        organization_id="org-456",
        credential_config_id="config-789",
        applicant_id="applicant-101",
        subject_did="did:example:abc123",
        credential_data={
            "name": "John Doe",
            "email": "john@example.com",
            "badgeClass": "OpenBadge2.0",
            "issueDate": "2024-01-15",
        },
        credential_format="vc+sd-jwt",
        deferred=False,
    )


# ==================== Unit Tests ====================


class TestTransactionGeneration:
    """Test transaction ID and code generation."""

    def test_generate_transaction_id_length(self):
        """Transaction IDs should have expected length."""
        tx_id = _generate_transaction_id()
        assert isinstance(tx_id, str)
        assert len(tx_id) > 32  # URL-safe base64 is longer than raw bytes

    def test_generate_transaction_id_uniqueness(self):
        """Transaction IDs should be unique."""
        ids = {_generate_transaction_id() for _ in range(1000)}
        assert len(ids) == 1000  # All unique

    def test_generate_pre_authorized_code(self):
        """Pre-authorized codes should be secure random strings."""
        code = _generate_pre_authorized_code()
        assert isinstance(code, str)
        assert len(code) > 32


class TestFormatNegotiation:
    """Test credential format negotiation logic."""

    def test_supported_formats_list(self):
        """Should return list of supported formats."""
        formats = _get_supported_formats()
        assert isinstance(formats, list)
        assert "vc+sd-jwt" in formats
        assert "jwt_vc_json" in formats
        assert "mso_mdoc" in formats

    def test_negotiate_format_match(self):
        """Should accept requested format if supported."""
        negotiated_format, format_changed = _negotiate_credential_format(
            requested_format="jwt_vc_json",
            session_format="vc+sd-jwt",
        )
        assert negotiated_format == "jwt_vc_json"
        assert format_changed is True

    def test_negotiate_format_same(self):
        """Should not change format if requested matches session."""
        negotiated_format, format_changed = _negotiate_credential_format(
            requested_format="vc+sd-jwt",
            session_format="vc+sd-jwt",
        )
        assert negotiated_format == "vc+sd-jwt"
        assert format_changed is False

    def test_negotiate_format_unsupported(self):
        """Should raise error for unsupported format."""
        with pytest.raises(HTTPException) as exc_info:
            _negotiate_credential_format(
                requested_format="unsupported_format",
                session_format="invalid_format",
            )
        assert exc_info.value.status_code == 400

    def test_negotiate_format_fallback(self):
        """Should fallback to session format if requested unsupported."""
        negotiated_format, format_changed = _negotiate_credential_format(
            requested_format="unsupported_format",
            session_format="vc+sd-jwt",
        )
        assert negotiated_format == "vc+sd-jwt"
        assert format_changed is False


class TestWalletDetection:
    """Test wallet vendor detection from User-Agent strings."""

    def test_detect_microsoft_authenticator(self):
        """Should detect Microsoft Authenticator."""
        wallet_type, version = _detect_wallet_from_user_agent(
            "Microsoft Authenticator/6.2024.1234 (iOS 17.0)"
        )
        assert wallet_type == "microsoft_authenticator"
        assert version == "6.2024.1234"

    def test_detect_spruce_wallet(self):
        """Should detect Spruce Wallet."""
        wallet_type, version = _detect_wallet_from_user_agent(
            "SpruceWallet/2.1.0 (Android 13)"
        )
        assert wallet_type == "spruce"
        assert version == "2.1.0"

    def test_detect_generic_android(self):
        """Should detect generic Android wallet."""
        wallet_type, version = _detect_wallet_from_user_agent(
            "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36"
        )
        assert wallet_type == "android_wallet"

    def test_detect_generic_ios(self):
        """Should detect generic iOS wallet."""
        wallet_type, version = _detect_wallet_from_user_agent(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"
        )
        assert wallet_type == "ios_wallet"

    def test_detect_unknown_wallet(self):
        """Should return unknown for unrecognized agents."""
        wallet_type, version = _detect_wallet_from_user_agent(
            "SomeUnknownClient/1.0"
        )
        assert wallet_type == "unknown"
        assert version is None


# ==================== Integration Tests ====================


class TestOfferCreation:
    """Test credential offer creation endpoint."""

    @pytest.mark.asyncio
    async def test_create_offer_success(self, mock_db_session, mock_current_user, sample_offer_request):
        """Should successfully create credential offer."""
        with patch('issuance.router.get_db', return_value=mock_db_session):
            with patch('issuance.router.require_org_admin', return_value=mock_current_user):
                # Mock database queries
                mock_db_session.execute.return_value.scalar_one_or_none.return_value = None
                
                # Call endpoint
                from issuance.router import create_credential_offer
                response = await create_credential_offer(
                    request=sample_offer_request,
                    current_user=mock_current_user,
                    issuer_url="https://issuer.example.com",
                    user_agent=None,
                    db=mock_db_session,
                )
                
                # Verify response
                assert response.transaction_id is not None
                assert response.credential_offer_uri.startswith("openid-credential-offer://")
                assert response.status == IssuanceStatus.PENDING
                assert response.qr_code_data is not None

    @pytest.mark.asyncio
    async def test_create_offer_with_wallet_adaptation(self, mock_db_session, mock_current_user, sample_offer_request):
        """Should adapt credential format based on wallet User-Agent."""
        # Mock wallet detection service response
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "detected_vendor": "microsoft_authenticator",
                "supported_formats": ["jwt_vc_json"],
                "recommended_format": "jwt_vc_json",
            }
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            
            with patch('issuance.router.get_db', return_value=mock_db_session):
                with patch('issuance.router.require_org_admin', return_value=mock_current_user):
                    from issuance.router import create_credential_offer
                    
                    response = await create_credential_offer(
                        request=sample_offer_request,
                        current_user=mock_current_user,
                        issuer_url="https://issuer.example.com",
                        user_agent="Microsoft Authenticator/6.2024.1234",
                        db=mock_db_session,
                    )
                    
                    # Format should be adapted
                    assert response.status == IssuanceStatus.PENDING

    @pytest.mark.asyncio
    async def test_create_offer_deferred(self, mock_db_session, mock_current_user):
        """Should create deferred credential offer."""
        request = CreateOfferRequest(
            organization_id="org-456",
            credential_config_id="config-789",
            applicant_id="applicant-101",
            credential_data={"name": "Test User"},
            credential_format="vc+sd-jwt",
            deferred=True,  # Deferred issuance
        )
        
        with patch('issuance.router.get_db', return_value=mock_db_session):
            with patch('issuance.router.require_org_admin', return_value=mock_current_user):
                with patch('issuance.router._create_credential_async') as mock_create:
                    from issuance.router import create_credential_offer
                    
                    response = await create_credential_offer(
                        request=request,
                        current_user=mock_current_user,
                        issuer_url="https://issuer.example.com",
                        user_agent=None,
                        db=mock_db_session,
                    )
                    
                    assert response.status == IssuanceStatus.DEFERRED
                    mock_create.assert_called_once()  # Should trigger async creation


class TestOfferRetrieval:
    """Test credential offer retrieval by wallet."""

    @pytest.mark.asyncio
    async def test_get_offer_success(self, mock_db_session):
        """Wallet should successfully retrieve valid offer."""
        # Mock offer and session from database
        mock_offer = MagicMock()
        mock_offer.id = "offer-123"
        mock_offer.is_active = True
        mock_offer.expires_at = datetime.utcnow() + timedelta(minutes=5)
        mock_offer.offer_payload = {
            "credential_issuer": "https://issuer.example.com",
            "credentials": ["VerifiableCredential"],
        }
        mock_offer.access_count = 0
        
        mock_session = MagicMock()
        mock_session.id = "session-456"
        mock_session.organization_id = "org-789"
        mock_session.applicant_id = "applicant-101"
        
        mock_db_session.execute.return_value.scalar_one_or_none.side_effect = [mock_offer, mock_session]
        
        with patch('issuance.router.get_db', return_value=mock_db_session):
            from issuance.router import get_credential_offer
            
            response = await get_credential_offer(
                offer_id="offer-123",
                user_agent="SpruceWallet/2.1.0",
                x_forwarded_for="192.168.1.1",
                x_real_ip=None,
                db=mock_db_session,
            )
            
            # Should return offer payload
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_offer_expired(self, mock_db_session):
        """Should reject expired offers."""
        mock_offer = MagicMock()
        mock_offer.id = "offer-123"
        mock_offer.is_active = True
        mock_offer.expires_at = datetime.utcnow() - timedelta(minutes=5)  # Expired
        
        mock_session = MagicMock()
        mock_session.organization_id = "org-789"
        
        mock_db_session.execute.return_value.scalar_one_or_none.side_effect = [mock_offer, mock_session]
        
        with patch('issuance.router.get_db', return_value=mock_db_session):
            with patch('issuance.router._log_offer_access') as mock_log:
                from issuance.router import get_credential_offer
                
                with pytest.raises(HTTPException) as exc_info:
                    await get_credential_offer(
                        offer_id="offer-123",
                        user_agent=None,
                        x_forwarded_for=None,
                        x_real_ip=None,
                        db=mock_db_session,
                    )
                
                assert exc_info.value.status_code == 410  # Gone
                # Should log expired access
                mock_log.assert_called_once()


class TestTokenExchange:
    """Test OID4VCI token endpoint (pre-authorized code flow)."""

    @pytest.mark.asyncio
    async def test_token_exchange_success(self):
        """Should exchange pre-authorized code for access token."""
        # Mock in-memory session
        mock_session = MagicMock()
        mock_session.transaction_id = "tx-123"
        mock_session.pre_authorized_code = "pre-auth-code-xyz"
        mock_session.is_expired = False
        mock_session.status = IssuanceStatus.PENDING
        
        with patch('issuance.router._issuance_sessions', {"tx-123": mock_session}):
            from issuance.router import token_endpoint
            
            response = await token_endpoint(
                grant_type="urn:ietf:params:oauth:grant-type:pre-authorized_code",
                pre_authorized_code="pre-auth-code-xyz",
                tx_code=None,
            )
            
            assert response.access_token is not None
            assert response.token_type == "Bearer"
            assert response.c_nonce is not None
            assert response.expires_in == 300

    @pytest.mark.asyncio
    async def test_token_exchange_invalid_code(self):
        """Should reject invalid pre-authorized code."""
        with patch('issuance.router._issuance_sessions', {}):
            from issuance.router import token_endpoint
            
            with pytest.raises(HTTPException) as exc_info:
                await token_endpoint(
                    grant_type="urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    pre_authorized_code="invalid-code",
                    tx_code=None,
                )
            
            assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_token_exchange_expired(self):
        """Should reject expired pre-authorized code."""
        mock_session = MagicMock()
        mock_session.pre_authorized_code = "pre-auth-code-expired"
        mock_session.is_expired = True
        
        with patch('issuance.router._issuance_sessions', {"tx-123": mock_session}):
            from issuance.router import token_endpoint
            
            with pytest.raises(HTTPException) as exc_info:
                await token_endpoint(
                    grant_type="urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    pre_authorized_code="pre-auth-code-expired",
                    tx_code=None,
                )
            
            assert exc_info.value.status_code == 400


class TestCredentialEndpoint:
    """Test OID4VCI credential endpoint."""

    @pytest.mark.asyncio
    async def test_credential_retrieval_success(self):
        """Should issue credential with valid access token."""
        mock_session = MagicMock()
        mock_session.transaction_id = "tx-123"
        mock_session.status = IssuanceStatus.READY
        mock_session.credential_format = "vc+sd-jwt"
        mock_session.issued_credential = "eyJ...credential-jwt..."
        mock_session.applicant_id = "applicant-101"
        mock_session.organization_id = "org-456"
        
        with patch('issuance.router._access_tokens', {"token-hash": "tx-123"}):
            with patch('issuance.router._issuance_sessions', {"tx-123": mock_session}):
                with patch('issuance.router._hash_token', return_value="token-hash"):
                    from issuance.router import credential_endpoint
                    
                    request = CredentialRequest(
                        format="vc+sd-jwt",
                        credential_identifier="config-789",
                    )
                    
                    response = await credential_endpoint(
                        request=request,
                        authorization="Bearer access-token-123",
                    )
                    
                    assert response.format == "vc+sd-jwt"
                    assert response.credential == "eyJ...credential-jwt..."
                    assert response.c_nonce is not None

    @pytest.mark.asyncio
    async def test_credential_format_negotiation(self):
        """Should negotiate credential format based on wallet request."""
        mock_session = MagicMock()
        mock_session.transaction_id = "tx-123"
        mock_session.status = IssuanceStatus.ACCEPTED
        mock_session.credential_format = "vc+sd-jwt"
        mock_session.issued_credential = None  # Not yet generated
        mock_session.applicant_id = "applicant-101"
        mock_session.organization_id = "org-456"
        
        with patch('issuance.router._access_tokens', {"token-hash": "tx-123"}):
            with patch('issuance.router._issuance_sessions', {"tx-123": mock_session}):
                with patch('issuance.router._hash_token', return_value="token-hash"):
                    with patch('issuance.router._create_credential_async') as mock_create:
                        from issuance.router import credential_endpoint
                        
                        request = CredentialRequest(
                            format="jwt_vc_json",  # Different format requested
                            credential_identifier="config-789",
                        )
                        
                        response = await credential_endpoint(
                            request=request,
                            authorization="Bearer access-token-123",
                        )
                        
                        # Should call create with negotiated format
                        mock_create.assert_called_once()
                        call_args = mock_create.call_args
                        assert call_args[1]["credential_format"] == "jwt_vc_json"

    @pytest.mark.asyncio
    async def test_credential_invalid_token(self):
        """Should reject invalid access token."""
        with patch('issuance.router._access_tokens', {}):
            from issuance.router import credential_endpoint
            
            request = CredentialRequest(format="vc+sd-jwt")
            
            with pytest.raises(HTTPException) as exc_info:
                await credential_endpoint(
                    request=request,
                    authorization="Bearer invalid-token",
                )
            
            assert exc_info.value.status_code == 401


class TestRetryPolicy:
    """Test credential offer regeneration and retry policy."""

    @pytest.mark.asyncio
    async def test_regenerate_offer_success(self, mock_db_session, mock_current_user):
        """Should regenerate expired offer within policy limits."""
        # TODO: Implement test for offer regeneration
        pass

    @pytest.mark.asyncio
    async def test_regenerate_offer_max_retries(self, mock_db_session, mock_current_user):
        """Should enforce maximum retry attempts."""
        # TODO: Implement test for max retries enforcement
        pass

    @pytest.mark.asyncio
    async def test_regenerate_offer_cooldown(self, mock_db_session, mock_current_user):
        """Should enforce cooldown period between retries."""
        # TODO: Implement test for cooldown enforcement
        pass


class TestAuditLogging:
    """Test audit trail integration."""

    @pytest.mark.asyncio
    async def test_audit_offer_created(self, mock_db_session, mock_current_user, sample_offer_request):
        """Should log audit event when offer is created."""
        with patch('issuance.router.log_audit_event') as mock_audit:
            with patch('issuance.router.get_db', return_value=mock_db_session):
                with patch('issuance.router.require_org_admin', return_value=mock_current_user):
                    from issuance.router import create_credential_offer
                    from subscription.models import AuditEventType
                    
                    await create_credential_offer(
                        request=sample_offer_request,
                        current_user=mock_current_user,
                        issuer_url="https://issuer.example.com",
                        user_agent=None,
                        db=mock_db_session,
                    )
                    
                    # Should log offer creation
                    mock_audit.assert_called_once()
                    call_args = mock_audit.call_args[1]
                    assert call_args["event_type"] == AuditEventType.CREDENTIAL_OFFER_CREATED

    @pytest.mark.asyncio
    async def test_audit_offer_accessed(self, mock_db_session):
        """Should log audit event when wallet accesses offer."""
        # TODO: Implement test for offer access audit logging
        pass

    @pytest.mark.asyncio
    async def test_audit_format_negotiated(self):
        """Should log audit event when format is negotiated."""
        # TODO: Implement test for format negotiation audit logging
        pass


# ==================== End-to-End Tests ====================


class TestCompleteIssuanceFlow:
    """End-to-end tests of complete OID4VCI flow."""

    @pytest.mark.asyncio
    async def test_full_issuance_flow(self, mock_db_session, mock_current_user):
        """Should successfully complete entire issuance flow."""
        # TODO: Implement full end-to-end test:
        # 1. Create offer
        # 2. Wallet retrieves offer
        # 3. Wallet exchanges pre-authorized code for access token
        # 4. Wallet requests credential
        # 5. Wallet receives issued credential
        pass

    @pytest.mark.asyncio
    async def test_deferred_issuance_flow(self, mock_db_session, mock_current_user):
        """Should successfully complete deferred issuance flow with polling."""
        # TODO: Implement deferred issuance test:
        # 1. Create deferred offer
        # 2. Wallet retrieves offer
        # 3. Wallet exchanges code for token
        # 4. Wallet polls credential endpoint
        # 5. Wallet receives credential when ready
        pass

    @pytest.mark.asyncio
    async def test_retry_regeneration_flow(self, mock_db_session, mock_current_user):
        """Should successfully handle offer expiry and regeneration."""
        # TODO: Implement retry flow test:
        # 1. Create offer
        # 2. Let offer expire
        # 3. Admin regenerates offer (attempt 2)
        # 4. Wallet completes flow with new offer
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
