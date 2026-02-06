"""
Auth Service

Authentication and session management microservice.
Handles OIDC authentication, session management, and user context.

Ports:
- HTTP API on port 8001
- Internal session validation endpoint

Architecture:
- domain/: Session, AuthenticatedUser entities
- application/: AuthenticateUseCase, ValidateSessionUseCase
- infrastructure/: FastAPI, Redis, Keycloak adapters
"""
