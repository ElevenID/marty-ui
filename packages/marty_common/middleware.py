"""
Common Middleware

Shared middleware components for Marty microservices.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware that ensures every request has a unique request ID.
    
    The request ID is:
    - Extracted from X-Request-ID header if present
    - Generated if not present
    - Added to response headers
    - Available in request.state.request_id
    """
    
    HEADER_NAME = "X-Request-ID"
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get or generate request ID
        request_id = request.headers.get(self.HEADER_NAME)
        if not request_id:
            request_id = str(uuid.uuid4())
        
        # Store in request state for use in handlers
        request.state.request_id = request_id
        
        # Process request
        response = await call_next(request)
        
        # Add request ID to response headers
        response.headers[self.HEADER_NAME] = request_id
        
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging request/response information.
    
    Logs:
    - Request method, path, and timing
    - Response status code
    - Request ID for correlation
    """
    
    def __init__(self, app, service_name: str = "service"):
        super().__init__(app)
        self.service_name = service_name
        self.logger = logging.getLogger(f"{service_name}.requests")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        request_id = getattr(request.state, "request_id", "unknown")
        
        # Log request
        self.logger.info(
            "Request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "query": str(request.query_params),
                "client_ip": request.client.host if request.client else "unknown",
            }
        )
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        
        # Log response
        log_level = logging.INFO if response.status_code < 400 else logging.WARNING
        self.logger.log(
            log_level,
            "Request completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
            }
        )
        
        return response


class UserContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware that extracts user context from gateway-injected headers.
    
    Expects headers:
    - X-User-ID: User's unique identifier
    - X-Organization-ID: User's organization
    - X-User-Email: User's email
    - X-User-Roles: Comma-separated list of roles
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Extract user context from headers (injected by gateway)
        user_id = request.headers.get("X-User-ID")
        organization_id = request.headers.get("X-Organization-ID")
        user_email = request.headers.get("X-User-Email")
        user_roles_header = request.headers.get("X-User-Roles", "")
        user_roles = [r.strip() for r in user_roles_header.split(",") if r.strip()]
        
        # Store in request state
        request.state.user_id = user_id
        request.state.organization_id = organization_id
        request.state.user_email = user_email
        request.state.user_roles = user_roles
        
        # Create user context dict for convenience
        if user_id:
            request.state.user = {
                "user_id": user_id,
                "organization_id": organization_id,
                "email": user_email,
                "roles": user_roles,
            }
        else:
            request.state.user = None
        
        return await call_next(request)


def get_request_id(request: Request) -> str:
    """Get the request ID from request state."""
    return getattr(request.state, "request_id", str(uuid.uuid4()))


def get_current_user(request: Request) -> dict | None:
    """Get the current user from request state."""
    return getattr(request.state, "user", None)


def require_authenticated(request: Request) -> dict:
    """Require authenticated user, raise if not present."""
    from fastapi import HTTPException
    
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_organization(request: Request) -> str:
    """Require organization context, raise if not present."""
    from fastapi import HTTPException
    
    user = require_authenticated(request)
    org_id = user.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=403, detail="Organization context required")
    return org_id
