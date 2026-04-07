"""
Common Data Transfer Objects

Standardized API response formats for all Marty services.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Generic, TypeVar
import uuid

from pydantic import BaseModel

T = TypeVar("T")


class DeleteResponse(BaseModel):
    """Standard response for DELETE operations."""
    success: bool = True


class CountResponse(BaseModel):
    """Standard response for count operations."""
    count: int


@dataclass
class ResponseMeta:
    """Metadata included in all API responses."""
    
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ApiResponse(Generic[T]):
    """Standard API response wrapper."""
    
    data: T
    meta: ResponseMeta = field(default_factory=ResponseMeta)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = self.data
        if hasattr(data, "to_dict"):
            data = data.to_dict()
        elif hasattr(data, "__dict__"):
            data = data.__dict__
        
        return {
            "data": data,
            "meta": self.meta.to_dict(),
        }
    
    @classmethod
    def success(cls, data: T, request_id: str | None = None) -> ApiResponse[T]:
        """Create a successful API response."""
        meta = ResponseMeta(request_id=request_id) if request_id else ResponseMeta()
        return cls(data=data, meta=meta)


@dataclass
class PaginationInfo:
    """Pagination metadata for list responses."""
    
    total: int
    limit: int
    offset: int
    
    @property
    def has_more(self) -> bool:
        """Check if there are more items after this page."""
        return self.offset + self.limit < self.total
    
    @property
    def page(self) -> int:
        """Current page number (1-indexed)."""
        if self.limit == 0:
            return 1
        return (self.offset // self.limit) + 1
    
    @property
    def total_pages(self) -> int:
        """Total number of pages."""
        if self.limit == 0:
            return 1
        return (self.total + self.limit - 1) // self.limit
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
            "has_more": self.has_more,
            "page": self.page,
            "total_pages": self.total_pages,
        }


@dataclass
class PaginatedResponse(Generic[T]):
    """Paginated API response for list endpoints."""
    
    data: list[T]
    pagination: PaginationInfo
    meta: ResponseMeta = field(default_factory=ResponseMeta)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        items = []
        for item in self.data:
            if hasattr(item, "to_dict"):
                items.append(item.to_dict())
            elif hasattr(item, "__dict__"):
                items.append(item.__dict__)
            else:
                items.append(item)
        
        return {
            "data": items,
            "pagination": self.pagination.to_dict(),
            "meta": self.meta.to_dict(),
        }
    
    @classmethod
    def create(
        cls,
        items: list[T],
        total: int,
        limit: int,
        offset: int,
        request_id: str | None = None,
    ) -> PaginatedResponse[T]:
        """Create a paginated response."""
        meta = ResponseMeta(request_id=request_id) if request_id else ResponseMeta()
        pagination = PaginationInfo(total=total, limit=limit, offset=offset)
        return cls(data=items, pagination=pagination, meta=meta)


@dataclass
class ErrorResponse:
    """Standard error response format."""
    
    error: dict[str, Any]
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "error": self.error,
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
        }
    
    @classmethod
    def from_exception(cls, error: Exception, request_id: str | None = None) -> ErrorResponse:
        """Create error response from an exception."""
        from .errors import MartyError
        
        if isinstance(error, MartyError):
            error_dict = error.to_dict()
        else:
            error_dict = {
                "code": "INTERNAL_ERROR",
                "message": str(error),
                "user_message": "An unexpected error occurred",
                "severity": "high",
                "recovery_action": "contact_support",
                "details": [],
            }
        
        return cls(
            error=error_dict,
            request_id=request_id or str(uuid.uuid4()),
        )
