"""Local applicant ORM mapping used by auth during legacy retirement.

This maps the shared ``applicants`` table without importing retired monolith
modules. Auth only needs a narrow subset of columns for just-in-time user
provisioning.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Date, DateTime, JSON, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class ApplicantProvisioningBase(DeclarativeBase):
    """Declarative base for narrow applicant table mappings."""



def _generate_uuid() -> str:
    return str(uuid4())



def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ApplicantRecord(ApplicantProvisioningBase):
    """Minimal ORM mapping for the shared applicants table."""

    __tablename__ = "applicants"
    __table_args__ = {"extend_existing": True}

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    account_id: Mapped[str | None] = mapped_column(String(36), unique=True, nullable=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    phone: Mapped[str | None] = mapped_column(String(50), nullable=True)
    surname: Mapped[str] = mapped_column(String(255), nullable=False)
    given_names: Mapped[str] = mapped_column(String(255), nullable=False)
    date_of_birth: Mapped[date] = mapped_column(Date, nullable=False)
    nationality: Mapped[str] = mapped_column(String(3), nullable=False)
    identity_proofing_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    identity_proofing_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    extra_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
