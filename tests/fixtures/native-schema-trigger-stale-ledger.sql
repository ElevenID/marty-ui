-- Synthetic fixture only. The driver appends the real verifier and rollback.
BEGIN;
DELETE FROM issuance_service.rust_schema_migrations WHERE version='0011_passport_administrative_cancellation';
