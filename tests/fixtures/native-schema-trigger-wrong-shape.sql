-- Synthetic fixture only. The driver appends the real verifier and rollback.
BEGIN;
ALTER TABLE issuance_service.physical_document_jobs DISABLE TRIGGER trg_administratively_cancelled_passport_job;
